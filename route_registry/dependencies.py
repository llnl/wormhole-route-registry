import logging
import requests

from requests.exceptions import HTTPError, InvalidJSONError
from functools import wraps

from fastapi import FastAPI, Request, HTTPException, Header, APIRouter, status
from fastapi.responses import RedirectResponse
from attrs import define, field
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.errors import InvalidClaimError, MissingClaimError, ExpiredTokenError
from authlib.integrations.starlette_client import StarletteOAuth2App, OAuth
from starlette.middleware.sessions import SessionMiddleware
from urllib.parse import unquote

from typing import Annotated

from .celery import TaskProxy
from .models import JWTConfig, VerificationStatus, User, Route, AdminRole, AdminToken
from .store.repository import NotFound
from .service.uow import BaseUOW
from .services import (
    validate_admin_token,
    get_admin_token,
)
from .utils import get_local_username

logger = logging.getLogger(__name__)


@define
class AdminTokenAuthenticator:
    """Performs Admin Token Authentication."""

    UOW: BaseUOW

    def __hash__(self):
        return hash(self.__class__.__name__)

    async def __call__(self, x_token: Annotated[str, Header()]) -> AdminToken:
        """Performs admin token authentication."""
        with self.UOW() as uow:
            try:
                if not validate_admin_token(uow, x_token):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Invalid Token",
                    )
            except ValueError:
                # TODO add logging to stdout that token is in an invalid format
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid Token",
                )
            return get_admin_token(uow, x_token)


@define
class JWTAuthenticator:
    config: dict
    UOW: BaseUOW
    jwt_config: JWTConfig
    task_proxy: TaskProxy
    leeway: int = field()
    lifespan: int = field()
    claims_registry: jwt.JWTClaimsRegistry = field()

    @leeway.default
    def _leeway(self):
        return self.config.get("leeway", 43_200)

    @lifespan.default
    def _lifespan(self):
        return self.config.get("lifespan", self.jwt_config.lifespan)

    @claims_registry.default
    def _claims_registry(self):
        return jwt.JWTClaimsRegistry(
            sub={"essential": True},
            leeway=self.leeway,
        )

    def __hash__(self):
        return hash(self.__class__.__name__)

    async def __call__(self, x_jwt: Annotated[str, Header()]) -> Route:
        """Performs jwt rotation via existing jwt."""

        try:
            token = jwt.decode(x_jwt, KeySet.import_key_set(self.jwt_config.jwks.keys))
            self.claims_registry.validate(token.claims)
        except (InvalidClaimError, MissingClaimError, ExpiredTokenError) as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e),
            )

        with self.UOW() as uow:
            route = uow.route_repo.get(token.claims["sub"])
            if not route:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

            if route.verification_status is not VerificationStatus.VERIFIED:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Cannot rotate jwt for unverified route",
                )

        return route


def extract_uid(jwks: dict, bearer_jwt: str) -> str:
    claims_registry = jwt.JWTClaimsRegistry(
        sub={"essential": True},
        leeway=1,
    )
    token = jwt.decode(bearer_jwt, KeySet.import_key_set(jwks))
    claims_registry.validate(token.claims)
    return token.claims["sub"]


@define
class TokenServiceAuthenticator:
    config: dict
    UOW: BaseUOW
    url: str = field()
    api_version: str = field()
    api_url: str = field()

    @url.default
    def _url(self):
        return self.config["host"]

    @api_version.default
    def _api_version(self):
        return self.config.get("api_version", "latest")

    @api_url.default
    def _api_url(self):
        return f"{self.url}/api/{self.api_version}"

    def __hash__(self):
        return hash(self.__class__.__name__)

    async def __call__(self, x_token: Annotated[str, Header()]) -> User:
        """Performs token authentication against Token Service."""

        # TODO: cache
        resp = requests.get(f"{self.url}/.well-known/jwks.json")
        jwks = resp.json()

        headers = {"X-Token": x_token}

        resp = requests.get(f"{self.api_url}/token/jwt", headers=headers)

        if resp.status_code == 401:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
            )

        try:
            resp.raise_for_status()
            uid = extract_uid(jwks, resp.json()["jwt"])
        except (
            HTTPError,
            InvalidJSONError,
            KeyError,
            InvalidClaimError,
            MissingClaimError,
        ):
            # TODO: log specific error here
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed validating token",
            )

        try:
            with self.UOW() as uow:
                return uow.entity_repo.get_user(uid)
        except NotFound:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)


@define
class AuthenticatorFactoryException(Exception):
    """AuthenticatorFactory base exception."""

    msg: str


@define
class AuthenticatorNotFound(AuthenticatorFactoryException):
    """Authenticator not found exception."""

    pass


@define
class BaseUserAuthDependency:
    UOW: BaseUOW
    config: dict

    def __call__(self, request: Request) -> User:
        raise NotImplementedError()

    def setup(self, app: FastAPI) -> None:
        """Apply additional setup required for the authenticator to work.

        This hook allows for configuring middleware, routing or exception handlers
        that cannot otherwise be performed on initializing the class.
        """
        pass


@define
class AuthenticatorFactory:
    """Factory for creating Authenticators."""

    authenticators: dict = field()

    @authenticators.default
    def _authenticators(self):
        return {
            "base_auth": BaseUserAuthDependency,
            "authlib_oidc": AuthLibOIDCAuthenticator,
            "local_dev": LocalDevAuthenticator,
        }

    def make_authenticator(self, uow, config):
        """Initialize authenticator by name."""
        authenticator = config["auth_name"]
        return self.authenticators[authenticator](UOW=uow, config=config[authenticator])


@define
class AuthLibOIDCAuthenticator(BaseUserAuthDependency):
    UOW: BaseUOW
    config: dict
    oauth_client: StarletteOAuth2App = field()
    url: str = field()
    redirect_uri: str = field()

    def __hash__(self):
        return hash(self.__class__.__name__)

    @oauth_client.default
    def _oauth_client(self):
        oauth = OAuth()
        oauth.register(
            name=self.config["strategy_name"],
            client_id=self.config["client_id"],
            client_secret=self.config["client_secret"],
            server_metadata_url=self.config["discovery_url"],
            client_kwargs=self.config.get(
                "client_kwargs",
                {"scope": "openid email profile"},
            ),
        )
        return oauth.create_client(self.config["strategy_name"])

    @url.default
    def _url(self):
        return self.config["url"]

    @redirect_uri.default
    def _redirect_uri(self):
        return f"{self.url}{self.config['redirect_uri']}"

    async def __call__(self, request: Request) -> User:
        session_user = request.session.get("user")
        x_target = request.headers.get("X-Target", "")
        next_url = ""
        if x_target:
            next_url = x_target
        else:
            path = request.scope["route"].path
            next_url = f"{self.url}{path}"

        if not session_user:
            raise HTTPException(
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                headers={"Location": f"{self.url}/auth/login?next={next_url}"},
            )
        try:
            with self.UOW() as uow:
                return uow.entity_repo.get_user(session_user["sub"])
        except NotFound:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    def make_router(self) -> APIRouter:
        router = APIRouter(
            prefix="/auth",
            tags=["auth"],
        )

        @router.get("/login")
        async def login(request: Request):
            next_url = request.query_params.get("next", "/")
            # Store "next" in the session so it's available after the callback
            request.session["next"] = unquote(next_url)
            return await self.oauth_client.authorize_redirect(
                request, self.redirect_uri
            )

        @router.get("/callback", status_code=status.HTTP_200_OK)
        async def auth_callback(request: Request):
            token = await self.oauth_client.authorize_access_token(request)
            user_info = token["userinfo"]
            request.session["user"] = dict(user_info)
            next_url = request.session.pop("next", "/")
            return RedirectResponse(url=next_url)

        return router

    def setup(self, app: FastAPI) -> None:
        # only OIDC needs session-based state
        session_config = self.config.get("session_config", {})
        if session_config:
            app.add_middleware(SessionMiddleware, **session_config)

        auth_router = self.make_router()
        if auth_router:
            app.include_router(auth_router)


@define
class LocalDevAuthenticator(BaseUserAuthDependency):
    """Authenticates every request as the local machine user.

    FOR LOCAL DEVELOPMENT ONLY. This performs no authentication whatsoever --
    it presents no credential requirement and hands back a user record. It
    exists because the shipped default (``base_auth``) cannot authenticate at
    all, which leaves every user-auth endpoint unreachable on a dev box.

    The user must already exist; seed it with::

        wormhole_route_registry seed-dev-user
    """

    UOW: BaseUOW
    config: dict
    uid: str = field()

    def __hash__(self):
        return hash(self.__class__.__name__)

    @uid.default
    def _uid(self):
        return self.config.get("uid") or get_local_username()

    async def __call__(self, request: Request = None) -> User:
        """Return the configured local user, ignoring all request state.

        ``request`` is accepted only to match the calling convention of the
        other user authenticators (notably ``TokenOrFallbackAuthenticator``,
        which passes one through). FastAPI injects ``Request`` itself, so no
        header, cookie or query parameter is ever required of the caller.
        """

        with self.UOW() as uow:
            try:
                return uow.entity_repo.get_user(self.uid)
            except NotFound:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=(
                        f"Local dev user {self.uid!r} is not seeded. "
                        f"Run: wormhole_route_registry seed-dev-user"
                    ),
                )

    def setup(self, app: FastAPI) -> None:
        logger.warning(
            f"AUTH IS DISABLED: every request authenticates as {self.uid!r} via "
            "LocalDevAuthenticator. Never enable auth_name='local_dev' "
            "outside local development."
        )


@define
class TokenOrFallbackAuthenticator:
    token_auth: TokenServiceAuthenticator
    fallback_auth: BaseUserAuthDependency

    def __hash__(self):
        return hash(self.__class__.__name__)

    async def __call__(self, request: Request) -> User:
        x_token = request.headers.get("X-Token", "")

        if x_token:
            return await self.token_auth(x_token)

        return await self.fallback_auth(request)

    def setup(self, app: FastAPI):
        self.fallback_auth.setup(app)


def require_admin(user_auth: BaseUserAuthDependency) -> User:
    @wraps(user_auth)
    async def wrapper(*args, **kwargs) -> User:
        user = await user_auth(*args, **kwargs)
        if not user.is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
        return user

    return wrapper


def require_admin_identity_role(admin_token_auth: AdminTokenAuthenticator):
    @wraps(admin_token_auth)
    async def wrapper(*args, **kwargs):
        admin_token = await admin_token_auth(*args, **kwargs)
        if admin_token.role not in (AdminRole.IDENTITY, AdminRole.ANY):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return wrapper


def require_admin_observer_role(admin_token_auth: AdminTokenAuthenticator):
    @wraps(admin_token_auth)
    async def wrapper(*args, **kwargs):
        admin_token = await admin_token_auth(*args, **kwargs)
        if admin_token.role not in (AdminRole.OBSERVER, AdminRole.ANY):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return wrapper


def require_admin_domain_role(admin_token_auth: AdminTokenAuthenticator):
    @wraps(admin_token_auth)
    async def wrapper(*args, **kwargs):
        admin_token = await admin_token_auth(*args, **kwargs)
        if admin_token.role not in (AdminRole.DOMAIN, AdminRole.ANY):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return wrapper
