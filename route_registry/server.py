import json
import uvicorn
from attrs import define, field
from fastapi_offline import FastAPIOffline
from fastapi import APIRouter
from fastapi.openapi.utils import get_openapi

from . import __version__
from .celery import TaskProxy
from .dependencies import (
    AdminTokenAuthenticator,
    JWTAuthenticator,
    TokenServiceAuthenticator,
    AuthenticatorFactory,
    TokenOrFallbackAuthenticator,
)
from .internal.route import make_router as make_admin_route_router
from .internal.domain import make_router as make_admin_domain_router
from .internal.user import make_router as make_admin_user_router
from .internal.group import make_router as make_admin_group_router
from .models import JWTConfig
from .internal.token import make_router as make_admin_token_router
from .routers.jwt import make_router as make_jwt_router
from .routers.community import make_router as make_community_router
from .routers.route import make_router as make_route_router
from .routers.well_known import make_router as make_well_known_router
from .service.uow import BaseUOW


@define
class Endpoint:
    current_version: str
    router: APIRouter
    public: bool = field(default=True)
    prefix: str = field(default="/api")
    versions: list = field(factory=lambda: ["stable", "latest"])


def bind_endpoint(app, endpoint, prefix, tags):
    app.include_router(
        endpoint.router, include_in_schema=endpoint.public, prefix=prefix, tags=tags
    )


def bind_endpoints(app, endpoints):
    for ep in endpoints:
        # Only apply versioning to routes with defined versions
        if ep.versions:
            for version in ep.versions:
                if version == "stable":
                    prefix = f"{ep.prefix}/{ep.current_version}"
                    tags = [ep.current_version]
                else:
                    prefix = f"{ep.prefix}/{version}"
                    tags = [version]

                bind_endpoint(app, ep, prefix, tags)
        else:
            bind_endpoint(app, ep, "", [])


def make_app(UOW, config: dict, task_proxy: TaskProxy) -> FastAPIOffline:
    # dependencies
    auth_config = config.get("AUTH", {})
    url_config = config.get("URL", {})

    authenticator_factory = AuthenticatorFactory()
    auth = authenticator_factory.make_authenticator(UOW, auth_config)
    jwt_config = JWTConfig(auth_config["jwt"])
    admin_token_auth = AdminTokenAuthenticator(UOW)
    jwt_auth = JWTAuthenticator(auth_config["jwt"], UOW, jwt_config, task_proxy)
    token_service_auth = TokenServiceAuthenticator(auth_config["token_service"], UOW)
    token_or_fallback_auth = TokenOrFallbackAuthenticator(token_service_auth, auth)

    app = FastAPIOffline(root_path=config.get("ROOT_PATH", ""))

    # import routers
    api_version = config["API_VERSION"]
    endpoints = [
        Endpoint(api_version, make_jwt_router(jwt_auth, task_proxy, url_config)),
        Endpoint(
            api_version, make_well_known_router(jwt_config.jwks), prefix="", versions=[]
        ),
        Endpoint(api_version, make_community_router(UOW, token_or_fallback_auth)),
        Endpoint(
            api_version, make_admin_route_router(UOW, admin_token_auth), public=False
        ),
        Endpoint(
            api_version, make_admin_domain_router(UOW, admin_token_auth), public=False
        ),
        Endpoint(
            api_version,
            make_admin_user_router(UOW, auth, admin_token_auth),
            public=False,
        ),
        Endpoint(
            api_version, make_admin_group_router(UOW, admin_token_auth), public=False
        ),
        Endpoint(api_version, make_admin_token_router(UOW, auth), public=False),
        Endpoint(
            api_version,
            make_route_router(
                UOW,
                task_proxy,
                jwt_config,
                url_config,
                token_or_fallback_auth,
            ),
            versions=["v1", "v2", "stable", "latest"],
        ),
    ]

    bind_endpoints(app, endpoints)

    auth.setup(app)

    return app


def make_server(UOW: BaseUOW, config: dict, task_proxy: TaskProxy) -> uvicorn.Server:
    app = make_app(UOW, config, task_proxy)
    # TODO: abstract data type for config
    server_config = config.get("SERVER", {})

    uvicorn_config = uvicorn.Config(app, **server_config)
    return uvicorn.Server(uvicorn_config)


def custom_spec_generator(app) -> str:
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Route Registry",
        version=__version__,
        summary="OpenAPI Spec for Route Registry",
        description="API for storing and interfacing with dynamic routes",
        routes=app.routes,
    )

    return openapi_schema


def generate_openapi_spec(config: dict) -> str:
    app = make_app(None, config, None)
    schema = custom_spec_generator(app)

    with open("openapi.json", "w") as fh:
        fh.write(json.dumps(schema, indent=2))
