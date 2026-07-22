"""Service Layer for Route Registry."""

import bcrypt
import logging
import pendulum
import requests

from attrs import define
from joserfc import jwt
from jsonschema import validate
from jsonschema.exceptions import ValidationError
from typing import Optional

from .clients.authorization import (
    AuthorizationClient,
    AuthorizationClientException,
    ConnectionException,
)
from .clients.holepunch import HolePunchClient
from .models import (
    Domain,
    Community,
    MembershipRequest,
    MembershipStatus,
    Route,
    VerificationStatus,
    Status,
    Authorization,
    Policy,
    Rule,
    User,
    Group,
    JWTConfig,
    AdminToken,
)
from .store.repository import MissingEntities, NotFound as RepoNotFound
from .service.uow import (
    BaseUOW,
    AlreadyExists as UOWAlreadyExists,
    UOWException,
)
from .utils import urljoin


logger = logging.getLogger(__name__)


@define
class BaseServiceException(Exception):
    """Base Service Exception."""

    msg: str


@define
class RouteRegistrationException(BaseServiceException):
    """Route Registration Error."""

    pass


@define
class StatusCheckException(BaseServiceException):
    """Status Check Exception."""

    pass


@define
class DomainNotFound(BaseServiceException):
    """Domain not found Exception."""

    pass


@define
class NotAllowed(BaseServiceException):
    """Not found Exception."""

    pass


@define
class NotFound(BaseServiceException):
    """Not found Exception."""

    pass


@define
class AlreadyExists(BaseServiceException):
    """Already exists Exception."""

    pass


def register_route(
    UOW: BaseUOW,
    user_uid: str,
    route_name: str,
    domain_name: str,
    tunnel_url: str,
    bind_subdomain: bool,
    community: Optional[Community] = None,
) -> Route:
    """
    Registers a brand new or existing (bound) route.

    New routes are allowed to bind to unrestricted domains. If no domain is
    specified the default is used.

    Restricted routes are bound using a separate API. On invocation of register,
    there will already be an established route with an established relationship
    to the restricted domain.

    Any community passed to this method **must** be one the route is allowed
    to attach to, i.e. it is owned by the user_uid.
    """

    with UOW() as uow:
        domain = (
            uow.domain_repo.get_by_name(domain_name) or uow.domain_repo.get_default()
        )

        if not domain:
            raise NotFound("No domain specified and no default domain configured")

        user = uow.entity_repo.get_user(user_uid)

        src_url = domain.create_src_url(
            route_name, user=user, bind_subdomain=bind_subdomain
        )

        route = uow.route_repo.get_by_src(src_url)
        if route:
            if user not in route.entities:
                raise NotAllowed("Route already taken")

            if community and not route.community:
                route.community = community

            route.last_contact = pendulum.now()
            route.verification_status = VerificationStatus.VERIFIED
            return route

        if domain and domain.restricted:
            # Restricted domains must be bound to a route using the bind API
            raise NotAllowed("Unable to register with restricted domain")

        route = Route(
            name=route_name,
            src=src_url,
            dst=tunnel_url,
            verification_status=VerificationStatus.VERIFIED,
            domain=domain,
            community=community,
        )

        route.entities.append(user)
        uow.route_repo.add(route)
        return route


def list_routes(
    UOW: BaseUOW, verification_status: VerificationStatus, status: Status
) -> list[Route]:
    with UOW() as uow:
        return uow.route_repo.list(verification=verification_status, status=status)


def list_available_routes(UOW: BaseUOW) -> list[Route]:
    with UOW() as uow:
        return [
            route
            for route in uow.route_repo.list(
                verification=VerificationStatus.VERIFIED, status=Status.UP
            )
        ]


def unverify_route(UOW: BaseUOW, route_id: str):
    with UOW() as uow:
        route = uow.route_repo.get(route_id)

        route.verification_status = VerificationStatus.UNVERIFIED
        route.status = Status.DOWN


def store_rules(uow: BaseUOW, route: Route, authz: Authorization):
    user_policies = [
        (Policy.ALLOW, u) for u in uow.entity_repo.get_users(authz.allowed.uids)
    ] + [(Policy.DENY, u) for u in uow.entity_repo.get_users(authz.disallowed.uids)]
    group_policies = [
        (Policy.ALLOW, g) for g in uow.entity_repo.get_groups(authz.allowed.group_names)
    ] + [
        (Policy.DENY, g)
        for g in uow.entity_repo.get_groups(authz.disallowed.group_names)
    ]

    uow.rule_repo.remove_for_route(route.id)

    for policy, entity in user_policies + group_policies:
        uow.rule_repo.add(Rule(route=route, entity=entity, policy=policy))


def list_rules(UOW: BaseUOW, route: Route) -> list[Rule]:
    with UOW() as uow:
        return uow.rule_repo.list(route.id)


def fetch_authorization(
    route: Route, authz_path: str, schema: dict, headers: dict = None
) -> dict:
    headers = headers or {}
    # Remain backwards compatible
    authz_path = authz_path or "authorization.json"

    authz = requests.get(urljoin(route.dst, authz_path), headers=headers).json()
    try:
        validate(instance=authz, schema=schema)
    except ValidationError:
        raise ValueError("Authorization file is invalid")

    return authz


def validate_route(UOW: BaseUOW, route_id: str, authz_path: str, schema: dict):
    with UOW() as uow:
        route = uow.route_repo.get(route_id)

        authz = fetch_authorization(route, authz_path, schema)
        plain_token = authz.get("token")

        if not bcrypt.checkpw(plain_token.encode(), route.token.encode()):
            raise ValueError("Invalid token in authoriztion.json file")

        store_rules(uow, route, Authorization(data=authz))
        route.verification_status = VerificationStatus.VERIFIED
        route.status = Status.UP
        route.last_contact = pendulum.now()


def notify_route_table_update(holepunch_client: HolePunchClient):
    holepunch_client.notify_route_update()


def update_route(
    UOW: BaseUOW, route_id: str, authz_client: AuthorizationClient, schema: dict
):
    """Update a routes status and authorization profile

    A route may be reachable but in a bad state (misconfigured, etc) which
    reflect in the other Status enum fields.

    We re-raise the error so that transient ones cause our task system to
    retry if possible.
    """

    err = None
    with UOW() as uow:
        route = uow.route_repo.get(route_id)
        try:
            # TODO optional health check target on route
            authz = authz_client.get_authorization(route)
            validate(instance=authz, schema=schema)
            store_rules(uow, route, Authorization(data=authz))
            route.status = Status.UP
            route.last_contact = pendulum.now()
        # TODO: logs for each exception condition
        except ConnectionException as e:
            route.status = Status.DOWN
            err = e
        except ValidationError as e:
            route.status = Status.MISCONFIGURED
            err = e
        except MissingEntities as e:
            route.status = Status.MISSING_ENTITY
            err = e
        except AuthorizationClientException as e:
            route.status = Status.SERVER_ERROR
            err = e

    if err:
        raise err


def check_routes(
    UOW: BaseUOW,
    schema: dict,
    authz_client: AuthorizationClient,
    stale_duration: int = 90,
):
    now = pendulum.now()
    with UOW() as uow:
        routes = uow.route_repo.list_active()

    for route in routes:
        logger.info(f"Checking route {route.id} at {route.dst}")

        try:
            update_route(UOW, route.id, authz_client, schema)
        except Exception as e:
            logger.warning(e)

        if now.diff(route.last_contact).in_days() > stale_duration:
            logger.warning(f"Unverifying stale route to {route.dst}")
            unverify_route(UOW, route.id)


def create_piko_jwt(
    route: Route,
    jwt_config: JWTConfig,
    lifespan: int | None = None,
) -> str:
    header = {"alg": jwt_config.alg, "kid": jwt_config.active_kid}
    now = pendulum.now()
    lifespan = lifespan or jwt_config.lifespan
    payload = {
        "sub": route.id,
        "piko": {
            "endpoints": [route.id],
        },
        "iat": now.timestamp(),
        "exp": now.add(seconds=lifespan).timestamp(),
        "nbf": now.timestamp(),
    }

    return jwt.encode(header, payload, jwt_config.signing_secret)


def list_users(UOW) -> list[User]:
    with UOW() as uow:
        return uow.entity_repo.list(User)


def create_user(UOW, user: User) -> User:
    try:
        with UOW() as uow:
            uow.entity_repo.add(user)
    except UOWAlreadyExists:
        raise AlreadyExists(f"User {user.uid} already exists")

    return user


def remove_user(UOW, user: User):
    try:
        with UOW() as uow:
            uow.entity_repo.remove_user(user)
    except RepoNotFound:
        raise NotFound(f"Unable to find user {user.uid}")


def list_groups(UOW) -> list[Group]:
    with UOW() as uow:
        return uow.entity_repo.list(Group)


def create_group(UOW, group: Group) -> Group:
    try:
        with UOW() as uow:
            uow.entity_repo.add(group)
    except UOWAlreadyExists:
        raise AlreadyExists(f"Group {group.name} already exists")

    return group


def remove_group(UOW, group: Group):
    try:
        with UOW() as uow:
            uow.entity_repo.remove_group(group)
    except RepoNotFound:
        raise NotFound(f"Unable to find group {group.name}")


def create_domain(UOW, domain: Domain) -> Domain:
    try:
        with UOW() as uow:
            uow.domain_repo.add(domain)
    except UOWAlreadyExists:
        raise AlreadyExists(f"Domain {domain.name} already exists")

    return domain


def set_default_domain(UOW, domain_id: str):
    with UOW() as uow:
        domains = uow.domain_repo.list()

        for d in domains:
            d.default = True if d.id == domain_id else False

        if not any(d.default for d in domains):
            raise DomainNotFound(f"Unable to find domain with id {domain_id}")


def remove_domain(UOW, domain_id: str):
    try:
        with UOW() as uow:
            uow.domain_repo.remove(domain_id)
    except RepoNotFound:
        raise DomainNotFound(f"Unable to find domain {domain_id}")


def list_domains(UOW) -> list[Domain]:
    with UOW() as uow:
        return uow.domain_repo.list()


def get_user_community(UOW, user: User, _id: str) -> Optional[Community]:
    with UOW() as uow:
        return uow.community_repo.get(_id, entity_id=user.id)


def create_community(UOW, user: User, community: Community) -> Community:
    try:
        with UOW() as uow:
            user = uow.entity_repo.get_user(user.uid)
            community.entity = user
            uow.community_repo.add(community)
    except UOWAlreadyExists:
        raise AlreadyExists(f"Community {community.name} already exists")

    return community


def add_route_to_community(
    UOW, user: User, route_id: str, community_id: str
) -> Optional[MembershipRequest]:
    with UOW() as uow:
        user = uow.entity_repo.get_user(user.uid)
        route = uow.route_repo.get(route_id)

        if not route:
            raise NotFound(f"Unable to find route with id {route_id}")

        community = uow.community_repo.get(community_id)
        if not community:
            raise NotFound(f"Unable to find community with id {community_id}")

        if user not in route.entities:
            request = uow.membership_request_repo.get(user.id, community_id, route_id)
            if request:
                return request

            request = MembershipRequest(
                entity_id=user.id,
                community_id=community_id,
                route_id=route_id,
                status=MembershipStatus.PENDING,
            )
            uow.membership_request_repo.add(request)
            return request

        if route in community.routes:
            raise AlreadyExists(f"Route {route} already in {community}")

        community.routes.append(route)


def remove_route_from_community(UOW, user: User, route_id: str, community_id: str):
    """Remove a route from a community.

    We specifically look up the route first to ensure it is owned by the
    invoking user. Then we look for the community in question. This allows
    for removing routes from communities that the invoking user does not own,
    but was allowed to join via membership request.
    """

    with UOW() as uow:
        user = uow.entity_repo.get_user(user.uid)
        route = next((r for r in user.routes if r.id == route_id), None)

        if not route:
            raise NotFound(f"Route {route_id} not found")

        if not route.community or route.community.id != community_id:
            raise NotFound(f"Community {community_id} not found")

        route.community = None


def remove_user_community(UOW, user: User, _id: str):
    try:
        with UOW() as uow:
            user = uow.entity_repo.get_user(user.uid)
            community = next(
                (c for c in user.communities if c.id == _id or c.name == _id), None
            )
            uow.community_repo.remove(community.id)
    except RepoNotFound:
        raise NotFound(f"Unable to find community {_id}")


def list_communities(UOW, entity_id: Optional[str] = None) -> list[Community]:
    with UOW() as uow:
        return uow.community_repo.list(entity_id=entity_id)


def validate_admin_token(uow: BaseUOW, admin_token_value: str) -> bool:
    admin_token_id, admin_token_plain = admin_token_value.split(".")
    admin_token = uow.admin_token_repo.get(admin_token_id)
    if admin_token and bcrypt.checkpw(
        admin_token_plain.encode(), admin_token.value.encode("utf-8")
    ):
        return True
    return False


def get_admin_token(uow: BaseUOW, admin_token_value: str) -> AdminToken:
    admin_token_id, _ = admin_token_value.split(".")
    admin_token = uow.admin_token_repo.get(admin_token_id)
    if not admin_token:
        raise NotFound(f"AdminToken with id {admin_token_id} not found")
    return admin_token


def add_admin(UOW: BaseUOW, user_uid: str):
    with UOW() as uow:
        user = uow.user_repo.get(user_uid)
        if not user:
            raise NotFound(f"User {user_uid} does not exist")
        user.is_admin = True


def remove_admin(UOW: BaseUOW, user_uid: str):
    with UOW() as uow:
        user = uow.user_repo.get(user_uid)
        if not user:
            raise NotFound(f"User {user_uid} does not exist")
        user.is_admin = False


def create_admin_token(UOW: BaseUOW, admin_token: AdminToken) -> str:
    try:
        with UOW() as uow:
            plain_token = admin_token.value
            admin_token.value = bcrypt.hashpw(
                admin_token.value.encode(), bcrypt.gensalt(12)
            ).decode("utf-8")
            uow.admin_token_repo.add(admin_token)
    except UOWAlreadyExists:
        raise AlreadyExists(f"Admin Token name {admin_token.name} already exists.")
    except UOWException as e:
        raise BaseServiceException(e)

    return f"{admin_token.id}.{plain_token}"  # The end user will get the token value this once and then there is no way to retrieve it


def list_admin_tokens(UOW: BaseUOW) -> list[AdminToken]:
    with UOW() as uow:
        return uow.admin_token_repo.list()


def remove_admin_token(UOW: BaseUOW, admin_token_value: str):
    try:
        with UOW() as uow:
            admin_token_id, _ = admin_token_value.split(".")
            uow.admin_token_repo.remove(admin_token_id)
    except RepoNotFound:
        raise NotFound("Admin Token not found")
    except ValueError:
        raise ValueError("Invalid Token Format")
