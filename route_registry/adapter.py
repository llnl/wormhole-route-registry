from attrs import asdict
from typing import Union, Optional
from .models import (
    Route,
    Domain,
    Community,
    User,
    Group,
    Policy,
    MembershipRequest,
    VerificationStatus,
    Status,
    AdminToken,
)
from .pydantic_models import (
    RegistrationRequest,
    Route as PydanticRoute,
    Domain as PydanticDomain,
    Community as PydanticCommunity,
    User as PydanticUser,
    Group as PydanticGroup,
    MembershipRequest as PydanticMembershipRequest,
    AdminToken as PydanticAdminToken,
)


def to_domain(p_domain: PydanticDomain) -> Domain:
    # Purposely excluding default since we'll have a single API for that
    return Domain(name=p_domain.name, value=p_domain.value)


def from_domain(domain: Domain) -> PydanticDomain:
    return PydanticDomain(**asdict(domain))


def to_user(p_user: PydanticUser) -> User:
    return User(uid=p_user.uid, duid=p_user.duid)


def from_user(user: User) -> PydanticUser:
    return PydanticUser(uid=user.uid)


def to_group(p_group: PydanticGroup) -> Group:
    return Group(name=p_group.name)


def from_group(group: Group) -> PydanticGroup:
    return PydanticGroup(name=group.name)


def to_community(p_community: PydanticCommunity) -> Community:
    return Community(name=p_community.name)


def from_community(community: Community) -> PydanticCommunity:
    p_routes = [from_route(r, with_rules=False) for r in community.routes]
    return PydanticCommunity(id=community.id, name=community.name, routes=p_routes)


def from_membership_request(request: MembershipRequest) -> PydanticMembershipRequest:
    return PydanticMembershipRequest(
        entity_id=request.entity_id,
        community_id=request.community_id,
        route_id=request.route_id,
        status=request.status,
    )


def to_verification_status(vs: Optional[str] = None) -> VerificationStatus:
    if not vs:
        return

    try:
        return VerificationStatus[vs.upper()]
    except KeyError:
        raise ValueError(f"Unable to convert {vs} to a VerificationStatus")


def to_status(s: Optional[str] = None) -> Status:
    if not s:
        return

    try:
        return Status[s.upper()]
    except KeyError:
        raise ValueError(f"Unable to convert {s} to a Status")


def to_route(p_route: Union[PydanticRoute, RegistrationRequest]) -> Route:
    return Route(name=p_route.name, dst=p_route.dst)


def from_route(route: Route, with_rules: bool = True) -> PydanticRoute:
    p_route = PydanticRoute(
        id=route.id,
        endpoint=route.id,
        name=route.name,
        src=route.src,
        url=route.src,
        dst=route.dst,
        jwt=route.token,
        token=route.token,
        community_id=route.community_id,
        community_name=route.community.name if route.community else None,
    )

    if not with_rules:
        return p_route

    for rule in route.rules:
        policy_set = (
            p_route.rules.allowed
            if rule.policy is Policy.ALLOW
            else p_route.rules.disallowed
        )
        entity_set = (
            policy_set.users if isinstance(rule.entity, User) else policy_set.groups
        )
        entity_id = (
            rule.entity.uid if isinstance(rule.entity, User) else rule.entity.name
        )

        entity_set.append(entity_id)

    return p_route


def to_admin_token(p_admin_token: PydanticAdminToken) -> AdminToken:
    data = {"name": p_admin_token.name, "role": p_admin_token.role}
    return AdminToken(**data)


def from_admin_token(admin_token: AdminToken) -> PydanticAdminToken:
    return PydanticAdminToken(name=admin_token.name, role=admin_token.role)
