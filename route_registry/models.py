"""Models supporting Route Registry."""

import pendulum
from attrs import define, field
from joserfc import jwk
from enum import StrEnum
from uuid import uuid4
from urllib.parse import urlunparse, ParseResult

from .utils import (
    make_token,
)


def to_pendulum_dt(val) -> pendulum.DateTime:
    if isinstance(val, int) or isinstance(val, float):
        return pendulum.from_timestamp(val)
    elif isinstance(val, pendulum.DateTime):
        return val
    else:
        raise ValueError(f"Unable to convert {val} to a pendulum.DateTime")


@define(slots=False)
class Entity:
    id: str = field(factory=lambda: str(uuid4()))
    kind: str = field(default="entity")
    communities: list = field(factory=list)
    routes: list = field(factory=list)
    rules: list = field(factory=list)


@define(slots=False)
class User(Entity):
    uid: str = field()
    duid: str = field(default=None)
    id: str = field(factory=lambda: str(uuid4()))
    kind: str = field(default="user")
    routes: list = field(factory=list)
    communities: list = field(factory=list)
    rules: list = field(factory=list)
    is_admin: bool = field(default=False)


@define(slots=False)
class Group(Entity):
    name: str = field()
    id: str = field(factory=lambda: str(uuid4()))
    kind: str = field(default="group")
    routes: list = field(factory=list)
    communities: list = field(factory=list)
    rules: list = field(factory=list)


class VerificationStatus(StrEnum):
    VERIFIED = "VERIFIED"
    PENDING = "PENDING"
    UNVERIFIED = "UNVERIFIED"


class Status(StrEnum):
    UP = "UP"
    MISCONFIGURED = "MISCONFIGURED"
    MISSING_ENTITY = "MISSING_ENTITY"
    UPGRADE_REQUIRED = "UPGRADE_REQUIRED"
    SERVER_ERROR = "SERVER_ERROR"
    DOWN = "DOWN"


class DomainType(StrEnum):
    STANDARD = "STANDARD"
    EPHEMERAL = "EPHEMERAL"
    USER = "USER"


@define(slots=False)
class Domain:
    id: str = field(factory=uuid4, converter=str)
    name: str = field(default=None)
    value: str = field(default=None)
    domain_type: DomainType = field(default=DomainType.STANDARD)
    restricted: bool = field(default=False)
    default: bool = field(default=False)

    def create_src_url(
        self,
        app_name: str,
        scheme: str = "https",
        path: str = "/",
        user: User = None,
        bind_subdomain: bool = True,
    ) -> str:
        if self.domain_type is DomainType.USER:
            if not user:
                raise ValueError(f"User required to use domain {self.name}")

            app_name = f"{user.uid}-{app_name}"
        elif self.domain_type is DomainType.EPHEMERAL:
            app_name = f"{app_name}-{uuid4()}"

        netloc = self.value if not bind_subdomain else f"{app_name}.{self.value}"
        path = f"{app_name}" if not bind_subdomain else "/"

        # ParseResult(scheme, netloc, path, params, query, fragment)
        return urlunparse(ParseResult(scheme, netloc, path, None, None, None))


class MembershipStatus(StrEnum):
    UNKNOWN = "UNKNOWN"
    PENDING = "PENDING"
    DECLINED = "DECLINED"
    APPROVED = "APPROVED"


@define(slots=False)
class MembershipRequest:
    entity_id: str = field(default=None)
    community_id: str = field(default=None)
    route_id: str = field(default=None)
    status: MembershipStatus = field(default=MembershipStatus.UNKNOWN)


@define(slots=False)
class Community:
    id: str = field(factory=lambda: str(uuid4()))
    name: str = field(default=None)
    entity_id: str = field(default=None)
    entity: Entity = field(default=None)
    routes: list = field(factory=list)


@define(slots=False)
class Route:
    id: str = field(factory=lambda: str(uuid4()))
    domain_id: str = field(default=None)
    domain: Domain = field(default=None)
    community_id: str = field(default=None)
    community: Community = field(default=None)
    name: str = field(default=None)
    src: str = field(default=None)
    dst: str = field(default=None)
    token: str = field(factory=make_token)
    rules: list = field(factory=list)
    entities: list = field(factory=list)
    verification_status: VerificationStatus = field(
        default=VerificationStatus.UNVERIFIED
    )
    status: Status = field(default=Status.DOWN)
    last_contact: pendulum.DateTime = field(
        factory=pendulum.now, converter=to_pendulum_dt
    )


class Policy(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


@define(slots=False)
class Rule:
    route_id: str = field(default=None)
    entity_id: str = field(default=None)
    route: Route = field(default=None)
    entity: Entity = field(default=None)
    policy: Policy = field(default=Policy.DENY)


@define
class EntitySet:
    users: list[User] = field(factory=list)
    groups: list[Group] = field(factory=list)

    @property
    def uids(self):
        return [u.uid for u in self.users]

    @property
    def group_names(self):
        return [g.name for g in self.groups]


@define
class Authorization:
    data: dict
    version: str = field()
    allowed: EntitySet = field()
    disallowed: EntitySet = field()

    @version.default
    def _version(self):
        return self.data["version"]

    @allowed.default
    def _allowed(self):
        users = [User(uid) for uid in self.data["allowed"].get("users", [])]
        groups = [Group(name) for name in self.data["allowed"].get("groups", [])]

        return EntitySet(users=users, groups=groups)

    @disallowed.default
    def _disallowed(self):
        users = [User(uid) for uid in self.data["disallowed"].get("users", [])]
        groups = [Group(name) for name in self.data["disallowed"].get("groups", [])]

        return EntitySet(users=users, groups=groups)


@define
class JWK:
    kid: str
    config: dict
    key_type: str = field()
    kid: str = field()
    public_key: jwk.Key = field()
    private_key: jwk.Key = field()

    def __hash__(self):
        return hash(self.__class__.__name__)

    @key_type.default
    def _key_type(self):
        return self.config["key_type"]

    @public_key.default
    def _public_key(self):
        public_pem = self.config.get("public_pem")
        if public_pem:
            return jwk.import_key(public_pem, self.key_type, {"kid": self.kid})

    @private_key.default
    def _private_key(self):
        private_pem = self.config.get("private_pem")
        if private_pem:
            return jwk.import_key(private_pem, self.key_type)


@define
class JWKS:
    config: dict = field(factory=dict)
    key_map: dict[str, JWK] = field()
    keys: dict = field()

    @key_map.default
    def _key_map(self):
        keys = self.config.get("keys", {})
        return {k: JWK(k, v) for k, v in keys.items()}

    @keys.default
    def _keys(self):
        return {
            "keys": [
                k.public_key.as_dict() for k in self.key_map.values() if k.public_key
            ]
        }


@define
class JWTConfig:
    config: dict
    jwks: JWKS = field()
    alg: str = field()
    active_kid: str = field()
    lifespan: int = field()
    signing_secret: jwk.Key = field()

    @jwks.default
    def _jwks(self):
        return JWKS(config=self.config)

    @active_kid.default
    def _active_kid(self):
        return str(self.config["active_kid"])

    @alg.default
    def _alg(self):
        return self.config["alg"]

    @lifespan.default
    def _lifespan(self):
        return self.config["lifespan"]

    @signing_secret.default
    def _signing_secret(self):
        return self.jwks.key_map[self.active_kid].private_key


class AdminRole(StrEnum):
    ANY = "ANY"
    OBSERVER = "OBSERVER"
    DOMAIN = "DOMAIN"
    IDENTITY = "IDENTITY"
    NONE = "NONE"


@define(slots=False)
class AdminToken:
    name: str
    role: AdminRole
    id: str = field(factory=uuid4, converter=str)
    value: str = field(factory=make_token)
