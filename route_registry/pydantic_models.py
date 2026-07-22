from pydantic import BaseModel
from .models import AdminRole


class User(BaseModel):
    uid: str | None = ""
    duid: str | None = ""


class Group(BaseModel):
    name: str | None = ""


class EntitySet(BaseModel):
    users: list[str] | None = []
    groups: list[str] | None = []


class Domain(BaseModel):
    id: str | None = ""
    name: str
    value: str
    default: bool | None = False


class Rules(BaseModel):
    version: str | None = None
    allowed: EntitySet | None = EntitySet()
    disallowed: EntitySet | None = EntitySet()


class Tunnel(BaseModel):
    url: str | None = None
    jwt: str | None = None
    endpoint: str | None = None


class Airlock(BaseModel):
    jwt_issuer_url: str | None = None


class Community(BaseModel):
    name: str
    id: str | None = None
    routes: list | None = []


class MembershipRequest(BaseModel):
    entity_id: str | None = None
    community_id: str | None = None
    route_id: str | None = None
    status: str | None = None


class Route(BaseModel):
    name: str
    domain_name: str | None = None
    community_name: str | None = None
    id: str | None = None
    dst: str | None = None
    src: str | None = None
    url: str | None = None
    token: str | None = None
    endpoint: str | None = None
    jwt: str | None = None
    community_id: str | None = None
    rules: Rules | None = Rules()


class RegistrationRequest(BaseModel):
    name: str
    domain_name: str | None = None
    community_name: str | None = None


class RegistrationResponse(BaseModel):
    url: str
    airlock: Airlock
    tunnel: Tunnel
    # TODO: remove once client migrated
    endpoint: str | None = None
    jwt: str | None = None


class JWKSet(BaseModel):
    keys: list[dict] | None = list()


class AdminToken(BaseModel):
    name: str
    role: AdminRole
