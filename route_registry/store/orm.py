import pendulum
from sqlalchemy import (
    create_engine,
    Boolean,
    DateTime,
    Table,
    Column,
    String,
    ForeignKey,
    Enum,
    TypeDecorator,
    URL,
    UniqueConstraint,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import registry, relationship, sessionmaker, Session
from urllib.parse import urlparse
from typing import Optional

from .. import models


class PendulumDateTime(TypeDecorator):
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """
        Converts a Pendulum datetime to a naive datetime before storing in the DB.
        """
        if isinstance(value, pendulum.DateTime):
            # Convert to UTC and make it naive
            return value.in_tz("UTC").naive()
        return value

    def process_result_value(self, value, dialect):
        """
        Converts a naive datetime from the DB back into a Pendulum datetime.
        """
        if value is not None:
            # Convert naive datetime to a timezone-aware Pendulum datetime in UTC
            return pendulum.instance(value, tz="UTC")
        return value


mapper_registry = registry()

# Tables

entity_table = Table(
    "entity",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column("kind", String(32)),
)
user_table = Table(
    "user",
    mapper_registry.metadata,
    Column("id", ForeignKey("entity.id"), primary_key=True),
    Column("uid", String(128), unique=True, nullable=False),
    Column("duid", String(128)),
    Column("is_admin", Boolean()),
)
group_table = Table(
    "group",
    mapper_registry.metadata,
    Column("id", ForeignKey("entity.id"), primary_key=True),
    Column("name", String(128), unique=True, nullable=False),
)

route_table = Table(
    "route",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column("domain_id", String(36), ForeignKey("domain.id"), nullable=False),
    Column("community_id", String(36), ForeignKey("community.id"), nullable=True),
    Column("name", String(128), nullable=False),
    Column("src", String(2000), unique=True, nullable=False),
    Column("dst", String(2000), nullable=False),
    Column("token", String(256), unique=True, nullable=False),
    Column("verification_status", Enum(models.VerificationStatus), nullable=False),
    Column("status", Enum(models.Status), nullable=False),
    Column("last_contact", PendulumDateTime(), nullable=False),
)

membership_request_table = Table(
    "membership_request",
    mapper_registry.metadata,
    Column("entity_id", String(36), ForeignKey("entity.id"), primary_key=True),
    Column("community_id", String(36), ForeignKey("community.id"), primary_key=True),
    Column("route_id", String(36), ForeignKey("route.id"), primary_key=True),
    Column(
        "status",
        Enum(models.MembershipStatus),
        nullable=False,
        server_default=models.MembershipStatus.UNKNOWN,
    ),
)

community_table = Table(
    "community",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column("entity_id", String(36), ForeignKey("entity.id"), nullable=False),
    Column("name", String(128), nullable=False),
    UniqueConstraint("entity_id", "name"),
)

domain_table = Table(
    "domain",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column("name", String(128), unique=True, nullable=False),
    Column("value", String(2048), unique=True, nullable=False),
    Column(
        "domain_type",
        Enum(models.DomainType),
        server_default=models.DomainType.STANDARD,
        nullable=False,
    ),
    Column("restricted", Boolean()),
    Column("default", Boolean()),
)

# The composite primary key using route.id and entity.id ensures there's only
# one policy for the pair
rule_table = Table(
    "rule",
    mapper_registry.metadata,
    Column("route_id", ForeignKey("route.id"), primary_key=True),
    Column("entity_id", ForeignKey("entity.id"), primary_key=True),
    Column("policy", Enum(models.Policy), nullable=False),
)

entity_route_association_table = Table(
    "entity_route_association",
    mapper_registry.metadata,
    Column("entity_id", String(36), ForeignKey("entity.id"), primary_key=True),
    Column("route_id", String(36), ForeignKey("route.id"), primary_key=True),
)

admin_token_table = Table(
    "admin_token",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column("name", String(128), unique=True, nullable=False),
    Column("value", String(128), unique=True, nullable=False),
    Column("role", Enum(models.AdminRole), nullable=False),
)

# Model map

mapper_registry.map_imperatively(
    models.Entity,
    entity_table,
    polymorphic_identity="entity",
    polymorphic_on=entity_table.c.kind,
    properties={
        "communities": relationship(models.Community, back_populates="entity"),
        "requests": relationship(models.MembershipRequest, back_populates="entity"),
        "rules": relationship(models.Rule, back_populates="entity"),
        "routes": relationship(
            models.Route,
            secondary=entity_route_association_table,
            back_populates="entities",
        ),
    },
)
mapper_registry.map_imperatively(
    models.User,
    user_table,
    polymorphic_identity="user",
    inherits=models.Entity,
)
mapper_registry.map_imperatively(
    models.Group,
    group_table,
    polymorphic_identity="group",
    inherits=models.Entity,
)
mapper_registry.map_imperatively(
    models.Route,
    route_table,
    properties={
        "domain": relationship(models.Domain, back_populates="routes"),
        "community": relationship(models.Community, back_populates="routes"),
        "requests": relationship(models.MembershipRequest, back_populates="route"),
        "rules": relationship(models.Rule, back_populates="route"),
        "entities": relationship(
            models.Entity,
            secondary=entity_route_association_table,
            back_populates="routes",
        ),
    },
)
mapper_registry.map_imperatively(
    models.Community,
    community_table,
    properties={
        "entity": relationship(models.Entity, back_populates="communities"),
        "routes": relationship(models.Route, back_populates="community"),
        "requests": relationship(models.MembershipRequest, back_populates="community"),
    },
)
mapper_registry.map_imperatively(
    models.MembershipRequest,
    membership_request_table,
    properties={
        "entity": relationship(models.Entity, back_populates="requests"),
        "community": relationship(models.Community, back_populates="requests"),
        "route": relationship(models.Route, back_populates="requests"),
    },
)
mapper_registry.map_imperatively(
    models.Domain,
    domain_table,
    properties={
        "routes": relationship(models.Route, back_populates="domain"),
    },
)
mapper_registry.map_imperatively(
    models.Rule,
    rule_table,
    properties={
        "route": relationship(models.Route),
        "entity": relationship(models.Entity),
    },
)
mapper_registry.map_imperatively(
    models.AdminToken,
    admin_token_table,
)


def escape_url(url: str, config: dict) -> str:
    parsed = urlparse(url)
    username = config.get("username", parsed.username)
    password = config.get("password", parsed.password)
    return URL.create(
        parsed.scheme,
        username=username,
        password=password,
        host=parsed.hostname,
        port=parsed.port,
        database=parsed.path.lstrip("/"),
    ).render_as_string(hide_password=False)


def make_engine(config: Optional[dict] = None) -> Engine:
    config = config or {}
    url = escape_url(config.get("url", "sqlite://"), config)
    engine_options = config.get("engine_options", {})
    return create_engine(url, **engine_options)


def create_db(engine: Engine):
    """Apply all mappings to create our db."""
    mapper_registry.metadata.create_all(engine)


def delete_db(engine: Engine):
    """Drop all tables to delete the db."""
    mapper_registry.metadata.drop_all(engine)


def reset_db(engine: Engine):
    delete_db(engine)
    create_db(engine)


def make_session_factory(engine: Optional[Engine] = None) -> Session:
    engine = engine or create_engine()
    create_db(engine)

    return sessionmaker(engine, expire_on_commit=False)
