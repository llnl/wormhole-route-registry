"""Repositories for Route Registry."""

from attrs import define
from multimethod import multimethod
from sqlalchemy import select, and_, or_
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.exc import NoResultFound
from typing import List, Optional, Type
from uuid import UUID

from .. import models


@define
class BaseRepoException(Exception):
    """Base Repo Exception."""

    msg: str


@define
class MissingEntities(BaseRepoException):
    """Missing requested entities in a bulk query."""

    pass


@define
class NotFound(BaseRepoException):
    """Not found exception"""

    pass


@define
class AlreadyExists(BaseRepoException):
    """Already exists exception"""

    pass


@define
class BaseRepo:
    """Base repository."""


@define
class SqlAlchemyRepo(BaseRepo):
    session: Session


@define
class SqlEntityRepo(SqlAlchemyRepo):
    def get(self, entity_id: str) -> Optional[models.Entity]:
        return self.session.execute(
            select(models.Entity).where(models.Entity.id == entity_id)
        ).scalar_one_or_none()

    def get_user(self, uid: str) -> models.User:
        try:
            return self.session.execute(
                select(models.User).where(models.User.uid == uid)
            ).scalar_one()
        except NoResultFound:
            raise NotFound(f"User with uid {uid} not found")

    def get_users(self, uids: list[str], require_all: bool = True) -> list[models.User]:
        users = self.session.query(models.User).filter(models.User.uid.in_(uids)).all()

        if len(uids) != len(users) and require_all:
            raise MissingEntities(f"Requested {len(uids)} users and got {len(users)}")

        return users

    def get_group(self, name: str) -> models.Group:
        try:
            return self.session.execute(
                select(models.Group).where(models.Group.name == name)
            ).scalar_one()
        except NoResultFound:
            raise NotFound(f"Group with name {name} not found")

    def get_groups(
        self, names: list[str], require_all: bool = True
    ) -> list[models.Group]:
        groups = (
            self.session.query(models.Group).filter(models.Group.name.in_(names)).all()
        )

        if len(names) != len(groups) and require_all:
            raise MissingEntities(f"Requested {len(names)} users and got {len(groups)}")

        return groups

    @multimethod
    def add(self, entity: models.Entity):
        self.session.add(entity)

    @add.register
    def _(self, entities: List[models.Entity]):
        self.session.add_all(entities)

    def remove_user(self, uid: str):
        try:
            u = self.session.query(models.User).where(models.User.uid == uid).one()
            self.session.delete(u)
        except NoResultFound:
            raise NotFound(f"Unable to find user with uid {uid}")

    def remove_group(self, name: str):
        try:
            g = self.session.query(models.Group).where(models.Group.name == name).one()
            self.session.delete(g)
        except NoResultFound:
            raise NotFound(f"Unable to find group with name {name}")

    def list(
        self, model: Optional[Type[models.Entity]] = models.Entity
    ) -> List[models.Entity]:
        return self.session.execute(select(model)).scalars().all()


@define
class SqlDomainRepo(SqlAlchemyRepo):
    def get(self, domain_id: str) -> Optional[models.Domain]:
        return self.session.execute(
            select(models.Domain).where(models.Domain.id == domain_id)
        ).scalar_one_or_none()

    def get_default(self) -> models.Domain:
        try:
            return self.session.execute(
                select(models.Domain).where(models.Domain.default)
            ).scalar_one()
        except NoResultFound:
            raise NotFound("Unable to find default domain")

    def get_by_name(self, name: str) -> Optional[models.Domain]:
        return self.session.execute(
            select(models.Domain).where(models.Domain.name == name)
        ).scalar_one_or_none()

    @multimethod
    def add(self, domain: models.Domain):
        self.session.add(domain)

    @add.register
    def _(self, domains: List[models.Domain]):
        self.session.add_all(domains)

    def remove(self, domain_id: str):
        domain = self.get(domain_id)
        if not domain:
            raise NotFound(f"Domain with id {domain_id} not found")
        self.session.delete(domain)

    def list(self) -> List[models.Domain]:
        return self.session.query(models.Domain).all()


@define
class SqlMembershipRequestRepo(SqlAlchemyRepo):
    def get(
        self, entity_id: str, community_id: str, route_id: str
    ) -> Optional[models.MembershipRequest]:
        return self.session.execute(
            select(models.MembershipRequest).where(
                and_(
                    models.MembershipRequest.entity_id == entity_id,
                    models.MembershipRequest.community_id == community_id,
                    models.MembershipRequest.route_id == route_id,
                )
            )
        ).scalar_one_or_none()

    @multimethod
    def add(self, membership_request: models.MembershipRequest):
        self.session.add(membership_request)

    @add.register
    def _(self, membership_requests: List[models.MembershipRequest]):
        self.session.add_all(membership_requests)

    def remove(self, membership_request_id: str):
        membership_request = self.get(membership_request_id)
        if not membership_request:
            raise NotFound(
                f"MembershipRequest with id {membership_request_id} not found"
            )
        self.session.delete(membership_request)

    def list(
        self,
        community_id: Optional[str] = None,
        status: Optional[models.MembershipStatus] = None,
    ) -> List[models.MembershipRequest]:
        query = select(models.MembershipRequest)
        if community_id:
            query = query.where(models.MembershipRequest.community_id == community_id)
        if status:
            query = query.where(models.MembershipRequest.status == status)
        return self.session.execute(query).scalars().all()


@define
class SqlCommunityRepo(SqlAlchemyRepo):
    def get(
        self, _id: str, entity_id: Optional[str] = None
    ) -> Optional[models.Community]:
        try:
            UUID(_id)
            return self.get_by_id(_id, entity_id=entity_id)
        except ValueError:
            return self.get_by_name(_id, entity_id=entity_id)

    def get_by_id(
        self, community_id: str, entity_id: Optional[str] = None
    ) -> Optional[models.Community]:
        query = select(models.Community).options(
            selectinload(models.Community.routes).selectinload(models.Route.community)
        )

        query = query.where(models.Community.id == community_id)

        if entity_id:
            query = query.where(models.Community.entity_id == entity_id)

        return self.session.execute(query).scalar_one_or_none()

    def get_by_name(
        self, name: str, entity_id: Optional[str] = None
    ) -> Optional[models.Community]:
        query = select(models.Community).options(
            selectinload(models.Community.routes).selectinload(models.Route.community)
        )

        query = query.where(models.Community.name == name)

        if entity_id:
            query = query.where(models.Community.entity_id == entity_id)

        return self.session.execute(query).scalar_one_or_none()

    @multimethod
    def add(self, community: models.Community):
        self.session.add(community)

    @add.register
    def _(self, communities: List[models.Community]):
        self.session.add_all(communities)

    def remove(self, community_id: str):
        community = self.get(community_id)
        if not community:
            raise NotFound(f"Community with id {community_id} not found")
        self.session.delete(community)

    def remove_by_name(self, name: str):
        community = self.get_by_name(name)
        if not community:
            raise NotFound(f"Community with id {name} not found")
        self.session.delete(community)

    def list(self, entity_id: str) -> List[models.Community]:
        # Eager load routes within the community
        query = select(models.Community).options(
            selectinload(models.Community.routes).selectinload(models.Route.community)
        )
        if entity_id:
            query = query.where(models.Community.entity_id == entity_id)
        return self.session.execute(query).scalars().all()


@define
class SqlRouteRepo(SqlAlchemyRepo):
    def get(self, route_id: str) -> Optional[models.Route]:
        query = select(models.Route).options(selectinload(models.Route.community))
        return self.session.execute(
            query.where(models.Route.id == route_id)
        ).scalar_one_or_none()

    def get_by_src_parts(
        self, route_name: str, domain_name: str
    ) -> Optional[models.Route]:
        query = select(models.Route).options(selectinload(models.Route.community))
        return self.session.execute(
            query.join(models.Domain).where(
                models.Domain.name == domain_name,
                models.Route.name == route_name,
            )
        ).scalar_one_or_none()

    def get_by_src(self, src: str) -> Optional[models.Route]:
        query = select(models.Route).options(selectinload(models.Route.community))
        return self.session.execute(
            query.where(models.Route.src == src)
        ).scalar_one_or_none()

    def get_by_dst(self, dst: str) -> Optional[models.Route]:
        query = select(models.Route).options(selectinload(models.Route.community))
        return self.session.execute(
            query.where(models.Route.dst == dst)
        ).scalar_one_or_none()

    @multimethod
    def add(self, route: models.Route):
        self.session.add(route)

    @add.register
    def _(self, routes: List[models.Route]):
        self.session.add_all(routes)

    def list(
        self,
        verification: models.VerificationStatus = None,
        status: models.Status = None,
        conditions: list = None,
    ) -> List[models.Route]:
        conditions = conditions or []
        query = (
            select(models.Route)
            .options(selectinload(models.Route.community))
            .options(
                selectinload(models.Route.rules)
                .selectinload(models.Rule.entity)
                .selectin_polymorphic([models.User, models.Group])
            )
        )
        if verification:
            conditions.append(models.Route.verification_status == verification)

        if status:
            conditions.append(models.Route.status == status)

        if conditions:
            query = query.where(and_(*conditions))

        return self.session.scalars(query).all()

    def list_active(self) -> List[models.Route]:
        query = select(models.Route).where(
            and_(
                models.Route.verification_status == models.VerificationStatus.VERIFIED,
                or_(
                    models.Route.status == models.Status.UP,
                    models.Route.status == models.Status.DOWN,
                ),
            )
        )
        return self.session.scalars(query).all()


@define
class SqlRuleRepo(SqlAlchemyRepo):
    def get(self, route_id: str, entity_id: str) -> Optional[models.Rule]:
        return self.session.execute(
            select(models.Rule).where(
                and_(
                    models.Rule.route_id == route_id, models.Rule.entity_id == entity_id
                )
            )
        ).scalar_one_or_none()

    @multimethod
    def add(self, rule: models.Rule):
        self.session.add(rule)

    @add.register
    def _(self, rules: List[models.Rule]):
        self.session.add_all(rules)

    def remove_for_route(self, route_id: str):
        self.session.query(models.Rule).where(models.Rule.route_id == route_id).delete()

    def list(self, route_id: Optional[str] = None) -> List[models.Rule]:
        stmt = select(models.Rule)
        if route_id:
            stmt = stmt.where(models.Rule.route_id == route_id)
        return self.session.execute(stmt).scalars().all()


@define
class SqlAdminTokenRepo(SqlAlchemyRepo):
    def get(self, admin_token_id: str) -> Optional[models.AdminToken]:
        return self.session.execute(
            select(models.AdminToken).where(models.AdminToken.id == admin_token_id)
        ).scalar_one_or_none()

    def remove(self, admin_token_id: str):
        a = self.get(admin_token_id)
        if a is None:
            raise NotFound(f"AdminToken with id {admin_token_id} does not exist.")
        self.session.delete(a)

    @multimethod
    def add(self, admin_token: models.AdminToken):
        self.session.add(admin_token)

    @add.register
    def _(self, admin_tokens: List[models.AdminToken]):
        self.session.add_all(admin_tokens)

    def list(self) -> List[models.AdminToken]:
        return self.session.execute(select(models.AdminToken)).scalars().all()
