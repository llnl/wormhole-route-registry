"""Unit of Work for Route Registry."""

from attrs import define, field
from contextlib import contextmanager
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import Callable

from ..store import repository
from ..store.orm import make_session_factory


@define
class UOWException(Exception):
    """Base Repo Exception."""

    msg: str


@define
class AlreadyExists(UOWException):
    """Already Exists Error."""

    pass


@define
class NotFound(UOWException):
    """Not Found Error."""

    pass


@define
class BaseUOW:
    """Base UOW."""


@define
class SqlUOW(BaseUOW):
    session: Session
    entity_repo: repository.SqlEntityRepo = field()
    domain_repo: repository.SqlDomainRepo = field()
    community_repo: repository.SqlCommunityRepo = field()
    membership_request_repo: repository.SqlMembershipRequestRepo = field()
    route_repo: repository.SqlRouteRepo = field()
    rule_repo: repository.SqlRuleRepo = field()
    admin_token_repo: repository.SqlAdminTokenRepo = field()

    @entity_repo.default
    def _entity_repo(self):
        return repository.SqlEntityRepo(self.session)

    @domain_repo.default
    def _domain_repo(self):
        return repository.SqlDomainRepo(self.session)

    @community_repo.default
    def _community_repo(self):
        return repository.SqlCommunityRepo(self.session)

    @membership_request_repo.default
    def _membership_request_repo(self):
        return repository.SqlMembershipRequestRepo(self.session)

    @route_repo.default
    def _route_repo(self):
        return repository.SqlRouteRepo(self.session)

    @rule_repo.default
    def _rule_repo(self):
        return repository.SqlRuleRepo(self.session)

    @admin_token_repo.default
    def _admin_token_repo(self):
        return repository.SqlAdminTokenRepo(self.session)


def make_sql_uow(engine: Engine) -> Callable[[], SqlUOW]:
    Session = make_session_factory(engine)

    @contextmanager
    def _fn():
        with Session() as session:
            yield SqlUOW(session)

            try:
                session.commit()
            except IntegrityError as e:
                session.rollback()
                if "unique" in str(e.orig).lower():
                    raise AlreadyExists(str(e))
            except repository.NotFound as e:
                session.rollback()
                raise NotFound(str(e))
            except (repository.BaseRepoException, Exception) as e:
                session.rollback()
                raise UOWException(str(e))

    return _fn
