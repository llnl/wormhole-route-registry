import pytest

from route_registry.clients.authorization import PikoAuthorizationClient
from route_registry.models import VerificationStatus
from route_registry.store.orm import make_engine, reset_db
from route_registry.service.uow import make_sql_uow


@pytest.fixture(scope="module")
def engine(base_config):
    return make_engine(base_config["DB"])


@pytest.fixture(autouse=True)
def clean_db(engine):
    reset_db(engine)


@pytest.fixture(scope="module")
def UOW(engine):
    return make_sql_uow(engine)


@pytest.fixture
def a_persisted_user(UOW, a_user):
    with UOW() as uow:
        uow.entity_repo.add(a_user)

    return a_user


@pytest.fixture
def a_persisted_group(UOW, a_group):
    with UOW() as uow:
        uow.entity_repo.add(a_group)

    return a_group


@pytest.fixture
def a_persisted_domain(UOW, a_domain):
    with UOW() as uow:
        uow.domain_repo.add(a_domain)

    return a_domain


@pytest.fixture
def a_persisted_route(UOW, a_route, a_domain):
    # NOTE: when we first register a route, we move the state to PENDING
    # rather than the default, UNVERIFIED, we'll mimic registration state
    a_route.verification_status = VerificationStatus.PENDING
    a_route.domain = a_domain
    with UOW() as uow:
        uow.route_repo.add(a_route)

    return a_route


@pytest.fixture
def a_persisted_rule(UOW, a_rule):
    with UOW() as uow:
        uow.rule_repo.add(a_rule)

    return a_rule


@pytest.fixture
def url_config(base_url):
    return {"wst": {"base_url": base_url}, "pds": {"base_url": base_url}}


@pytest.fixture
def authz_client(base_config):
    return PikoAuthorizationClient(config=base_config["URL"])
