import pytest

from tenacity import retry, wait_fixed
from threading import Thread
from unittest import mock
from werkzeug.serving import make_server as make_flask_server

from route_registry.config import settings
from route_registry.clients.authorization import PikoAuthorizationClient
from route_registry.clients.holepunch import HolePunchClient
from route_registry.celery import make_celery_app, TaskProxy
from route_registry.server import make_server
from route_registry.models import JWTConfig, VerificationStatus
from route_registry.store.orm import make_engine, reset_db
from route_registry.service.uow import make_sql_uow
from route_registry.utils import (
    generate_private_key,
    generate_public_key,
    convert_private_key_to_pem,
    convert_public_key_to_pem,
)
from urllib.parse import urlparse

from tests.helpers.fake_app import make_fake_app
from tests.helpers.fake_holepunch import make_fake_holepunch
from tests.helpers.fake_deps import FakeAuthenticatorFactory


@pytest.fixture(scope="session")
def a_dst_host():
    return "127.0.0.1"


@pytest.fixture(scope="session")
def a_dst_port():
    return 8001


@pytest.fixture(scope="session")
def a_dst_url(a_dst_host, a_dst_port):
    return f"http://{a_dst_host}:{a_dst_port}"


@pytest.fixture(scope="session")
def config(base_url, a_dst_url):
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)
    keys = {
        "1": {
            "key_type": "RSA",
            "public_pem": convert_public_key_to_pem(public_key).decode(),
            "private_pem": convert_private_key_to_pem(private_key).decode(),
        }
    }

    settings.SERVER.loop = "asyncio"
    settings.log_level = "debug"
    settings.AUTH.jwt.leeway = 1
    settings.AUTH.jwt.active_kid = "1"
    settings.TRACK.routes.check_interval = 1
    settings.TASKS.validate_route.celery.max_retries = 1
    settings.TASKS.validate_route.celery.retry_backoff = 1
    settings.URL.bind_subdomain = True
    settings.URL.tunnel.base_url = a_dst_url
    settings.URL.entry.base_url = base_url

    cfg = settings.to_dict()
    cfg["AUTH"]["jwt"]["keys"] = keys
    return cfg


@pytest.fixture(scope="session")
def bind_subdomain(config):
    return config["URL"]["bind_subdomain"]


@pytest.fixture(scope="session")
def an_entry_url(config):
    return config["URL"]["entry"]["base_url"]


@pytest.fixture(scope="session")
def a_token_service_url(config):
    return config["URL"]["token_service"]["base_url"]


@pytest.fixture(scope="session")
def a_tunnel_connect_url(config):
    return config["URL"]["tunnel"]["connect_url"]


@pytest.fixture(scope="session")
def jwks(config):
    return JWTConfig(config["AUTH"]["jwt"])


@pytest.fixture(scope="session")
def authz_client(config):
    return PikoAuthorizationClient(config=config["URL"])


@pytest.fixture(scope="session")
def engine(config):
    return make_engine(config["DB"])


@pytest.fixture(autouse=True)
def clean_db(engine):
    reset_db(engine)


@pytest.fixture(scope="session")
def UOW(engine):
    return make_sql_uow(engine)


@pytest.fixture(scope="session")
def registration_token():
    return "token_service_token"


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
def a_persisted_community(UOW, a_persisted_user, a_community):
    with UOW() as uow:
        a_community.entity = a_persisted_user
        uow.community_repo.add(a_community)

    return a_community


@pytest.fixture
def a_persisted_membership_request(
    UOW,
    make_membership_request,
    a_persisted_user,
    a_persisted_community,
    a_persisted_route,
):
    with UOW() as uow:
        request = make_membership_request(
            entity_id=a_persisted_user.id,
            community_id=a_persisted_community.id,
            route_id=a_persisted_route.id,
        )
        uow.membership_request_repo.add(request)

    return request


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
def a_persisted_rule(UOW, a_rule, a_persisted_domain):
    a_rule.route.domain = a_persisted_domain
    with UOW() as uow:
        uow.rule_repo.add(a_rule)

    return a_rule


@pytest.fixture(scope="session")
def celery_app(config):
    return make_celery_app(config)


@pytest.fixture(scope="session")
def task_proxy(celery_app):
    return TaskProxy(celery_app)


@pytest.fixture(scope="session")
def server_mock_target():
    return mock.MagicMock()


@pytest.fixture(scope="session")
def requests_mock_target():
    return mock.MagicMock()


@pytest.fixture(scope="session")
def extract_uid_mock_target():
    return mock.MagicMock()


@pytest.fixture(autouse=True)
def reset_server_mock_target(server_mock_target):
    # since server_mock_target lives for the session it should be reset after
    # every test to ensure no state carries over from test to test
    server_mock_target.reset_mock(return_value=True, side_effect=True)


@pytest.fixture(autouse=True)
def reset_requests_mock_target(requests_mock_target):
    requests_mock_target.reset_mock(return_value=True, side_effect=True)


@pytest.fixture(autouse=True)
def reset_extract_uid_mock_target(extract_uid_mock_target):
    extract_uid_mock_target.reset_mock(return_value=True, side_effect=True)


@pytest.fixture
def mock_oidc_call(a_persisted_user):
    with mock.patch("tests.helpers.fake_deps.oidc_call_target") as mock_call:
        mock_call.return_value = a_persisted_user
        yield mock_call


@pytest.fixture(scope="session")
def app_server(
    config, a_dst_host, a_dst_port, a_dst_url, server_mock_target, a_route_name
):
    app = make_fake_app(config["URL"], a_route_name)

    with mock.patch("tests.helpers.fake_app.fake_target", new=server_mock_target):
        server = make_flask_server(a_dst_host, a_dst_port, app, threaded=True)
        t = Thread(target=server.serve_forever)
        t.start()

        yield a_dst_url

        server.shutdown()
        t.join()


# Holepunch
@pytest.fixture(scope="session")
def holepunch_mock_target():
    return mock.MagicMock()


@pytest.fixture(autouse=True)
def reset_holepunch_mock_target(holepunch_mock_target):
    holepunch_mock_target.reset_mock(return_value=True, side_effect=True)


@pytest.fixture(scope="session")
def holepunch_server(config, holepunch_mock_target):
    holepunch_config = config["URL"]["holepunch"]
    base_url = holepunch_config["base_url"]
    holepunch = make_fake_holepunch(holepunch_config)
    url_parts = urlparse(base_url)
    host, port = url_parts.netloc.split(":")

    with mock.patch(
        "tests.helpers.fake_holepunch.fake_target", new=holepunch_mock_target
    ):
        server = make_flask_server(host, port, holepunch, threaded=True)
        t = Thread(target=server.serve_forever)
        t.start()

        yield base_url

        server.shutdown()
        t.join()


@pytest.fixture(scope="session")
def holepunch_client(config, holepunch_server):
    return HolePunchClient(config=config["URL"]["holepunch"])


@pytest.fixture(scope="session")
def task_queue(celery_app):
    worker = celery_app.Worker()

    t = Thread(target=worker.start)
    t.start()

    @retry(wait=wait_fixed(3))
    def wait_up():
        if not celery_app.control.ping():
            raise

    wait_up()
    yield
    celery_app.control.shutdown()
    t.join()


@pytest.fixture(scope="session")
async def server(
    UOW, config, task_proxy, a_dst_url, requests_mock_target, extract_uid_mock_target
):
    with (
        mock.patch("route_registry.dependencies.requests", new=requests_mock_target),
        mock.patch(
            "route_registry.dependencies.extract_uid", new=extract_uid_mock_target
        ),
        mock.patch(
            "route_registry.server.AuthenticatorFactory", new=FakeAuthenticatorFactory,
        ),
    ):
        server = make_server(UOW, config, task_proxy)

        t = Thread(target=server.run)
        t.start()

        @retry(wait=wait_fixed(3))
        def wait_up():
            if not server.started:
                raise

        wait_up()
        yield f"http://{server.config.host}:{server.config.port}"
        server.should_exit = True
        t.join()


@pytest.fixture(scope="session")
async def server_api(server):
    yield f"{server}/api"
