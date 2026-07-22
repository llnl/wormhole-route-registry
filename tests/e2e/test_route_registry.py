import pendulum
import pytest
import requests

from joserfc import jwt as jose_jwt
from tenacity import retry, stop_after_attempt, wait_fixed
from typing import Callable
from unittest import mock

from route_registry.models import Status, VerificationStatus, DomainType, AdminRole
from route_registry.services import create_piko_jwt
from route_registry.store.repository import NotFound
from route_registry.track import make_route_tracker

pytestmark = pytest.mark.e2e


def decode_route_jwt(token: str, jwt_config):
    decoded = jose_jwt.decode(
        token, jwt_config.jwks.key_map[jwt_config.active_kid].public_key
    )
    return decoded


# Admin token fixtures
@pytest.fixture
def a_persisted_admin_observer_token(UOW, make_admin_token):
    admin_token = make_admin_token(
        id="9942481e-6224-421b-8077-0a9ff9434db2",
        name="observer_token",
        role=AdminRole.OBSERVER,
    )
    with UOW() as uow:
        uow.admin_token_repo.add(admin_token)

    return admin_token


@pytest.fixture
def plain_observer_token():
    return "9942481e-6224-421b-8077-0a9ff9434db2.admintoken"


@pytest.fixture
def observer_auth_header(a_persisted_admin_observer_token, plain_observer_token):
    return {"X-Token": plain_observer_token}


@pytest.fixture
def a_persisted_admin_identity_token(UOW, make_admin_token):
    admin_token = make_admin_token(
        id="9942481e-6224-421b-8077-0a9ff9434db3",
        name="identity_token",
        role=AdminRole.IDENTITY,
    )
    with UOW() as uow:
        uow.admin_token_repo.add(admin_token)

    return admin_token


@pytest.fixture
def plain_identity_token():
    return "9942481e-6224-421b-8077-0a9ff9434db3.admintoken"


@pytest.fixture
def identity_auth_header(a_persisted_admin_identity_token, plain_identity_token):
    return {"X-Token": plain_identity_token}


@pytest.fixture
def a_persisted_admin_domain_token(UOW, make_admin_token):
    admin_token = make_admin_token(
        id="9942481e-6224-421b-8077-0a9ff9434db4",
        name="domain_token",
        role=AdminRole.DOMAIN,
    )
    with UOW() as uow:
        uow.admin_token_repo.add(admin_token)

    return admin_token


@pytest.fixture
def plain_domain_token():
    return "9942481e-6224-421b-8077-0a9ff9434db4.admintoken"


@pytest.fixture
def domain_auth_header(a_persisted_admin_domain_token, plain_domain_token):
    return {"X-Token": plain_domain_token}


@pytest.fixture
def a_persisted_admin_user(make_user, UOW):
    with UOW() as uow:
        user = make_user(uid="admin_user", is_admin=True)
        uow.entity_repo.add(user)

    return user


@pytest.fixture
def mock_oidc_admin(a_persisted_admin_user):
    with mock.patch("tests.helpers.fake_deps.oidc_call_target") as mock_call:
        mock_call.return_value = a_persisted_admin_user
        yield mock_call


def try_until_succeeds(
    call: Callable, attempts: int = 10, time_between_attempts: float = 0.2
):
    """Make function to retry until True."""

    @retry(stop=stop_after_attempt(attempts), wait=wait_fixed(time_between_attempts))
    def _to_try():
        call()

    _to_try()


async def test_register_and_validate(
    server_api,
    app_server,
    holepunch_server,
    task_queue,
    registration_token,
    an_entry_url,
    bind_subdomain,
    a_tunnel_connect_url,
    a_token_service_url,
    a_persisted_user,
    a_persisted_group,
    a_persisted_domain,
    a_route_name,
    make_authz,
    server_mock_target,
    holepunch_mock_target,
    requests_mock_target,
    extract_uid_mock_target,
    jwks,
    UOW,
):
    # Setup
    src_url = a_persisted_domain.create_src_url(
        a_route_name, user=a_persisted_user, bind_subdomain=bind_subdomain
    )
    headers = {"X-Token": registration_token}
    data = {"name": a_route_name}

    mock_resp = mock.MagicMock()
    mock_resp.json.return_value = {"jwt": "{}"}
    server_mock_target.return_value = make_authz()
    requests_mock_target.return_value = mock_resp
    extract_uid_mock_target.return_value = a_persisted_user.uid

    # Execute
    resp = requests.post(f"{server_api}/v2/route", headers=headers, json=data)

    # Verify
    # Initial state is correct
    with UOW() as uow:
        route = uow.route_repo.get_by_src(src_url)
        assert route
        assert route.status == Status.DOWN
        assert route.verification_status == VerificationStatus.VERIFIED

    data = resp.json()
    # Valid jwt
    encoded_jwt = data["tunnel"]["jwt"]
    claims = decode_route_jwt(encoded_jwt, jwks)
    jose_jwt.JWTClaimsRegistry(leeway=1).validate(claims.claims)

    # tunnel data
    assert data["tunnel"]["url"] == a_tunnel_connect_url
    assert data["tunnel"]["endpoint"] == route.id
    assert data["airlock"]["jwt_issuer_url"] == a_token_service_url

    # Route is up once validated
    def verify_setup():
        holepunch_mock_target.assert_called_once()
        with UOW() as uow:
            route = uow.route_repo.get_by_src(src_url)
            assert route
            assert route.status == Status.UP
            assert route.verification_status == VerificationStatus.VERIFIED
            assert route.last_contact > pendulum.now().subtract(seconds=30)

    try_until_succeeds(verify_setup)


async def test_register_and_validate_with_user_domain(
    server_api,
    app_server,
    holepunch_server,
    task_queue,
    registration_token,
    an_entry_url,
    bind_subdomain,
    a_persisted_user,
    a_persisted_group,
    a_route_name,
    make_authz,
    make_domain,
    server_mock_target,
    requests_mock_target,
    extract_uid_mock_target,
    jwks,
    UOW,
):
    # Setup
    with UOW() as uow:
        domain = make_domain(domain_type=DomainType.USER)
        uow.domain_repo.add(domain)

    src_url = domain.create_src_url(
        a_route_name, user=a_persisted_user, bind_subdomain=bind_subdomain
    )
    headers = {"X-Token": registration_token}
    data = {"name": a_route_name}

    mock_resp = mock.MagicMock()
    mock_resp.json.return_value = {"jwt": "{}"}
    server_mock_target.return_value = make_authz()
    requests_mock_target.return_value = mock_resp
    extract_uid_mock_target.return_value = a_persisted_user.uid

    # Execute
    requests.post(f"{server_api}/v2/route", headers=headers, json=data)

    with UOW() as uow:
        route = uow.route_repo.get_by_src(src_url)
        assert a_persisted_user.uid in route.src


async def test_register_and_validate_updates_existing_owned_route(
    server_api,
    app_server,
    holepunch_server,
    task_queue,
    registration_token,
    an_entry_url,
    bind_subdomain,
    a_persisted_user,
    a_persisted_group,
    a_persisted_domain,
    a_route_name,
    make_authz,
    server_mock_target,
    requests_mock_target,
    extract_uid_mock_target,
    UOW,
):
    # Setup
    src_url = a_persisted_domain.create_src_url(
        a_route_name, user=a_persisted_user, bind_subdomain=bind_subdomain
    )
    headers = {"X-Token": registration_token}
    data = {"name": a_route_name}

    mock_resp = mock.MagicMock()
    mock_resp.json.return_value = {"jwt": "{}"}
    server_mock_target.return_value = make_authz()
    requests_mock_target.return_value = mock_resp
    extract_uid_mock_target.return_value = a_persisted_user.uid

    requests.post(f"{server_api}/v2/route", headers=headers, json=data)

    # Initial state is correct
    with UOW() as uow:
        route = uow.route_repo.get_by_src(src_url)
        assert route
        assert route.status == Status.DOWN
        assert route.verification_status == VerificationStatus.VERIFIED

    # Route is up once validated
    def verify_setup():
        with UOW() as uow:
            route = uow.route_repo.get_by_src(src_url)
            assert route
            assert route.status == Status.UP
            assert route.verification_status == VerificationStatus.VERIFIED
            assert route.last_contact > pendulum.now().subtract(seconds=30)

    try_until_succeeds(verify_setup)

    # Execute second call
    resp = requests.post(f"{server_api}/v2/route", headers=headers, json=data)
    resp.raise_for_status()

    # Verify
    # Already UP and last_contact updated
    with UOW() as uow:
        new_route = uow.route_repo.get_by_src(src_url)
        assert new_route
        assert new_route.status == Status.UP
        assert new_route.verification_status == VerificationStatus.VERIFIED
        assert new_route.id == route.id
        assert new_route.last_contact > route.last_contact


async def test_register_and_validate_can_bind_to_an_existing_community(
    server_api,
    app_server,
    holepunch_server,
    task_queue,
    registration_token,
    an_entry_url,
    bind_subdomain,
    a_persisted_user,
    a_persisted_group,
    a_persisted_domain,
    a_persisted_community,
    a_community_name,
    a_route_name,
    make_authz,
    server_mock_target,
    requests_mock_target,
    extract_uid_mock_target,
    UOW,
    request,
):
    # Setup
    src_url = a_persisted_domain.create_src_url(
        a_route_name, user=a_persisted_user, bind_subdomain=bind_subdomain
    )
    headers = {"X-Token": registration_token}
    data = {"name": a_route_name, "community_name": a_community_name}

    mock_resp = mock.MagicMock()
    mock_resp.json.return_value = {"jwt": "{}"}
    server_mock_target.return_value = make_authz()
    requests_mock_target.return_value = mock_resp
    extract_uid_mock_target.return_value = a_persisted_user.uid

    requests.post(f"{server_api}/v2/route", headers=headers, json=data)

    # Initial state is correct
    with UOW() as uow:
        route = uow.route_repo.get_by_src(src_url)
        assert route
        assert route.status == Status.DOWN
        assert route.verification_status == VerificationStatus.VERIFIED

    # Route is up and is part of a community
    def verify():
        with UOW() as uow:
            route = uow.route_repo.get_by_src(src_url)
            assert route
            assert route.status == Status.UP
            assert route.verification_status == VerificationStatus.VERIFIED
            assert route.community
            assert route.community.name == a_community_name

    try_until_succeeds(verify)


async def test_register_and_validate_fails_if_user_does_not_own_route(
    server_api,
    registration_token,
    an_entry_url,
    bind_subdomain,
    a_persisted_user,
    a_persisted_group,
    a_persisted_domain,
    a_route_name,
    make_user,
    make_route,
    requests_mock_target,
    extract_uid_mock_target,
    UOW,
):
    # Setup
    src_url = a_persisted_domain.create_src_url(
        a_route_name, user=a_persisted_user, bind_subdomain=bind_subdomain
    )
    headers = {"X-Token": registration_token}
    data = {"name": a_route_name, "domain_name": a_persisted_domain.name}

    mock_resp = mock.MagicMock()
    mock_resp.json.return_value = {"jwt": "{}"}
    requests_mock_target.return_value = mock_resp
    extract_uid_mock_target.return_value = a_persisted_user.uid

    # Create a route of the same name and src_url with a different user
    with UOW() as uow:
        user = make_user(
            uid=f"{a_persisted_user.uid}-different",
            duid=f"{a_persisted_user.duid}-different",
        )
        route = make_route(name=a_route_name, src=src_url, domain=a_persisted_domain)
        route.entities.append(user)
        uow.route_repo.add(route)

    # Execute
    resp = requests.post(f"{server_api}/v2/route", headers=headers, json=data)

    # Verify
    assert resp.status_code == 403
    assert "taken" in resp.json()["detail"]


async def test_register_and_validate_fails_invalid_token(
    server_api,
    a_route_name,
    registration_token,
    requests_mock_target,
):
    # Setup
    headers = {"X-Token": registration_token}
    data = {"name": a_route_name}

    mock_resp = mock.MagicMock()
    mock_resp.status_code = 401
    requests_mock_target.get.return_value = mock_resp

    # Execute
    resp = requests.post(f"{server_api}/v2/route", headers=headers, json=data)
    requests_mock_target.reset_mock()

    # Verify
    assert resp.status_code == 401
    assert "Invalid token" in resp.json()["detail"]


async def test_register_and_validate_fails_user_not_found(
    server_api,
    a_route_name,
    registration_token,
    requests_mock_target,
    extract_uid_mock_target,
):
    # Setup
    headers = {"X-Token": registration_token}
    data = {"name": a_route_name}

    mock_resp = mock.MagicMock()
    mock_resp.json.return_value = {"jwt": "{}"}
    requests_mock_target.return_value = mock_resp
    extract_uid_mock_target.return_value = "non-existent-user"

    # Execute
    resp = requests.post(f"{server_api}/v2/route", headers=headers, json=data)

    # Verify
    assert resp.status_code == 401


async def test_rotate_jwt(
    server_api,
    task_queue,
    make_route,
    a_domain,
    jwks,
    UOW,
):
    # Setup
    route = make_route(
        verification_status=VerificationStatus.VERIFIED,
        status=Status.UP,
        domain=a_domain,
    )
    with UOW() as uow:
        uow.route_repo.add(route)

    old_jwt = create_piko_jwt(route, jwks, 300)
    old_claims = decode_route_jwt(old_jwt, jwks)
    headers = {"X-JWT": old_jwt}

    # Execute
    resp = requests.post(f"{server_api}/latest/jwt", headers=headers)

    # Verify
    new_jwt = resp.json()["jwt"]
    assert new_jwt
    new_claims = decode_route_jwt(new_jwt, jwks)
    jose_jwt.JWTClaimsRegistry(leeway=1).validate(old_claims.claims)
    jose_jwt.JWTClaimsRegistry(leeway=1).validate(new_claims.claims)
    assert pendulum.from_timestamp(new_claims.claims["exp"]) > pendulum.from_timestamp(
        old_claims.claims["exp"]
    )


async def test_rotate_jwt_rechecks_downed_route(
    server_api,
    app_server,
    holepunch_server,
    task_queue,
    a_persisted_user,
    a_persisted_group,
    a_persisted_domain,
    a_route_name,
    bind_subdomain,
    registration_token,
    make_authz,
    server_mock_target,
    extract_uid_mock_target,
    make_route,
    jwks,
    UOW,
):
    # TODO: Remove this setup once token validation is removed
    # Setup
    src_url = a_persisted_domain.create_src_url(
        a_route_name, user=a_persisted_user, bind_subdomain=bind_subdomain
    )
    headers = {"X-Token": registration_token}
    data = {"name": a_route_name, "dst": a_persisted_domain.name}
    extract_uid_mock_target.return_value = a_persisted_user.uid

    requests.post(f"{server_api}/v2/route", json=data, headers=headers)

    server_mock_target.return_value = make_authz()

    # Route is able to be validated once authz file contains token
    def verify_setup():
        with UOW() as uow:
            route = uow.route_repo.get_by_src(src_url)
            assert route
            assert route.status == Status.UP
            assert route.verification_status == VerificationStatus.VERIFIED
            assert route.last_contact > pendulum.now().subtract(seconds=30)

    try_until_succeeds(verify_setup)

    # Simulate the route going down
    with UOW() as uow:
        route = uow.route_repo.get_by_src(src_url)
        route.status = Status.DOWN

    jwt = create_piko_jwt(route, jwks, 300)
    headers = {"X-JWT": jwt}

    # Execute
    requests.post(f"{server_api}/latest/jwt", headers=headers)

    # Verify the validate job triggered and brought the route UP

    def verify_setup():
        with UOW() as uow:
            route = uow.route_repo.get_by_src(src_url)
        assert route
        assert route.status == Status.UP
        assert route.verification_status == VerificationStatus.VERIFIED
        assert route.last_contact > pendulum.now().subtract(seconds=30)

    try_until_succeeds(verify_setup)


async def test_rotate_jwt_fails_expired_past_leeway(
    server_api,
    task_queue,
    make_route,
    a_domain,
    jwks,
    UOW,
):
    # Setup
    route = make_route(
        verification_status=VerificationStatus.VERIFIED,
        status=Status.UP,
        domain=a_domain,
    )
    with UOW() as uow:
        uow.route_repo.add(route)

    old_jwt = create_piko_jwt(route, jwks, -2)
    headers = {"X-JWT": old_jwt}

    # Execute
    resp = requests.post(f"{server_api}/latest/jwt", headers=headers)

    # Verify
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"]


async def test_rotate_jwt_fails_unknown_route(
    server_api,
    task_queue,
    make_route,
    a_domain,
    jwks,
    UOW,
):
    # Setup
    route = make_route(id="invalid", domain=a_domain)
    old_jwt = create_piko_jwt(route, jwks, 300)
    headers = {"X-JWT": old_jwt}

    # Execute
    resp = requests.post(f"{server_api}/latest/jwt", headers=headers)

    # Verify
    assert resp.status_code == 401


async def test_rotate_jwt_fails_unverified_route(
    server_api,
    task_queue,
    make_route,
    a_domain,
    jwks,
    UOW,
):
    # Setup
    route = make_route(
        verification_status=VerificationStatus.UNVERIFIED, domain=a_domain
    )
    with UOW() as uow:
        uow.route_repo.add(route)

    old_jwt = create_piko_jwt(route, jwks, 300)
    headers = {"X-JWT": old_jwt}

    # Execute
    resp = requests.post(f"{server_api}/latest/jwt", headers=headers)

    # Verify
    assert resp.status_code == 401
    assert "unverified" in resp.json()["detail"]


@pytest.mark.parametrize("verification_status", [vs for vs in VerificationStatus])
@pytest.mark.parametrize("status", [s for s in Status])
async def test_tracker(
    verification_status,
    status,
    server_api,
    app_server,
    holepunch_client,
    task_queue,
    a_persisted_user,
    a_persisted_group,
    authorization_schema,
    server_mock_target,
    holepunch_mock_target,
    a_route,
    a_domain,
    UOW,
    request,
    authz_client,
    make_authz,
):
    # Setup
    a_route.dst = app_server
    a_route.verification_status = verification_status
    a_route.status = status
    a_route.domain = a_domain
    a_route.last_contact = pendulum.now()

    def will_track() -> bool:
        return verification_status is VerificationStatus.VERIFIED and (
            status is Status.UP or status is Status.DOWN
        )

    if will_track():
        server_mock_target.return_value = make_authz()

    with UOW() as uow:
        uow.route_repo.add(a_route)

    # Execute
    tracker = make_route_tracker(
        UOW,
        authorization_schema,
        authz_client,
        holepunch_client,
        check_interval=0.2,
        stale_duration=1,
    )
    tracker.start()

    # Verify
    try:

        def verify():
            if will_track():
                holepunch_mock_target.assert_called_once()
                with UOW() as uow:
                    route = uow.route_repo.get_by_dst(a_route.dst)
                    assert route
                    assert route.verification_status is VerificationStatus.VERIFIED
                    assert route.status is Status.UP
            else:
                server_mock_target.assert_not_called()

        try_until_succeeds(verify)
    finally:
        tracker.stop()


async def test_tracker_marks_route_with_invalid_authz_misconfigured(
    server_api,
    app_server,
    holepunch_client,
    task_queue,
    authorization_schema,
    server_mock_target,
    a_route,
    a_domain,
    UOW,
    request,
    authz_client,
):
    # Setup
    # Route begins verified and up
    a_route.dst = app_server
    a_route.verification_status = VerificationStatus.VERIFIED
    a_route.status = Status.UP
    a_route.domain = a_domain
    a_route.last_contact = pendulum.now()
    invalid_authz = {}

    server_mock_target.return_value = invalid_authz

    with UOW() as uow:
        uow.route_repo.add(a_route)

    # Execute
    tracker = make_route_tracker(
        UOW,
        authorization_schema,
        authz_client,
        holepunch_client,
        check_interval=0.2,
        stale_duration=1,
    )
    tracker.start()

    # Verify
    # Route is verified but misconfigured after the tracker runs
    try:

        def verify():
            with UOW() as uow:
                route = uow.route_repo.get_by_dst(a_route.dst)
                assert route
                assert route.verification_status is VerificationStatus.VERIFIED
                assert route.status is Status.MISCONFIGURED

        try_until_succeeds(verify)
    finally:
        tracker.stop()


async def test_tracker_marks_route_with_missing_entities(
    server_api,
    app_server,
    holepunch_client,
    task_queue,
    authorization_schema,
    server_mock_target,
    a_route,
    a_domain,
    UOW,
    request,
    authz_client,
    make_authz,
):
    # Setup
    # Route begins verified and up
    a_route.dst = app_server
    a_route.verification_status = VerificationStatus.VERIFIED
    a_route.status = Status.UP
    a_route.domain = a_domain
    a_route.last_contact = pendulum.now()
    missing_user_authz = make_authz()
    missing_user_authz["allowed"]["users"].append("nonexistent")

    server_mock_target.return_value = missing_user_authz

    with UOW() as uow:
        uow.route_repo.add(a_route)

    # Execute
    tracker = make_route_tracker(
        UOW,
        authorization_schema,
        authz_client,
        holepunch_client,
        check_interval=0.2,
        stale_duration=1,
    )
    tracker.start()

    # Verify
    # Route is verified but misconfigured after the tracker runs
    try:

        def verify():
            with UOW() as uow:
                route = uow.route_repo.get_by_dst(a_route.dst)
                assert route
                assert route.verification_status is VerificationStatus.VERIFIED
                assert route.status is Status.MISSING_ENTITY

        try_until_succeeds(verify)
    finally:
        tracker.stop()


async def test_tracker_marks_route_with_any_other_errors_as_server_error(
    server_api,
    app_server,
    holepunch_client,
    task_queue,
    a_dst_host,
    a_dst_port,
    authorization_schema,
    server_mock_target,
    a_route,
    a_domain,
    UOW,
    request,
    authz_client,
    make_authz,
):
    # Setup
    # Route begins verified and up
    a_route.dst = app_server
    a_route.verification_status = VerificationStatus.VERIFIED
    a_route.status = Status.UP
    a_route.domain = a_domain
    a_route.last_contact = pendulum.now()

    server_mock_target.side_effect = ValueError()

    with UOW() as uow:
        uow.route_repo.add(a_route)

    # Execute
    tracker = make_route_tracker(
        UOW,
        authorization_schema,
        authz_client,
        holepunch_client,
        check_interval=0.2,
        stale_duration=1,
    )
    tracker.start()

    # Verify
    # Route is verified but misconfigured after the tracker runs
    try:

        def verify():
            with UOW() as uow:
                route = uow.route_repo.get_by_dst(a_route.dst)
                assert route
                assert route.verification_status is VerificationStatus.VERIFIED
                assert route.status is Status.SERVER_ERROR

        try_until_succeeds(verify)
    finally:
        tracker.stop()


async def test_tracker_unverifies_route(
    server_api,
    app_server,
    holepunch_client,
    task_queue,
    authorization_schema,
    a_route,
    a_domain,
    UOW,
    request,
    authz_client,
):
    # Setup
    # Route begins verified and up
    a_route.dst = "http://localhost:1453"
    a_route.verification_status = VerificationStatus.VERIFIED
    a_route.status = Status.UP
    a_route.domain = a_domain
    a_route.last_contact = pendulum.now().subtract(days=5)

    with UOW() as uow:
        uow.route_repo.add(a_route)

    # Execute
    tracker = make_route_tracker(
        UOW,
        authorization_schema,
        authz_client,
        holepunch_client,
        check_interval=0.2,
        stale_duration=1,
    )
    tracker.start()

    # Verify
    # Route is down and unverified after the tracker runs
    try:

        def verify_unverified():
            with UOW() as uow:
                route = uow.route_repo.get_by_dst(a_route.dst)
                assert route
                assert route.status == Status.DOWN
                assert route.verification_status == VerificationStatus.UNVERIFIED

        try_until_succeeds(verify_unverified)
    finally:
        tracker.stop()


async def test_list_available(
    server_api,
    app_server,
    holepunch_server,
    task_queue,
    a_dst_url,
    a_persisted_user,
    a_persisted_group,
    a_persisted_domain,
    a_route_name,
    bind_subdomain,
    registration_token,
    make_authz,
    server_mock_target,
    extract_uid_mock_target,
    UOW,
):
    # Setup
    src_url = a_persisted_domain.create_src_url(
        a_route_name, user=a_persisted_user, bind_subdomain=bind_subdomain
    )
    headers = {"X-Token": registration_token}
    data = {"name": a_route_name, "domain_name": a_persisted_domain.name}
    extract_uid_mock_target.return_value = a_persisted_user.uid

    # Execute
    requests.post(f"{server_api}/v2/route", json=data, headers=headers)

    # Set token in our authorization.json file
    server_mock_target.return_value = make_authz()

    # Route is up

    def verify_setup():
        with UOW() as uow:
            route = uow.route_repo.get_by_src(src_url)
            assert route
            assert route.status == Status.UP
            assert route.verification_status == VerificationStatus.VERIFIED

    try_until_succeeds(verify_setup)

    # Execute
    routes = requests.get(f"{server_api}/latest/route").json()

    # Verify
    route = routes[0]
    assert route
    assert route["src"] == src_url
    assert route["rules"]["allowed"]["users"]
    assert route["rules"]["allowed"]["groups"]
    assert a_persisted_user.uid in route["rules"]["allowed"]["users"]
    assert a_persisted_group.name in route["rules"]["allowed"]["groups"]


@pytest.mark.parametrize("lookup_id", ["id", "name"])
async def test_get_community(
    UOW, lookup_id, server_api, mock_oidc_call, a_persisted_community
):
    # Setup
    _id = getattr(a_persisted_community, lookup_id)

    # Execute
    resp = requests.get(f"{server_api}/latest/community/{_id}")

    # Verify
    community = resp.json()
    assert community
    assert community["id"] == a_persisted_community.id
    assert community["name"] == a_persisted_community.name


async def test_list_community(UOW, server_api, mock_oidc_call, a_persisted_community):
    # Execute
    resp = requests.get(f"{server_api}/latest/community")

    # Verify
    communities = resp.json()
    assert communities

    community = communities[0]
    assert community["id"] == a_persisted_community.id
    assert community["name"] == a_persisted_community.name


async def test_add_route_to_community(
    UOW,
    server_api,
    mock_oidc_call,
    a_persisted_user,
    a_persisted_community,
    a_persisted_route,
):
    # Setup
    with UOW() as uow:
        user = uow.entity_repo.get(a_persisted_user.id)
        route = uow.route_repo.get(a_persisted_route.id)
        user.routes.append(route)

    # Execute
    resp = requests.put(
        f"{server_api}/latest/community/{a_persisted_community.id}/route/{a_persisted_route.id}"
    )

    # Verify
    assert resp.status_code == 204
    with UOW() as uow:
        community = uow.community_repo.get(a_persisted_community.id)
        assert any(a_persisted_route.id == r.id for r in community.routes)


@pytest.mark.parametrize("request_exists", [False, True])
async def test_add_route_to_community_of_another_user(
    UOW,
    server_api,
    mock_oidc_call,
    request_exists,
    a_persisted_user,
    a_persisted_community,
    a_persisted_route,
    request,
):
    # Setup
    if request_exists:
        request.getfixturevalue("a_persisted_membership_request")

    # Execute
    resp = requests.put(
        f"{server_api}/latest/community/{a_persisted_community.id}/route/{a_persisted_route.id}"
    )

    # Verify
    membership_request = resp.json()
    assert membership_request["community_id"] == a_persisted_community.id
    assert membership_request["route_id"] == a_persisted_route.id
    assert membership_request["status"] == "PENDING"


async def test_remove_route_from_community(
    UOW,
    server_api,
    mock_oidc_call,
    a_persisted_user,
    a_persisted_community,
    a_persisted_route,
):
    # Setup
    with UOW() as uow:
        user = uow.entity_repo.get(a_persisted_user.id)
        route = uow.route_repo.get(a_persisted_route.id)
        community = uow.community_repo.get(a_persisted_community.id)
        user.routes.append(route)
        community.routes.append(route)

    # Ensure the route belongs to the community
    with UOW() as uow:
        route = uow.route_repo.get(a_persisted_route.id)
        assert route.community.id == a_persisted_community.id

    # Execute
    resp = requests.delete(
        f"{server_api}/latest/community/{a_persisted_community.id}/route/{a_persisted_route.id}"
    )

    # Verify
    assert resp.status_code == 204
    with UOW() as uow:
        community = uow.community_repo.get(a_persisted_community.id)
        assert not any(a_persisted_route.id == r.id for r in community.routes)


@pytest.mark.parametrize("lookup_id", ["id", "name"])
async def test_remove_community(
    UOW, server_api, lookup_id, mock_oidc_call, a_persisted_community
):
    # Setup
    _id = getattr(a_persisted_community, lookup_id)

    # Execute
    resp = requests.delete(f"{server_api}/latest/community/{_id}")

    # Verify
    assert resp.status_code == 204


async def test_add_domain(UOW, domain_auth_header, server_api):
    # Setup
    name = "foo"
    value = "foo.example.com"
    data = {"name": name, "value": value}

    # Execute
    resp = requests.post(
        f"{server_api}/latest/admin/domain", headers=domain_auth_header, json=data
    )
    domain_data = resp.json()

    # Verify
    with UOW() as uow:
        domain = uow.domain_repo.get_by_name(name)
        assert domain
        assert domain_data["name"] == domain.name
        assert domain_data["value"] == domain.value


@pytest.mark.parametrize("verified", [None] + list(VerificationStatus))
@pytest.mark.parametrize("status", [None] + list(Status))
async def test_list_routes(
    verified, status, UOW, a_domain, make_route, observer_auth_header, server_api
):
    # Setup
    params = {
        "verification_status": verified,
        "status": status,
    }
    with UOW() as uow:
        route = make_route(**{k: v for k, v in params.items() if v is not None})
        route.domain = a_domain
        uow.route_repo.add(route)

    # Execute
    resp = requests.get(
        f"{server_api}/latest/admin/route", headers=observer_auth_header, params=params
    )

    # Verify
    route_data = resp.json()[0]
    assert route_data["id"] == route.id


async def test_list_active_routes(
    UOW, a_domain, make_route, observer_auth_header, server_api
):
    # Setup
    active_route = None

    with UOW() as uow:
        for vs in list(VerificationStatus):
            for s in list(Status):
                route = make_route(src=f"{vs}-{s}", verification_status=vs, status=s)
                route.domain = a_domain
                uow.route_repo.add(route)
                if vs is VerificationStatus.VERIFIED and s is Status.UP:
                    active_route = route

    # Execute
    resp = requests.get(
        f"{server_api}/latest/admin/route/active", headers=observer_auth_header
    )

    # Verify
    routes_data = resp.json()
    assert len(routes_data) == 1

    route_data = routes_data[0]
    assert route_data["id"] == active_route.id


async def test_set_default_domain(
    UOW, domain_auth_header, server_api, make_domain, a_persisted_domain
):
    # Setup
    new_domain_name = "new_default"
    new_domain_url = "new-default.example.com"
    with UOW() as uow:
        new_domain = make_domain(
            name=new_domain_name, value=new_domain_url, default=False
        )
        uow.domain_repo.add(new_domain)
        assert not new_domain.default
        assert a_persisted_domain.default

    # Execute
    requests.put(
        f"{server_api}/latest/admin/domain/default/{new_domain.id}",
        headers=domain_auth_header,
    )

    # Verify
    with UOW() as uow:
        old_domain = uow.domain_repo.get(a_persisted_domain.id)
        new_domain = uow.domain_repo.get(new_domain.id)
        assert new_domain.default
        assert not old_domain.default


async def test_remove_domain(UOW, domain_auth_header, server_api, a_persisted_domain):
    # Setup / Execute
    requests.delete(
        f"{server_api}/latest/admin/domain/{a_persisted_domain.id}",
        headers=domain_auth_header,
    )

    # Verify
    with UOW() as uow:
        assert not uow.domain_repo.get(a_persisted_domain.id)


async def test_list_domains(UOW, domain_auth_header, server_api, a_persisted_domain):
    # Setup / Execute
    resp = requests.get(f"{server_api}/latest/admin/domain", headers=domain_auth_header)

    # Verify
    assert next(a_persisted_domain.id == domain["id"] for domain in resp.json())


async def test_add_user(UOW, identity_auth_header, server_api):
    # Setup
    uid = "foo"
    data = {"uid": uid}

    # Execute
    resp = requests.post(
        f"{server_api}/latest/admin/users", headers=identity_auth_header, json=data
    )
    user_data = resp.json()

    # Verify
    with UOW() as uow:
        user = uow.entity_repo.get_user(uid)
        assert user
        assert user_data["uid"] == user.uid


async def test_remove_user(UOW, identity_auth_header, server_api, a_persisted_user):
    # Setup / Execute
    requests.delete(
        f"{server_api}/latest/admin/users/{a_persisted_user.uid}",
        headers=identity_auth_header,
    )

    # Verify
    with UOW() as uow:
        with pytest.raises(NotFound):
            uow.entity_repo.get_user(a_persisted_user.uid)


async def test_list_users(UOW, identity_auth_header, server_api, a_persisted_user):
    # Setup / Execute
    resp = requests.get(
        f"{server_api}/latest/admin/users", headers=identity_auth_header
    )

    # Verify
    users = resp.json()
    assert users
    assert users[0]["uid"] == a_persisted_user.uid


async def test_add_group(UOW, identity_auth_header, server_api):
    # Setup
    name = "foo"
    data = {"name": name}

    # Execute
    resp = requests.post(
        f"{server_api}/latest/admin/groups", headers=identity_auth_header, json=data
    )
    group_data = resp.json()

    # Verify
    with UOW() as uow:
        group = uow.entity_repo.get_group(name)
        assert group
        assert group_data["name"] == group.name


async def test_remove_group(UOW, identity_auth_header, server_api, a_persisted_group):
    # Setup / Execute
    requests.delete(
        f"{server_api}/latest/admin/groups/{a_persisted_group.name}",
        headers=identity_auth_header,
    )

    # Verify
    with UOW() as uow:
        with pytest.raises(NotFound):
            uow.entity_repo.get_group(a_persisted_group.name)


async def test_list_groups(UOW, identity_auth_header, server_api, a_persisted_group):
    # Setup / Execute
    resp = requests.get(
        f"{server_api}/latest/admin/groups", headers=identity_auth_header
    )

    # Verify
    groups = resp.json()
    assert groups
    assert groups[0]["name"] == a_persisted_group.name


# Admin Token Tests
async def test_create_admin_token(server_api, mock_oidc_admin, UOW):
    # Setup
    admin_token_data = {"name": "admin-token-1", "role": "ANY"}

    # Execute
    resp = requests.post(f"{server_api}/latest/admin/token", json=admin_token_data)

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 201
    plain_admin_token = resp.json()
    admin_id, admin_plain = plain_admin_token.split(".")
    with UOW() as uow:
        stored = uow.admin_token_repo.get(admin_id)
    assert stored and stored.name == admin_token_data["name"]
    assert stored.role == AdminRole.ANY


async def test_create_admin_token_fails_when_unprivileged_user(
    server_api, mock_oidc_call, UOW
):
    # Setup
    admin_token_data = {"name": "admin-token-1", "role": "ANY"}

    # Execute
    resp = requests.post(f"{server_api}/latest/admin/token", json=admin_token_data)

    # Verify
    assert resp.status_code == 403

    with UOW() as uow:
        assert not uow.admin_token_repo.list()


async def test_create_admin_token_fails_when_duplicate(
    server_api, mock_oidc_admin, a_persisted_admin_identity_token, UOW
):
    # Setup
    admin_token_data = {
        "name": a_persisted_admin_identity_token.name,
        "role": "IDENTITY",
    }

    # Execute
    resp = requests.post(f"{server_api}/latest/admin/token", json=admin_token_data)

    # Verify
    assert resp.status_code == 409


async def test_list_admin_tokens(
    server_api,
    mock_oidc_admin,
    UOW,
    a_persisted_admin_identity_token,
):
    # Execute
    resp = requests.get(f"{server_api}/latest/admin/token")

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 200
    tokens = resp.json()
    assert isinstance(tokens, list)
    assert any(t.get("name") == a_persisted_admin_identity_token.name for t in tokens)


async def test_delete_admin_token_by_value(server_api, mock_oidc_admin, UOW):
    # Setup
    admin_token_data = {"name": "admin-token-to-delete", "role": "ANY"}
    plain_admin_token = requests.post(
        f"{server_api}/latest/admin/token", json=admin_token_data
    ).json()

    # Execute
    resp = requests.delete(f"{server_api}/latest/admin/token/{plain_admin_token}")

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 204
    admin_id = plain_admin_token.split(".")[0]
    with UOW() as uow:
        assert not uow.admin_token_repo.get(admin_id)


async def test_delete_admin_token_fails_when_not_found(
    server_api, mock_oidc_admin, UOW
):
    # Setup
    non_existent_token = "nonexistent-id.faketoken"

    # Execute
    resp = requests.delete(f"{server_api}/latest/admin/token/{non_existent_token}")

    # Verify
    assert resp.status_code == 404


async def test_delete_admin_token_fails_with_invalid_format(
    server_api, mock_oidc_admin, UOW
):
    # Setup
    invalid_token = "invalidformatnoperiod"

    # Execute
    resp = requests.delete(f"{server_api}/latest/admin/token/{invalid_token}")

    # Verify
    assert resp.status_code == 400
