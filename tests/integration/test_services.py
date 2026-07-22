import pendulum
import pytest
from joserfc import jwt
from unittest import mock
from route_registry.services import (
    list_available_routes,
    validate_route,
    store_rules,
    check_routes,
    create_piko_jwt,
)
from route_registry.models import (
    VerificationStatus,
    Status,
    Policy,
    Authorization,
    JWTConfig,
)
from route_registry.store.repository import MissingEntities
from route_registry.utils import (
    generate_private_key,
    generate_public_key,
    convert_private_key_to_pem,
    convert_public_key_to_pem,
)


@pytest.fixture
def jwks():
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)
    return JWTConfig(
        {
            "alg": "RS256",
            "lifespan": 300,
            "active_kid": "1",
            "keys": {
                "1": {
                    "key_type": "RSA",
                    "public_pem": convert_public_key_to_pem(public_key).decode(),
                    "private_pem": convert_private_key_to_pem(private_key).decode(),
                }
            },
        }
    )


def test_store_rules_repeated_calls(
    UOW,
    a_persisted_user,
    a_persisted_group,
    a_persisted_route,
    a_persisted_rule,
    make_authz,
):
    # Setup
    authz = Authorization(make_authz())

    # Execute
    with UOW() as uow:
        route = uow.route_repo.get(a_persisted_route.id)
        store_rules(uow, route, authz)

    # Verify
    with UOW() as uow:
        route = uow.route_repo.get(a_persisted_route.id)
        store_rules(uow, route, authz)


def test_store_rules_existing_remain_on_error(
    UOW,
    a_persisted_user,
    a_persisted_group,
    a_persisted_route,
    a_persisted_rule,
    make_authz,
):
    # Setup
    authz = Authorization(make_authz())

    # Execute
    try:
        with UOW() as uow:
            route = uow.route_repo.get(a_persisted_route.id)
            store_rules(uow, route, authz)
            raise Exception()
    except Exception:
        with UOW() as uow:
            # Verify
            existing_rule = uow.rule_repo.get(a_persisted_route.id, a_persisted_user.id)
            assert existing_rule.route.id == a_persisted_rule.route.id
            assert existing_rule.entity.id == a_persisted_rule.entity.id
            assert existing_rule.policy is a_persisted_rule.policy


def test_list_available_routes(UOW, make_route, make_domain):
    # Setup
    domain = make_domain()
    routes = [make_route(src=f"src{i}", dst=f"dst{i}", domain=domain) for i in range(3)]
    verified_route = routes[0]
    verified_route.status = Status.UP
    verified_route.verification_status = VerificationStatus.VERIFIED

    with UOW() as uow:
        uow.route_repo.add(routes)

    # Execute
    results = list_available_routes(UOW)

    # Verify
    assert len(results) == 1
    assert results[0].id == verified_route.id
    assert all(
        r.status == Status.UP and r.verification_status == VerificationStatus.VERIFIED
        for r in results
    )


@pytest.mark.parametrize("user_policy", ["disallowed", "allowed"])
@pytest.mark.parametrize("group_policy", ["disallowed", "allowed"])
def test_validate_route(
    UOW,
    authorization_schema,
    authorization_path,
    url_config,
    user_policy,
    group_policy,
    a_plaintext_token,
    a_persisted_user,
    a_persisted_group,
    a_persisted_route,
):
    # Setup/Execute
    authz = {
        "version": "1",
        "token": a_plaintext_token,
        "allowed": {},
        "disallowed": {},
    }
    authz[user_policy]["users"] = [a_persisted_user.uid]
    authz[group_policy]["groups"] = [a_persisted_group.name]
    expected_user_policy = Policy.ALLOW if user_policy == "allowed" else Policy.DENY
    expected_group_policy = Policy.ALLOW if group_policy == "allowed" else Policy.DENY

    with mock.patch("requests.get") as mock_get:
        mock_get.return_value.json.return_value = authz
        validate_route(
            UOW, a_persisted_route.id, authorization_path, authorization_schema
        )

    # Verify
    with UOW() as uow:
        route = uow.route_repo.get(a_persisted_route.id)
        assert route.verification_status == VerificationStatus.VERIFIED

        user_rule = uow.rule_repo.get(route_id=route.id, entity_id=a_persisted_user.id)
        group_rule = uow.rule_repo.get(
            route_id=route.id, entity_id=a_persisted_group.id
        )
        assert user_rule.policy == expected_user_policy
        assert group_rule.policy == expected_group_policy


# NOTE: the validate service does nothing to change the VerificationStatus of
# the route. Transitioning to UNVERIFIED is handled by the task failure callback
@pytest.mark.parametrize("persisted_entity", ["a_persisted_user", "a_persisted_group"])
def test_validate_route_fails_missing_entities(
    UOW,
    authorization_schema,
    authorization_path,
    an_authz_with_token,
    persisted_entity,
    a_persisted_route,
    request,
):
    # Setup/Execute

    # Request only 1 entity of 2 that are in the authz file
    request.getfixturevalue(persisted_entity)

    with mock.patch("requests.get") as mock_get:
        mock_get.return_value.json.return_value = an_authz_with_token
        with pytest.raises(MissingEntities):
            validate_route(
                UOW, a_persisted_route.id, authorization_path, authorization_schema
            )

    # Verify
    with UOW() as uow:
        route = uow.route_repo.get(a_persisted_route.id)
        assert route.verification_status == VerificationStatus.PENDING


def test_validate_route_bad_token(
    UOW, authorization_schema, authorization_path, make_authz, a_persisted_route
):
    # Setup/Execute
    with mock.patch("requests.get") as mock_get:
        mock_get.return_value.json.return_value = make_authz(token="wrong")
        with pytest.raises(ValueError):
            validate_route(
                UOW, a_persisted_route.id, authorization_path, authorization_schema
            )

    # Verify
    with UOW() as uow:
        updated = uow.route_repo.get(a_persisted_route.id)
        assert updated.verification_status == VerificationStatus.PENDING


def test_validate_route_invalid_authz(
    UOW, authorization_schema, authorization_path, make_authz, a_persisted_route
):
    # Setup/Execute
    with mock.patch("requests.get") as mock_get:
        mock_get.return_value.status_code = make_authz(version=1)
        with pytest.raises(ValueError):
            validate_route(
                UOW, a_persisted_route.id, authorization_path, authorization_schema
            )

    # Assert
    with UOW() as uow:
        updated = uow.route_repo.get(a_persisted_route.id)
        assert updated.verification_status == VerificationStatus.PENDING


def test_check_routes_removes_old_routes(
    UOW, authorization_schema, authz_client, make_route, make_domain
):
    # Setup
    stale_duration = 1
    domain = make_domain()
    routes = [
        make_route(
            src=f"src{_}",
            dst=f"dst{_}",
            domain=domain,
            verification_status=VerificationStatus.VERIFIED,
            status=Status.UP,
        )
        for _ in range(3)
    ]
    old_route = routes[0]
    old_route.last_contact = pendulum.now().subtract(days=stale_duration + 2)

    with UOW() as uow:
        uow.route_repo.add(routes)

    # Execute
    with mock.patch("route_registry.services.update_route"):
        check_routes(
            UOW, authorization_schema, authz_client, stale_duration=stale_duration
        )

    # Verify
    with UOW() as uow:
        actual_old_route = uow.route_repo.get(old_route.id)
        assert actual_old_route.verification_status is VerificationStatus.UNVERIFIED
        assert actual_old_route.status is Status.DOWN
        active_routes = (r for r in routes if r.id != actual_old_route.id)

        for route in active_routes:
            assert route.verification_status is VerificationStatus.VERIFIED
            assert route.status is Status.UP


def test_create_piko_jwt(a_persisted_route, jwks):
    # Setup/Execute
    encoded_jwt = create_piko_jwt(a_persisted_route, jwks, 300)

    # Verify
    claims = jwt.decode(encoded_jwt, jwks.jwks.key_map[jwks.active_kid].public_key)
    jwt.JWTClaimsRegistry(leeway=1).validate(claims.claims)

    assert claims
    assert claims.claims["piko"]
    assert claims.claims["piko"]["endpoints"][0] == a_persisted_route.id
