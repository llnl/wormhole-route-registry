import inspect
import logging
import pytest

from typing import Annotated
from unittest import mock

from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from route_registry.models import User
from route_registry.dependencies import (
    AuthenticatorFactory,
    LocalDevAuthenticator,
    TokenOrFallbackAuthenticator,
    TokenServiceAuthenticator,
    require_admin,
)

# Treat unawaited coroutine warnings as errors for this file
pytestmark = pytest.mark.filterwarnings(
    "error::RuntimeWarning",
)


@pytest.mark.asyncio
async def test_local_dev_authenticator_returns_configured_user(UOW, a_persisted_user):
    # Setup
    auth = LocalDevAuthenticator(UOW, {"uid": a_persisted_user.uid})

    # Execute
    user = await auth()

    # Verify
    assert user.uid == a_persisted_user.uid


@pytest.mark.asyncio
async def test_local_dev_authenticator_defaults_to_local_username(UOW):
    # Setup
    with mock.patch(
        "route_registry.dependencies.get_local_username", return_value="machine_user"
    ):
        auth = LocalDevAuthenticator(UOW, {})

    # Verify
    assert auth.uid == "machine_user"


@pytest.mark.asyncio
async def test_local_dev_authenticator_401s_when_user_not_seeded(UOW):
    # Setup
    auth = LocalDevAuthenticator(UOW, {"uid": "never_seeded"})

    # Execute and Verify
    with pytest.raises(Exception) as excinfo:
        await auth()
    assert "seed-dev-user" in str(excinfo.value.detail)


@pytest.mark.asyncio
async def test_local_dev_authenticator_requires_no_credential(UOW):
    """FastAPI derives the request contract from __call__'s signature.

    Its only parameter is a Request, which FastAPI injects itself; that is what
    makes the endpoint require no credential. If a header, cookie or query
    parameter ever creeps in, callers start getting 422s.
    """

    auth = LocalDevAuthenticator(UOW, {"uid": "whoever"})
    params = inspect.signature(auth.__call__).parameters

    assert list(params) == ["request"]
    assert params["request"].annotation is Request


@pytest.mark.asyncio
async def test_local_dev_authenticator_works_as_a_token_fallback(UOW, a_persisted_user):
    """TokenOrFallbackAuthenticator passes the request through positionally."""

    auth = LocalDevAuthenticator(UOW, {"uid": a_persisted_user.uid})

    user = await auth(mock.Mock(spec=Request))

    assert user.uid == a_persisted_user.uid


def test_local_dev_authenticator_is_hashable(UOW):
    """FastAPI hashes dependency callables; @define would otherwise break it."""

    assert hash(LocalDevAuthenticator(UOW, {"uid": "whoever"}))


def test_local_dev_is_registered_with_the_factory(base_config):
    """Registration plus a matching config table.

    make_authenticator does config[auth_name], so a registered authenticator
    with no settings.toml section of the same name is a startup KeyError.
    """

    assert AuthenticatorFactory().authenticators["local_dev"] is LocalDevAuthenticator
    assert "local_dev" in base_config["AUTH"]


def test_local_dev_authenticator_built_by_the_factory(UOW, base_config):
    """The real settings.toml table must produce a working authenticator.

    make_authenticator does config[auth_name], so this exercises the wiring a
    developer actually gets from DYNACONF_AUTH__auth_name=local_dev.
    """

    auth_config = base_config["AUTH"] | {"auth_name": "local_dev"}

    with mock.patch(
            "route_registry.dependencies.get_local_username", return_value="machine_user"
    ):
        auth = AuthenticatorFactory().make_authenticator(UOW, auth_config)

    assert isinstance(auth, LocalDevAuthenticator)
    # settings.toml ships uid = "", which must fall through to the machine user
    assert auth.uid == "machine_user"


def test_local_dev_authenticator_warns_loudly_on_setup(UOW, caplog):
    """Turning authentication off must never be silent."""

    auth = LocalDevAuthenticator(UOW, {"uid": "whoever"})

    with caplog.at_level(logging.WARNING, logger="route_registry.dependencies"):
        auth.setup(FastAPI())

    assert "AUTH IS DISABLED" in caplog.text
    assert "whoever" in caplog.text


@pytest.fixture
def make_local_dev_client(UOW, base_config):
    """A minimal app wired the way server.make_app wires the real one."""

    def _fn(uid: str) -> TestClient:
        auth = LocalDevAuthenticator(UOW, {"uid": uid})
        token_auth = TokenServiceAuthenticator(
            base_config["AUTH"]["token_service"], UOW
        )
        fallback = TokenOrFallbackAuthenticator(token_auth, auth)

        app = FastAPI()

        @app.get("/me")
        async def me(user: Annotated[User, Depends(auth)]):
            return {"uid": user.uid}

        @app.get("/community")
        async def community(user: Annotated[User, Depends(fallback)]):
            return {"uid": user.uid}

        @app.get("/admin-only")
        async def admin_only(user: Annotated[User, Depends(require_admin(auth))]):
            return {"uid": user.uid}

        return TestClient(app)

    return _fn


def test_endpoint_needs_no_credential(make_local_dev_client, a_persisted_user):
    """No header, no cookie, no query parameter -- and no 422."""

    resp = make_local_dev_client(a_persisted_user.uid).get("/me")

    assert resp.status_code == 200
    assert resp.json() == {"uid": a_persisted_user.uid}


def test_endpoint_behind_token_fallback_needs_no_credential(
    make_local_dev_client, a_persisted_user
):
    """The community and route routers depend on TokenOrFallbackAuthenticator.

    With no X-Token header it defers to the fallback, which is where the local
    dev authenticator has to work.
    """

    resp = make_local_dev_client(a_persisted_user.uid).get("/community")

    assert resp.status_code == 200
    assert resp.json() == {"uid": a_persisted_user.uid}


def test_admin_endpoint_allows_a_seeded_admin(make_local_dev_client, UOW, make_user):
    admin = make_user(uid="an_admin", is_admin=True)
    with UOW() as uow:
        uow.entity_repo.add(admin)

    resp = make_local_dev_client(admin.uid).get("/admin-only")

    assert resp.status_code == 200


def test_admin_endpoint_rejects_a_seeded_non_admin(
    make_local_dev_client, a_persisted_user
):
    """Seeding with --no-admin must still gate the admin endpoints."""

    assert not a_persisted_user.is_admin

    resp = make_local_dev_client(a_persisted_user.uid).get("/admin-only")

    assert resp.status_code == 403


def test_endpoint_401s_with_the_seed_hint_when_not_seeded(make_local_dev_client):
    resp = make_local_dev_client("never_seeded").get("/me")

    assert resp.status_code == 401
    assert "seed-dev-user" in resp.json()["detail"]
