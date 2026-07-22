import bcrypt
import json
import pytest
from route_registry import models
from route_registry.config import settings


@pytest.fixture(scope="session")
def base_config():
    return settings.to_dict()


@pytest.fixture(scope="session")
def authorization_path(base_config):
    return base_config["URL"]["authorization_path"]


@pytest.fixture(scope="module")
def authorization_schema():
    return json.loads(settings.SCHEMA.data)


@pytest.fixture(scope="session")
def a_domain_name():
    return "example"


@pytest.fixture(scope="session")
def a_domain_url():
    return "example.com"


@pytest.fixture(scope="session")
def a_route_name():
    return "route_name"


@pytest.fixture(scope="session")
def a_community_name():
    return "community_name"


@pytest.fixture(scope="session")
def make_user():
    def _fn(**kwargs) -> models.User:
        defaults = {
            "uid": "foo_user",
            "duid": "1234567890",
        }
        return models.User(**(defaults | kwargs))

    return _fn


@pytest.fixture(scope="session")
def make_group():
    def _fn(**kwargs) -> models.Group:
        defaults = {
            "name": "foo_group",
        }
        return models.Group(**(defaults | kwargs))

    return _fn


@pytest.fixture(scope="session")
def make_domain(a_domain_name, a_domain_url):
    def _fn(**kwargs) -> models.Domain:
        defaults = {
            "name": a_domain_name,
            "value": a_domain_url,
            "default": True,
        }
        return models.Domain(**(defaults | kwargs))

    return _fn


@pytest.fixture(scope="session")
def make_route(a_route_name):
    def _fn(**kwargs) -> models.Route:
        defaults = {
            "name": a_route_name,
            "src": "https://localhost:5000/foo",
            "dst": "https://localhost:3000/bar",
        }
        return models.Route(**(defaults | kwargs))

    return _fn


@pytest.fixture(scope="session")
def make_community(a_community_name):
    def _fn(**kwargs) -> models.Community:
        defaults = {
            "name": a_community_name,
        }
        return models.Community(**(defaults | kwargs))

    return _fn


@pytest.fixture(scope="session")
def make_membership_request():
    def _fn(**kwargs) -> models.MembershipRequest:
        defaults = {
            "status": models.MembershipStatus.PENDING,
        }
        return models.MembershipRequest(**(defaults | kwargs))

    return _fn


@pytest.fixture(scope="session")
def make_rule(make_user, make_route):
    def _fn(**kwargs) -> models.Rule:
        defaults = {
            "entity": make_user(),
            "route": make_route(),
        }
        return models.Rule(**(defaults | kwargs))

    return _fn


@pytest.fixture
def a_plaintext_token():
    return "foo_token"


@pytest.fixture
def a_hashed_token(a_plaintext_token):
    return bcrypt.hashpw(a_plaintext_token.encode(), bcrypt.gensalt(12)).decode()


@pytest.fixture
def a_user_uid():
    return "foo_user"


@pytest.fixture
def a_group_name():
    return "bar_group"


@pytest.fixture
def a_user(make_user, a_user_uid):
    return make_user(uid=a_user_uid)


@pytest.fixture
def a_group(make_group, a_group_name):
    return make_group(name=a_group_name)


@pytest.fixture
def a_domain(make_domain):
    return make_domain()


@pytest.fixture
def a_route(make_route, a_hashed_token):
    return make_route(token=a_hashed_token)


@pytest.fixture
def a_community(make_community, a_user):
    return make_community(entity_id=a_user.id)


@pytest.fixture
def a_rule(make_rule, a_route, a_user):
    return make_rule(route=a_route, entity=a_user)


@pytest.fixture
def make_authz(a_user_uid, a_group_name):
    def _fn(
        token: str = "",
        allowed: dict = None,
        disallowed: dict = None,
        version: str = "0.0.1",
    ):
        allowed = allowed or {}
        disallowed = disallowed or {}

        default = {
            "version": "0.0.1",
            "allowed": {
                "users": [a_user_uid],
                "groups": [a_group_name],
            },
            "disallowed": {
                "users": [],
                "groups": [],
            },
        }

        default["token"] = token
        default["allowed"] = default["allowed"] | allowed
        default["disallowed"] = default["disallowed"] | disallowed

        return default

    return _fn


@pytest.fixture
def an_authz_with_token(a_plaintext_token, make_authz):
    return make_authz(token=a_plaintext_token)


@pytest.fixture(scope="session")
def base_url():
    return "https://example.com/wormhole"


@pytest.fixture
def admin_token_name():
    return "test_admin_token"


@pytest.fixture
def admin_token_id():
    return "9942481e-6224-421b-8077-0a9ff9434db1"


@pytest.fixture
def plain_admin_token(admin_token_id):
    return f"{admin_token_id}.admintoken"


@pytest.fixture
def make_admin_token(plain_admin_token, admin_token_name, admin_token_id):
    def _fn(**kwargs) -> models.AdminToken:
        _, secret = plain_admin_token.split(".")
        hashed_secret = bcrypt.hashpw(secret.encode(), bcrypt.gensalt(12)).decode(
            "utf-8"
        )
        defaults = {
            "id": admin_token_id,
            "name": admin_token_name,
            "value": hashed_secret,
            "role": models.AdminRole.ANY,
        }
        return models.AdminToken(**(defaults | kwargs))

    return _fn
