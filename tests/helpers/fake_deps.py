from attrs import define
from typing import Any

from route_registry.models import User


def token_service_call_target():
    raise NotImplementedError("Implement via mock")


def oidc_call_target():
    raise NotImplementedError("Implement via mock")


@define
class FakeTokenServiceAuthenticator:
    config: dict
    uow: Any

    def __hash__(self):
        return hash(self.__class__.__name__)

    def __call__(self) -> User:
        return token_service_call_target()

    def setup(self, app) -> None:
        return None


@define
class FakeOIDCAuthenticator:
    config: dict
    uow: Any

    def __hash__(self):
        return hash(self.__class__.__name__)

    # NOTE: Make request optional with default None to work with both direct calls
    # (with request parameter) and wrapped calls through require_admin
    async def __call__(self, request=None) -> User | None:
        return oidc_call_target()

    def setup(self, app) -> None:
        return None


@define
class FakeAuthenticatorFactory:
    @staticmethod
    def make_authenticator(uow, config) -> FakeOIDCAuthenticator:
        return FakeOIDCAuthenticator(config=config, uow=uow)
