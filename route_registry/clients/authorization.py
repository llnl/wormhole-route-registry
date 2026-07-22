"""API client for fetching app authorization."""

import json
from attrs import define, field
from requests import Session
from requests.exceptions import HTTPError

from .base_client import BaseAPIClient, APIClientException, APIClientConnectionException
from ..models import Route


@define
class AuthorizationClientException(APIClientException):
    """Base Authorization client exception."""


@define
class ConnectionException(AuthorizationClientException):
    """Authorization client connection exception."""


@define(slots=False)
class AuthorizationClient(BaseAPIClient):
    """Authz API client."""

    def _handle_error(self, e: HTTPError):
        raise AuthorizationClientException(
            message=e.strerror, status_code=e.response.status_code, url=e.response.url
        )

    def get_authorization(self, route: Route) -> dict:
        """Get authorization spec from app."""

        try:
            resp = self._process("authorization.json", alt_url=route.dst)
            return resp.json()
        except APIClientConnectionException:
            raise ConnectionException("Unable to connect to fetch authorization file")
        except json.JSONDecodeError:
            raise APIClientException("Failed decoding response for get_authorization")


@define(slots=False)
class PikoAuthorizationClient(AuthorizationClient):
    """Authz API client."""

    config: dict = field(factory=dict)
    tunnel_config: dict = field()
    url: str = field()
    secret: str = field()
    ca_cert_path: str = field()
    session: Session = field(default=Session())
    authz_path: str = field()
    piko_header: str = field()

    @tunnel_config.default
    def _tunnel_config(self):
        return self.config.get("tunnel", {})

    @url.default
    def _url(self):
        return self.tunnel_config.get("base_url", "")

    @secret.default
    def _secret(self):
        return self.tunnel_config.get("token", "")

    @ca_cert_path.default
    def _ca_cert_path(self):
        return self.tunnel_config.get("ca_cert_path", "")

    @authz_path.default
    def _authz_path(self):
        return self.config.get("authorization_path", "authorization.json")

    @piko_header.default
    def _piko_header(self):
        return self.tunnel_config.get("target_header", "X-Piko-Endpoint")

    def get_authorization(self, route: Route) -> dict:
        """Get authorization spec from app behind piko."""

        headers = {self.piko_header: route.id}
        # TODO: potentially offer a way to configure the authz_path for a route
        try:
            resp = self._process(self.authz_path, alt_url=route.dst, headers=headers)
            return resp.json()
        except APIClientConnectionException:
            raise ConnectionException("Unable to connect to fetch authorization file")
        except json.JSONDecodeError:
            raise APIClientException("Failed decoding response for get_authorization")
