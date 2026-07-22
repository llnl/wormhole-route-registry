"""API client for interacting with HolePunch."""

from attrs import define, field
from requests.exceptions import HTTPError
from requests import Session

from .base_client import BaseAPIClient, APIClientException, APIClientConnectionException
from route_registry.utils import urljoin


@define
class ClientException(APIClientException):
    """Base HolePunch client exception."""


@define
class ConnectionException(ClientException):
    """HolePunch client connection exception."""


@define(slots=False)
class HolePunchClient(BaseAPIClient):
    """HolePunch API client."""

    config: dict = field(factory=dict)
    base_url: str = field()
    version: str = field()
    url: str = field()
    secret: str = field(default=None)
    ca_cert_path: str = field(default=None)
    session: Session = field(factory=Session)

    @base_url.default
    def _base_url(self):
        return self.config["base_url"]

    @version.default
    def _version(self):
        return self.config.get("version", "v1")

    @url.default
    def _url(self):
        return urljoin(self.base_url, self.version)

    def _handle_error(self, e: HTTPError):
        raise ClientException(
            message=e.strerror, status_code=e.response.status_code, url=e.response.url
        )

    def notify_route_update(self):
        """Notify that the route table has updated."""

        try:
            resp = self._process("/webhook/routes", method="POST")
            resp.raise_for_status()
        except APIClientConnectionException:
            raise ConnectionException("Unable to connect to HolePunch")
