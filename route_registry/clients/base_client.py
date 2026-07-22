"""Base API client."""

import json
from attrs import define, field
from requests import PreparedRequest, Request, Response, Session
from requests.exceptions import ConnectionError, HTTPError
from typing import Optional
import logging
from ..utils import urljoin

logger = logging.getLogger(__name__)


@define
class APIClientException(Exception):
    """Base API client exception."""

    message: str
    status_code: int = field(default=200)
    url: str = field(default="")


@define
class APIClientConnectionException(APIClientException):
    """API connection exception."""

    pass


@define(slots=False)
class BaseAPIClient:
    """Base API client."""

    config: dict = field(factory=dict)
    url: str = field()
    secret: str = field()
    ca_cert_path: str = field()
    session: Session = field(default=Session())

    @url.default
    def _url(self):
        return self.config["url"]

    @secret.default
    def _secret(self):
        return self.config.get("token", "")

    @ca_cert_path.default
    def _ca_cert_path(self):
        return self.config.get("ca_cert_path", "")

    def _build_headers(self) -> dict:
        return {}

    def _prepare(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[dict] = None,
        data: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> PreparedRequest:
        default_headers = self._build_headers()
        self.session.verify = self.ca_cert_path or False
        data_json = json.dumps(data) if data else None
        if headers:
            default_headers.update(headers)
        req = Request(
            method, url, headers=default_headers, data=data_json, params=params
        )
        return self.session.prepare_request(req)

    def _handle_error(self, e: HTTPError):
        raise APIClientException(
            message=e.strerror, status_code=e.response.status_code, url=e.response.url
        )

    def _process(
        self,
        path: str,
        alt_url: str = "",
        method: str = "GET",
        headers: Optional[dict] = None,
        data: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> Response:
        url = urljoin(alt_url or self.url, path)
        prepped = self._prepare(url, method, headers, data, params)

        try:
            resp = self.session.send(prepped)
            resp.raise_for_status()
            return resp
        except ConnectionError:
            raise APIClientConnectionException(f"Unable to connect to API at {url}")
        except HTTPError as e:
            self._handle_error(e)
