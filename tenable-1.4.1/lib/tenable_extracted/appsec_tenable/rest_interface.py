# ruff: noqa: A002

import logging

import requests
import requests.adapters
import requests.auth
from requests.exceptions import RequestException
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util import Retry

logger = logging.getLogger(__name__)


class Header:
    def __init__(self, config: dict):
        self.header_key: str = config["headerKey"]
        self.header_value: str = config["headerValue"]


class Proxy:
    def __init__(self, config: dict):
        self.proxy_protocol = config["protocol"]
        self.proxy_address = config["proxyAddress"]


class Auth:
    def __init__(self, type: str, **kwargs):
        self.type = type

        if type in ["Basic", "Digest"]:
            self.basic_init(kwargs["username"], kwargs["password"])
        elif type == "Header":
            self.header_init(kwargs["header_key"], kwargs["header_value"])
        elif type == "OAuth2" and kwargs["grant_type"] == "Client Credentials":
            self.oauth2_client_credentials_init(
                kwargs["token_url"],
                kwargs["client_id"],
                kwargs["client_secret"],
                kwargs["resource"],
                kwargs["scope"],
            )

    def basic_init(self, username: str, password: str):
        self.username = username
        self.password = password

    def header_init(self, header_key: str, header_value: str):
        self.header_key = header_key
        self.header_value = header_value

    def oauth2_client_credentials_init(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        resource: str = None,
        scope: str = None,
        basic_auth: bool = True,
    ):
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.resource = resource
        self.scope = scope
        self.basic_auth = basic_auth


class RequestsHeaderAuth(requests.auth.AuthBase):
    def __init__(self, header_key: str, header_value: str):
        self.header_key = header_key
        self.header_value = header_value

    def __call__(self, r):
        r.headers[self.header_key] = self.header_value
        return r


class OAuth2ClientCredentialsGrant(requests.auth.AuthBase):
    # TODO Don't refresh the token every time
    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        resource: str = None,
        scope: str = None,
        basic_auth: bool = False,
        verify_ssl: bool = True,
        retries: int = 3,
        backoff_factor: float = 0.1,
    ):
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.resource = resource
        self.scope = scope
        self.basic_auth = basic_auth
        self.verify_ssl = verify_ssl
        self.retries = retries
        self.backoff_factor = backoff_factor

    def __call__(self, r):
        # get token
        token_data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "resource": self.resource,
            "scope": self.scope,
        }
        token_auth = Auth(type=None)

        token_headers = [
            Header({"headerKey": "Content-Type", "headerValue": "application/x-www-form-urlencoded"})
        ]

        token_handler = RestApiHandler(
            self.token_url,
            token_auth,
            verify_ssl=self.verify_ssl,
            retries=self.retries,
            backoff_factor=self.backoff_factor,
        )
        token_request = token_handler.post_url(data=token_data, headers=token_headers)
        token = token_request.json()["access_token"]

        # add token to header
        r.headers["Authorization"] = f"Bearer {token}"
        return r


class RestApiHandler:
    def __init__(
        self,
        url: str,
        auth: Auth | None = None,
        proxies: list[Proxy] | None = None,
        verify_ssl: bool = True,
        retries: int = 5,
        backoff_factor: float = 0.1,
        logger: logging.Logger = logger,
    ):
        self.url = url
        self.logger = logger

        # Setup session
        if proxies is None:
            proxies = []

        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.proxies = {proxy.proxy_protocol: proxy.proxy_address for proxy in proxies}
        self.session.proxies.update({proxy.proxy_protocol: proxy.proxy_address for proxy in proxies})
        self.retries = Retry(
            total=retries, backoff_factor=backoff_factor, allowed_methods=None, backoff_max=15
        )
        self.session.mount(url, requests.adapters.HTTPAdapter(max_retries=self.retries))

        # Setup authentication
        if auth is None:
            auth = Auth(type=None)
        elif auth.type == "Basic":
            self.session.auth = requests.auth.HTTPBasicAuth(auth.username, auth.password)
        elif auth.type == "Digest":
            self.session.auth = requests.auth.HTTPDigestAuth(auth.username, auth.password)
        elif auth.type == "Header":
            self.session.auth = RequestsHeaderAuth(auth.header_key, auth.header_value)
        elif auth.type == "OAuth2":
            self.session.auth = OAuth2ClientCredentialsGrant(
                auth.token_url,
                auth.client_id,
                auth.client_secret,
                auth.resource,
                auth.scope,
                auth.basic_auth,
                verify_ssl=verify_ssl,
                retries=retries,
                backoff_factor=backoff_factor,
            )

    def get_url(
        self, url: None | str = None, headers: list[Header] | None = None, params=None
    ) -> requests.Response:
        if url is None:
            url = self.url
        if headers is None:
            headers = []

        request_headers = {header.header_key: header.header_value for header in headers}

        self.logger.debug(
            f"Attempting GET request to {url} with headers {request_headers} and params {params}"
        )
        try:
            r = self.session.get(url=url, headers=request_headers, params=params, proxies=self.proxies)
            r.raise_for_status()

        except RequestException as e:
            try:
                self.logger.error(
                    f"DEC:D8 Exception when querying {url} -- {e}. "
                    f"Status code {r.status_code} and response {r.text}"
                )
            except UnboundLocalError:
                self.logger.error(f"DEC:D8 Exception when querying {url} -- {e}.")
            raise e

        return r

    def post_url(
        self, url: None | str = None, headers: list[Header] | None = None, params=None, json=None, data=None
    ) -> requests.Response:
        if url is None:
            url = self.url
        if headers is None:
            headers = []

        request_headers = {header.header_key: header.header_value for header in headers}

        self.logger.debug(
            f"Attempting POST request to {url} with headers {request_headers}, params {params}, "
            f"json {json} and URL-encoded data {data}"
        )
        try:
            r = self.session.post(url=url, headers=request_headers, params=params, json=json, data=data)
            r.raise_for_status()

        except RequestException as e:
            try:
                self.logger.error(
                    f"DEC:D8 Exception when querying {url} -- {e}. "
                    f"Status code {r.status_code} and response {r.text}"
                )
            except UnboundLocalError:
                self.logger.error(f"DEC:D8 Exception when querying {url} -- {e}.")
            raise e

        return r
