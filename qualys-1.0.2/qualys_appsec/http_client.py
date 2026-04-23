import logging
import requests
from requests.auth import HTTPBasicAuth
from requests.exceptions import ConnectionError, ProxyError
from typing import Dict, Optional
import time
from datetime import datetime, timedelta

log = logging.getLogger(__name__)


class InvalidCredentialsError(Exception):
    pass


class MissingJWTError(Exception):
    pass


class JWT:
    def __init__(self, value: str):
        self.value = value
        self.expiration = datetime.now() + timedelta(minutes=200)


class GatewayClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        log: logging.Logger = None,
        proxies: Dict = None,
        verify: bool = True,
        timeout_seconds: int = 120,
    ):

        self.jwt: JWT = None

        while base_url.endswith("/"):
            base_url = base_url[:-1]
        self.base_url = base_url

        if proxies is None:
            proxies = {}
        self.proxies = proxies

        self.username = username
        self.password = password

        self.verify = verify
        self.timeout_seconds = timeout_seconds

        self.log = log
        if self.log is None:
            self.log = logging.getLogger(__name__)
            self.log.setLevel(logging.WARNING)
            st = logging.StreamHandler()
            fmt = logging.Formatter(
                "%(asctime)s - %(levelname)s - %(name)s - %(thread)d - %(filename)s:%(lineno)d - %(message)s"
            )
            st.setFormatter(fmt)
            self.log.addHandler(st)

    def update_jwt(self):
        if self.jwt:
            if (self.jwt.expiration - datetime.now()).total_seconds() > 600:
                self.log.info(f"No need to update JWT yet.")
                return
        try:
            credential_form = {
                "username": self.username,
                "password": self.password,
                "token": "true",
            }
            resp = requests.post(
                f"{self.base_url}/auth",
                proxies=self.proxies,
                timeout=self.timeout_seconds,
                verify=self.verify,
                data=credential_form,
            )
            self.jwt = JWT(resp.text)
        except ProxyError as e:
            self.log.error(
                f"DEC:1C2 An issue with the configured proxy was encountered when obtaining a JWT: {e}."
            )
        except ConnectionError as e:
            self.log.error(
                f"DEC:1C3 Unable to connect to the Qualys API at {self.base_url}/auth: {e}"
            )
        except InvalidCredentialsError as e:
            self.log.error(
                f"DEC:1C6 Unauthorized response when requesting JWT from {self.base_url}/auth"
            )
        except Exception as e:
            self.log.exception(f"Unable to obtain JWT for an unexpected reason: {e}.")

    def make_request(
        self,
        path: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        method="GET",
        data=None,
        files=None,
        body=None,
    ) -> requests.Response:
        url = f"{self.base_url}{path}"

        if not self.jwt:
            raise MissingJWTError()

        if headers is None:
            headers = {}
        if "X-Requested-With" not in [headers.keys()]:
            headers.update({"X-Requested-With": "Dynatrace"})
        headers.update({"Authorization": f"Bearer {self.jwt.value}"})

        self.log.debug(f"Making call to {url}")
        s = requests.Session()
        r = s.request(
            method,
            url,
            headers=headers,
            params=params,
            json=body,
            verify=self.verify,
            proxies=self.proxies,
            data=data,
            files=files,
            timeout=self.timeout_seconds,
        )
        self.log.debug(f"Made call to {url}. Response: {r.status_code}")

        if r.status_code == 401:
            raise InvalidCredentialsError()
        if r.status_code >= 400:
            raise Exception(f"Error making request to {url}: {r}. Response: {r.text}")
        else:
            self.log.debug(f"url: '{url}' response: '{r.text}'")

        return r


class HttpClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        log: logging.Logger = None,
        proxies: Dict = None,
        verify: bool = True,
        timeout_seconds: int = 120,
    ):
        while base_url.endswith("/"):
            base_url = base_url[:-1]
        self.base_url = base_url

        if proxies is None:
            proxies = {}
        self.proxies = proxies

        self.username = username
        self.password = password

        self.verify = verify
        self.timeout_seconds = timeout_seconds

        self.log = log
        if self.log is None:
            self.log = logging.getLogger(__name__)
            self.log.setLevel(logging.WARNING)
            st = logging.StreamHandler()
            fmt = logging.Formatter(
                "%(asctime)s - %(levelname)s - %(name)s - %(thread)d - %(filename)s:%(lineno)d - %(message)s"
            )
            st.setFormatter(fmt)
            self.log.addHandler(st)

    def make_request(
        self,
        path: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        method="GET",
        data=None,
        files=None,
    ) -> requests.Response:
        url = f"{self.base_url}{path}"

        body = None

        if headers is None:
            headers = {}
        if "X-Requested-With" not in [headers.keys()]:
            headers.update({"X-Requested-With": "Dynatrace"})

        self.log.debug(f"Making call to {url}")
        s = requests.Session()
        r = s.request(
            method,
            url,
            headers=headers,
            params=params,
            json=body,
            verify=self.verify,
            proxies=self.proxies,
            data=data,
            files=files,
            auth=HTTPBasicAuth(self.username, self.password),
            timeout=self.timeout_seconds,
        )
        self.log.debug(f"Made call to {url}. Response: {r.status_code}")

        rate_limit = r.headers.get("x-ratelimit-limit")
        rate_limit_remaining = r.headers.get("x-ratelimit-remaining")
        to_wait_sec = r.headers.get("x-ratelimit-towait-sec")
        concurrency_limit = r.headers.get("x-concurrency-limit-limit")
        self.log.debug(
            f"Rate limit headers: Rate limit: {rate_limit}, Rate limit remaining: {rate_limit_remaining}, To wait: {to_wait_sec}, Concurrency limit: {concurrency_limit}"
        )

        if (
            rate_limit_remaining
            and int(rate_limit_remaining) <= 0
            and to_wait_sec
            and int(to_wait_sec) > 0
        ):
            self.log.warning(
                f"Rate limit reached, will try again after {to_wait_sec} seconds (limit: {rate_limit}, remaining: {rate_limit_remaining})."
            )
            time.sleep(int(to_wait_sec))
            r = self.make_request(path, params, headers, method, data, files)

        if r.status_code == 401:
            raise InvalidCredentialsError()
        if r.status_code >= 400:
            raise Exception(f"Error making request to {url}: {r}. Response: {r.text}")

        return r
