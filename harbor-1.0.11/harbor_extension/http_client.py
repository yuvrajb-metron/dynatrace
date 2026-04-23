import logging
from typing import Dict, Optional
import logging
import requests
from requests.adapters import HTTPAdapter, Retry
from requests.auth import HTTPBasicAuth
from typing import Dict, Optional

API_BASE = "/api/v2.0"

RETRIES = Retry(total=5, backoff_factor=.2)

class HttpClient:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        log: logging.Logger = None,
        proxies: Dict = None,
        verify: bool = False,
        timeout_seconds: int = 60,
    ):
        while host.endswith("/"):
            host = host[:-1]
        self.base_url = f"{host}{API_BASE}"

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
        if method in ["POST", "PUT"]:
            body = params
            params = None

        if headers is None:
            headers = {}
        if files is None and "content-type" not in [
            key.lower() for key in headers.keys()
        ]:
            headers.update({"content-type": "application/json"})

        s = requests.Session()
        s.mount('https://', HTTPAdapter(max_retries=RETRIES))
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
            timeout=self.timeout_seconds
        )

        if r.status_code >= 400:
            raise Exception(f"Error making request to {url}: {r}. Response: {r.text}")
        else:
            self.log.debug(f"url: '{url}' response: '{r}'")

        return r
