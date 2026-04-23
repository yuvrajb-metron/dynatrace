
import time
import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import RequestException

MAX_RETRIES = 5
class ApiError(Exception):
    pass

class RestApiHandler:
    """GET/POST with optional auth. Bearer or Api-Token in Authorization header."""

    def __init__(self, auth_header: str | None = None):
        self.session = requests.Session()
        self.session.mount("https://", HTTPAdapter(max_retries=MAX_RETRIES))
        self.session.mount("http://", HTTPAdapter(max_retries=MAX_RETRIES))

        if auth_header:
            self.session.headers["Authorization"] = auth_header

    def _handle_response(self, response: requests.Response, url: str):
        status = response.status_code

        if status == 401:
            raise ApiError(f"401 Unauthorized: Invalid or expired credentials for URL {url}")

        if status == 403:
            raise ApiError(f"403 Forbidden: Access denied for URL {url}")

        if status == 429:
            retry_after = int(response.headers.get("Retry-After", 1))
            raise ApiError(f"429 Too Many Requests: Retry after {retry_after}s")

        if 500 <= status < 600:
            raise ApiError(f"{status} Server error: {response.text}")

        response.raise_for_status()

    def _request_with_retry(self, method, url, **kwargs):
        for attempt in range(MAX_RETRIES):
            try:
                response = self.session.request(method, url, **kwargs)

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 1))
                    time.sleep(retry_after)
                    continue

                if 500 <= response.status_code < 600:
                    time.sleep(2 ** attempt)  # exponential backoff
                    continue

                self._handle_response(response, url)
                return response

            except RequestException as e:
                if attempt == MAX_RETRIES - 1:
                    raise ApiError(f"Request failed after retries: {e}")
                time.sleep(2 ** attempt)

        raise ApiError("Max retries exceeded")

    def get_url(self, url: str, headers=None) -> requests.Response:
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"URL {url} must start with http:// or https://")

        return self._request_with_retry("GET", url, headers=headers)

    def post_url(self, url: str, json=None, verify: bool | None = None) -> requests.Response:
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"URL {url} must start with http:// or https://")

        kwargs = {"json": json}
        if verify is not None:
            kwargs["verify"] = verify
        return self._request_with_retry("POST", url, **kwargs)