"""
HTTP session wrapper for GitLab (PRIVATE-TOKEN) and Dynatrace (Api-Token) calls.

Provides retries, unified error handling, and a small GraphQL helper.
"""

import time

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import ChunkedEncodingError, ConnectionError, HTTPError, RequestException, Timeout
from dynatrace_extension.sdk.extension import extension_logger as logger

from ..utils import constants as c

MAX_RETRIES = 5


class ApiError(Exception):
    """Raised when the remote API returns an error status or repeated failures after retries."""


class RestApiHandler:
    """
    Configured ``requests.Session`` for REST and GraphQL HTTP calls.

    Responsibility:
        Attach authentication headers, retry on rate limits / transient 5xx, normalize
        failures as ``ApiError``, and expose ``get_url``, ``post_url``, and ``graphql``.
    """

    def __init__(self, auth_header: str | None = None, private_token: str | None = None) -> None:
        """
        Args:
            auth_header: Full ``Authorization`` header value (e.g. ``Api-Token …``).
            private_token: GitLab ``PRIVATE-TOKEN`` value (mutually combinable with ``auth_header``).
        """
        self.session = requests.Session()
        self.session.mount("https://", HTTPAdapter(max_retries=MAX_RETRIES))
        self.session.mount("http://", HTTPAdapter(max_retries=MAX_RETRIES))
        if auth_header:
            self.session.headers["Authorization"] = auth_header
        if private_token:
            self.session.headers["PRIVATE-TOKEN"] = private_token
        self.session.headers["Content-Type"] = "application/json"

    def _handle_response(self, response: requests.Response, url: str) -> None:
        """
        Map HTTP status codes to exceptions.

        Args:
            response: Completed response object.
            url: Request URL (for error messages).

        Raises:
            ApiError: On 401, 403, 404, 429, or 5xx after ``raise_for_status`` path.
        """
        status = response.status_code
        if status == c.UNAUTHORIZED:
            raise ApiError(f"401 Unauthorized for URL {url}")
        if status == c.FORBIDDEN:
            raise ApiError(f"403 Forbidden for URL {url}")
        if status == c.NOT_FOUND:
            raise ApiError(f"404 Not Found for URL {url}")
        if status == c.TOO_MANY_REQUESTS:
            retry_after = int(response.headers.get("Retry-After", 1))
            raise ApiError(f"429 Too Many Requests: Retry after {retry_after}s")
        if c.SERVER_ERROR <= status < c.CLIENT_ERROR:
            raise ApiError(f"{status} Server error: {response.text}")
        response.raise_for_status()

    def _request_with_retry(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Execute an HTTP request with manual backoff for 429, 5xx, and transient transport errors.

        Client errors (4xx) from ``raise_for_status`` / ``HTTPError`` are not retried.
        Retries apply to: 429, 5xx responses, and connection/timeouts/decoding issues only.

        Args:
            method: HTTP verb.
            url: Absolute URL.
            **kwargs: Passed to ``session.request``.

        Returns:
            Successful ``requests.Response``.

        Raises:
            ApiError: On non-retryable HTTP errors or after ``MAX_RETRIES`` on retryable failures.
        """
        for attempt in range(MAX_RETRIES):
            try:
                response = self.session.request(method, url, **kwargs)
                if response.status_code == c.TOO_MANY_REQUESTS:
                    retry_after = int(response.headers.get("Retry-After", 1))
                    logger.debug(
                        f"HTTP {response.status_code} for {url}; retrying after {retry_after}s "
                        f"(attempt {attempt + 1}/{MAX_RETRIES})"
                    )
                    time.sleep(retry_after)
                    continue
                if c.SERVER_ERROR <= response.status_code < c.CLIENT_ERROR:
                    logger.debug(
                        f"HTTP {response.status_code} for {url}; backing off "
                        f"(attempt {attempt + 1}/{MAX_RETRIES})"
                    )
                    time.sleep(2**attempt)
                    continue
                self._handle_response(response, url)
                return response
            except HTTPError as e:
                resp = e.response
                status = getattr(resp, "status_code", 0) or 0
                if c.SERVER_ERROR <= status < c.CLIENT_ERROR:
                    if attempt == MAX_RETRIES - 1:
                        logger.error(
                            f"Request to {url} failed after {MAX_RETRIES} attempts (HTTP {status}): {e}"
                        )
                        raise ApiError(f"Request failed after retries: {e}") from e
                    logger.debug(
                        f"HTTP {status} for {url}; backing off (attempt {attempt + 1}/{MAX_RETRIES})"
                    )
                    time.sleep(2**attempt)
                    continue
                body = getattr(resp, "text", "") if resp is not None else ""
                raise ApiError(f"HTTP {status} for URL {url}: {body}") from e
            except (ConnectionError, Timeout, ChunkedEncodingError) as e:
                if attempt == MAX_RETRIES - 1:
                    logger.error(f"Request to {url} failed after {MAX_RETRIES} attempts: {e}")
                    raise ApiError(f"Request failed after retries: {e}") from e
                logger.debug(f"Request to {url} failed ({e}); retrying attempt {attempt + 2}/{MAX_RETRIES}")
                time.sleep(2**attempt)
            except RequestException as e:
                raise ApiError(f"Request failed: {e}") from e
        raise ApiError("Max retries exceeded")

    def get_url(self, url: str, params=None, headers=None) -> requests.Response:
        """
        Args:
            url: Absolute ``http`` or ``https`` URL.
            params: Optional query string mapping.
            headers: Optional extra headers.

        Returns:
            Successful GET response.
        """
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"URL {url} must start with http:// or https://")
        return self._request_with_retry("GET", url, params=params, headers=headers)

    def post_url(self, url: str, json=None, verify: bool | None = None) -> requests.Response:
        """
        Args:
            url: Absolute URL.
            json: JSON body (typically a list of events for Dynatrace ingest).
            verify: SSL verification flag (``False`` for local dev endpoints).

        Returns:
            Successful POST response.
        """
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"URL {url} must start with http:// or https://")
        kwargs = {"json": json}
        if verify is not None:
            kwargs["verify"] = verify
        return self._request_with_retry("POST", url, **kwargs)

    def graphql(self, url: str, query: str, variables: dict | None = None) -> dict:
        """
        POST a GraphQL body and return the ``data`` object.

        Args:
            url: GraphQL endpoint (GitLab ``/api/graphql``).
            query: GraphQL query string.
            variables: Optional variables dict.

        Returns:
            Parsed ``data`` field from the response.

        Raises:
            ApiError: If ``errors`` is non-empty in the JSON body.
        """
        response = self.post_url(url, json={"query": query, "variables": variables or {}})
        data = response.json()
        if data.get("errors"):
            raise ApiError(f"GraphQL errors from {url}: {data['errors']}")
        return data.get("data", {})
