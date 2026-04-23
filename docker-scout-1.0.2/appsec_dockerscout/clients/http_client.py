"""
HTTP client and Docker Hub API client.

RestApiHandler: POST with auth and retries; used by ingest for Dynatrace security events push.

DockerHubClient: Docker Hub API v2 (login, orgs, repos, tags) for image discovery.
"""

import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import RequestException

from appsec_dockerscout.models import ImageRef, Org, Repo
from dynatrace_extension.sdk.extension import extension_logger as logger

MAX_RETRIES = 5
HUB_BASE = "https://hub.docker.com/v2"

# Hub repository ``status`` from GET /v2/namespaces/{ns}/repositories.
# ``1`` + status_description ``active`` means the repo is active for analysis (Docker Scout).
# ``0`` + ``initialized`` and other values are skipped so we only run ``docker scout`` on enabled repos.
HUB_REPO_STATUS_ACTIVE = 1


def _parse_hub_api_timestamp_to_utc(raw_timestamp: Optional[str]) -> Optional[datetime]:
    """
    Convert a Docker Hub JSON datetime field to an aware ``datetime`` in UTC.

    The Hub API uses ISO-8601 strings, often with a ``Z`` (UTC) suffix. Python 3.10’s
    ``datetime.fromisoformat`` does not accept ``Z``, so we rewrite it to ``+00:00``
    before parsing. Naive values are treated as UTC.
    """
    if not raw_timestamp or not isinstance(raw_timestamp, str):
        return None

    normalized = raw_timestamp.strip()
    # fromisoformat() compatibility: Z means UTC.
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _is_in_utc_interval_inclusive(
    instant_utc: datetime,
    interval_start_utc: datetime,
    interval_end_utc: datetime,
) -> bool:
    """
    Return whether ``instant_utc`` lies inside the closed UTC interval
    ``[interval_start_utc, interval_end_utc]`` (endpoints count as inside).

    Used for Hub activity lookback so repo ``last_updated`` and tag ``tag_last_pushed``
    fall within the configured time window.
    """
    return interval_start_utc <= instant_utc <= interval_end_utc


class ApiError(Exception):
    """Request or API response error (auth, rate limit, server error)."""


def handle_http_response(response: requests.Response, url: str) -> None:
    """
    Validate HTTP status: map 401/403/429/5xx to ``ApiError``, else ``raise_for_status``.

    Used by ``RestApiHandler`` (Dynatrace ingest) and by :func:`handle_http_response_as_hub_error`.

    Args:
        response: The HTTP response object.
        url: Request URL (for error messages).

    Raises:
        ApiError: On auth, rate limit, or server error statuses.
        requests.HTTPError: On other non-success statuses (from ``raise_for_status``).
    """
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


class RestApiHandler:
    """POST with optional auth. Bearer or Api-Token in Authorization header."""

    def __init__(self, auth_header: str | None = None) -> None:
        """
        Create a session with optional ``Authorization`` header.

        Args:
            auth_header: Value for the ``Authorization`` header (e.g. ``Api-Token …``).
        """
        self.session = requests.Session()
        self.session.mount("https://", HTTPAdapter(max_retries=MAX_RETRIES))
        self.session.mount("http://", HTTPAdapter(max_retries=MAX_RETRIES))

        if auth_header:
            self.session.headers["Authorization"] = auth_header

    def _request_with_retry(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Perform an HTTP request with retries on 429 and 5xx.

        Args:
            method: HTTP method name.
            url: Request URL.
            **kwargs: Passed to ``session.request``.

        Returns:
            Successful response after :func:`handle_http_response`.

        Raises:
            ApiError: When retries are exhausted or a non-retryable error occurs.
        """
        for attempt in range(MAX_RETRIES):
            try:
                response = self.session.request(method, url, **kwargs)

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 1))
                    time.sleep(retry_after)
                    continue

                if 500 <= response.status_code < 600:
                    time.sleep(2**attempt)
                    continue

                handle_http_response(response, url)
                return response

            except RequestException as e:
                if attempt == MAX_RETRIES - 1:
                    raise ApiError(f"Request failed after retries: {e}") from e
                time.sleep(2**attempt)

        raise ApiError("Max retries exceeded")

    def post_url(
        self, url: str, json: dict | list | None = None, verify: bool | None = None
    ) -> requests.Response:
        """
        Perform POST request with retries and auth.

        Args:
            url: Absolute HTTP(S) URL.
            json: JSON body.
            verify: SSL verify flag for the request.

        Returns:
            The HTTP response object.
        """
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"URL {url} must start with http:// or https://")
        kwargs: dict = {"json": json}
        if verify is not None:
            kwargs["verify"] = verify
        return self._request_with_retry("POST", url, **kwargs)


class DockerHubClientError(Exception):
    """Docker Hub API or auth error."""


def handle_http_response_as_hub_error(response: requests.Response, url: str) -> None:
    """
    Same validation as :func:`handle_http_response`, but raise :class:`DockerHubClientError`
    instead of :class:`ApiError` so Hub discovery code can catch one exception type.
    """
    try:
        handle_http_response(response, url)
    except ApiError as e:
        raise DockerHubClientError(str(e)) from e


class DockerHubClient:
    """Client for Docker Hub API v2 (auth, orgs, repos, tags)."""

    def __init__(self, username: str, password: str, timeout: int = 30) -> None:
        """
        Args:
            username: Docker Hub username.
            password: Personal access token (PAT).
            timeout: HTTP timeout in seconds.
        """
        self.username = username
        self.password = password
        self.timeout = timeout
        self._token: Optional[str] = None

    def login(self) -> str:
        """
        Exchange username + PAT for JWT.

        Returns:
            The bearer token string.

        Raises:
            DockerHubClientError: On HTTP failure or missing token in response.
        """
        login_url = f"{HUB_BASE}/users/login/"
        logger.debug(
            f"Docker Hub login starting: url={login_url}, username={self.username}"
        )
        login_request_body = {
            "username": self.username,
            "password": self.password,
        }
        try:
            response = requests.post(
                login_url,
                json=login_request_body,
                timeout=self.timeout,
                headers={"Content-Type": "application/json"},
            )
            handle_http_response_as_hub_error(response, login_url)
            login_response = response.json()
            self._token = login_response.get("token")
            if not self._token:
                raise DockerHubClientError("Login response missing token")
            logger.debug("Docker Hub login succeeded; token received.")
            return self._token
        except DockerHubClientError:
            raise
        except requests.RequestException as e:
            raise DockerHubClientError(f"Docker Hub login failed: {e}") from e

    def _ensure_token(self) -> str:
        """Return cached JWT or login and cache it."""
        if not self._token:
            return self.login()
        return self._token

    def _headers(self) -> dict:
        """Headers for authenticated Hub API requests."""
        return {
            "Authorization": f"Bearer {self._ensure_token()}",
            "Content-Type": "application/json",
        }

    def get_orgs(self) -> List[Org]:
        """
        GET /v2/user/orgs/: list orgs for the authenticated user.

        Returns:
            List of Org objects.

        Raises:
            DockerHubClientError: On request failure.
        """
        next_page_url = f"{HUB_BASE}/user/orgs/"
        logger.debug(f"get_orgs starting: url={next_page_url}")
        organizations: List[Org] = []
        while next_page_url:
            try:
                response = requests.get(
                    next_page_url,
                    headers=self._headers(),
                    timeout=self.timeout,
                )
                handle_http_response_as_hub_error(response, next_page_url)
                page_body = response.json()
                for org_record in page_body.get("results", []):
                    organization_name = org_record.get(
                        "orgname",
                        org_record.get("name", ""),
                    )
                    organizations.append(
                        Org(
                            name=organization_name,
                            org_id=str(org_record.get("id", "")),
                        )
                    )
                next_page_url = page_body.get("next")
            except DockerHubClientError:
                raise
            except requests.RequestException as e:
                logger.warning(f"get_orgs request failed: {e}")
                raise DockerHubClientError(f"get_orgs failed: {e}") from e
        logger.debug(f"get_orgs finished: {len(organizations)} org(s).")
        return organizations

    def get_repositories(
        self,
        namespace: str,
        page_size: int = 100,
        *,
        lookback_window_start_utc: datetime,
        lookback_window_end_utc: datetime,
    ) -> List[Repo]:
        """
        GET /v2/namespaces/<namespace>/repositories.

        Only repositories with ``status == 1`` (Hub ``active``) are returned so Docker Scout
        is run only on repos that are enabled/ready per Docker Hub.
        Repositories whose ``last_updated`` is outside
        ``[lookback_window_start_utc, lookback_window_end_utc]`` are skipped.

        Args:
            namespace: Org/namespace name.
            page_size: Page size for pagination.
            lookback_window_start_utc: Inclusive lower bound (UTC) for ``last_updated``.
            lookback_window_end_utc: Inclusive upper bound (UTC) for ``last_updated``.

        Returns:
            List of Repo objects.

        Raises:
            DockerHubClientError: On request failure.
        """
        next_page_url = f"{HUB_BASE}/namespaces/{namespace}/repositories"
        logger.debug(f"get_repositories starting: namespace={namespace}")
        scout_active_repositories: List[Repo] = []
        page_params = {"page_size": page_size}
        while next_page_url:
            try:
                response = requests.get(
                    next_page_url,
                    headers=self._headers(),
                    params=page_params,
                    timeout=self.timeout,
                )
                handle_http_response_as_hub_error(response, next_page_url)
                page_body = response.json()
                for repo_record in page_body.get("results", []):
                    repository_name = repo_record.get("name", "")
                    if not repository_name:
                        continue
                    repository_status = repo_record.get("status")
                    if repository_status != HUB_REPO_STATUS_ACTIVE:
                        status_description = repo_record.get("status_description")
                        logger.debug(
                            f"Skipping {namespace}/{repository_name}: "
                            f"repository status={repository_status} ({status_description}), "
                            f"not Docker Scout-active (expect status={HUB_REPO_STATUS_ACTIVE})"
                        )
                        continue
                    last_updated_raw = repo_record.get("last_updated")
                    last_updated_at_utc = _parse_hub_api_timestamp_to_utc(
                        last_updated_raw
                        if isinstance(last_updated_raw, str)
                        else None
                    )
                    if last_updated_at_utc is None or not _is_in_utc_interval_inclusive(
                        last_updated_at_utc,
                        lookback_window_start_utc,
                        lookback_window_end_utc,
                    ):
                        logger.debug(
                            f"Skipping {namespace}/{repository_name}: last_updated="
                            f"{last_updated_raw!r} outside hub activity lookback window "
                            f"[{lookback_window_start_utc.isoformat()}, "
                            f"{lookback_window_end_utc.isoformat()}]"
                        )
                        continue
                    scout_active_repositories.append(
                        Repo(
                            name=repository_name,
                            namespace=namespace,
                            repo_id=str(repo_record.get("id", "")),
                        )
                    )
                next_page_url = page_body.get("next")
                page_params = {}
            except DockerHubClientError:
                raise
            except requests.RequestException as e:
                logger.warning(f"get_repositories request failed: {e}")
                raise DockerHubClientError(f"get_repositories failed: {e}") from e
        logger.debug(
            f"get_repositories finished: namespace={namespace}, "
            f"{len(scout_active_repositories)} Docker Scout-active repo(s)."
        )
        return scout_active_repositories

    def get_tags(
        self,
        org: str,
        repo: str,
        page_size: int = 100,
        *,
        lookback_window_start_utc: datetime,
        lookback_window_end_utc: datetime,
    ) -> List[str]:
        """
        GET /v2/repositories/<org>/<repo>/tags: list tag names.

        Tags whose ``tag_last_pushed`` is outside
        ``[lookback_window_start_utc, lookback_window_end_utc]`` are omitted.

        Args:
            org: Namespace.
            repo: Repository name.
            page_size: Page size for pagination.
            lookback_window_start_utc: Inclusive lower bound (UTC) for ``tag_last_pushed``.
            lookback_window_end_utc: Inclusive upper bound (UTC) for ``tag_last_pushed``.

        Returns:
            List of tag strings.

        Raises:
            DockerHubClientError: On request failure.
        """
        next_page_url = f"{HUB_BASE}/repositories/{org}/{repo}/tags"
        logger.debug(f"get_tags starting: org={org}, repo={repo}")
        tag_names: List[str] = []
        page_params = {"page_size": page_size}
        while next_page_url:
            try:
                response = requests.get(
                    next_page_url,
                    headers=self._headers(),
                    params=page_params,
                    timeout=self.timeout,
                )
                handle_http_response_as_hub_error(response, next_page_url)
                page_body = response.json()
                for tag_record in page_body.get("results", []):
                    tag_name = tag_record.get("name", "")
                    if not tag_name:
                        continue
                    tag_last_pushed_raw = tag_record.get("tag_last_pushed")
                    tag_pushed_at_utc = _parse_hub_api_timestamp_to_utc(
                        tag_last_pushed_raw
                        if isinstance(tag_last_pushed_raw, str)
                        else None
                    )
                    if tag_pushed_at_utc is None or not _is_in_utc_interval_inclusive(
                        tag_pushed_at_utc,
                        lookback_window_start_utc,
                        lookback_window_end_utc,
                    ):
                        logger.debug(
                            f"Skipping tag {org}/{repo}:{tag_name}: "
                            f"tag_last_pushed={tag_last_pushed_raw!r} outside hub activity lookback window "
                            f"[{lookback_window_start_utc.isoformat()}, "
                            f"{lookback_window_end_utc.isoformat()}]"
                        )
                        continue
                    tag_names.append(tag_name)
                next_page_url = page_body.get("next")
                page_params = {}
            except DockerHubClientError:
                raise
            except requests.RequestException as e:
                logger.warning(f"get_tags request failed: {e}")
                raise DockerHubClientError(f"get_tags failed: {e}") from e
        logger.debug(f"get_tags finished: {org}/{repo}, {len(tag_names)} tag(s).")
        return tag_names

    def _image_refs_for_repository(
        self,
        namespace: str,
        repository: Repo,
        lookback_window_start_utc: datetime,
        lookback_window_end_utc: datetime,
    ) -> List[ImageRef]:
        """
        List Hub tags for one repository and map each to an :class:`ImageRef`.

        Raises:
            DockerHubClientError: If tag listing fails (propagate in ``discover_images``).
        """
        tag_names = self.get_tags(
            namespace,
            repository.name,
            lookback_window_start_utc=lookback_window_start_utc,
            lookback_window_end_utc=lookback_window_end_utc,
        )
        return [
            ImageRef(org=namespace, repo=repository.name, tag=tag_name)
            for tag_name in tag_names
        ]

    def discover_images(
        self,
        org_filter: Optional[List[str]] = None,
        *,
        hub_activity_lookback_hours: int,
    ) -> List[ImageRef]:
        """
        Discover all images (org/repo:tag) for the authenticated user.

        If org_filter is set, only those org names are used; otherwise all orgs.
        Repositories must have Hub API ``status == 1`` (active); others are omitted.
        Repositories and tags are further restricted to Hub timestamps within the last
        ``hub_activity_lookback_hours`` (inclusive window ending at discovery time).

        Args:
            org_filter: Optional list of org names to restrict discovery.
            hub_activity_lookback_hours: ``last_updated`` / ``tag_last_pushed`` must fall within this
                many hours before the discovery instant.

        Returns:
            List of ImageRef (one per tag).
        """
        lookback_window_end_utc = datetime.now(timezone.utc)
        lookback_window_start_utc = lookback_window_end_utc - timedelta(hours=hub_activity_lookback_hours)
        logger.debug(
            f"discover_images started: org_filter={org_filter}, "
            f"hub_activity_lookback_hours={hub_activity_lookback_hours}, window=[{lookback_window_start_utc.isoformat()}, "
            f"{lookback_window_end_utc.isoformat()}]"
        )
        images: List[ImageRef] = []
        organizations = self.get_orgs()
        if org_filter:
            namespace_names = {
                organization.name
                for organization in organizations
                if organization.name in org_filter
            }
        else:
            namespace_names = {
                organization.name for organization in organizations
            }
        for namespace in namespace_names:
            try:
                repositories = self.get_repositories(
                    namespace,
                    lookback_window_start_utc=lookback_window_start_utc,
                    lookback_window_end_utc=lookback_window_end_utc,
                )
                for repository in repositories:
                    try:
                        images.extend(
                            self._image_refs_for_repository(
                                namespace,
                                repository,
                                lookback_window_start_utc,
                                lookback_window_end_utc,
                            )
                        )
                    except DockerHubClientError:
                        continue
            except DockerHubClientError:
                continue
        logger.debug(
            f"discover_images finished: {len(namespace_names)} org(s), {len(images)} image(s)."
        )
        return images
