"""Renovate CE REST API: orgs, repos, jobs, job logs."""

from datetime import datetime, timedelta
from typing import Any, Iterator

from requests.exceptions import RequestException
from dynatrace_extension.sdk.extension import extension_logger as logger

from ..clients.http_client import RestApiHandler
MAX_JOBS_PER_PAGE = 50

def _extract_full_repo_name(repo_item: dict) -> str:
    """Extract fullName field safely from repo item."""
    if isinstance(repo_item, dict):
        return repo_item.get("fullName", "")
    return ""

def _parse_repo_spec(repo_spec: str) -> tuple[str, str]:
    """Parse 'org/repo' string into (org, repo)."""
    if not isinstance(repo_spec, str):
        return "", ""

    repo_spec = repo_spec.strip()

    if "/" not in repo_spec:
        return "", ""

    org, _, repo = repo_spec.partition("/")
    return org.strip(), repo.strip()

def _convert_sets_to_lists(
    org_repo_map: dict[str, set[str]]
) -> dict[str, list[str]]:
    """Convert repo sets to sorted lists."""
    return {
        org: sorted(list(repos))
        for org, repos in org_repo_map.items()
    }

def _extract_repositories_config(activation_config: dict) -> dict:
    """Safely extract repositories config."""
    return (
        activation_config.get("connection", {})
        .get("repositories", {})
    )

def _extract_selected_org_names(repos_config: dict) -> list[str]:
    """Extract cleaned org names from config (orgList key)."""
    return [
        entry.strip()
        for entry in repos_config.get("orgList", [])
        if isinstance(entry, str) and entry.strip()
    ]

def _fetch_all_org_names(base_url: str, api_secret: str) -> list[str]:
    """Fetch all organization names from API."""
    orgs = fetch_orgs(base_url, api_secret)

    return [
        org.get("name")
        for org in orgs
        if isinstance(org, dict) and org.get("name")
    ]

def _build_repo_map_from_repo_list(repos_config: dict) -> dict[str, list[str]]:
    """Build org -> repos mapping directly from repolist config."""
    org_repo_map: dict[str, set[str]] = {}

    for entry in repos_config.get("repoList", []):
        org, repo = _parse_repo_spec(entry)
        if org and repo:
            org_repo_map.setdefault(org, set()).add(repo)

    return _convert_sets_to_lists(org_repo_map)

def _populate_repos_for_orgs(
    org_repo_map: dict[str, set[str]],
    org_names: list[str],
    base_url: str,
    api_secret: str,
) -> None:
    """Fetch and populate repos for given organizations."""
    for org_name in org_names:
        repo_items = fetch_repos_for_org(base_url, api_secret, org_name)

        for repo_item in repo_items:
            full_name = _extract_full_repo_name(repo_item)
            org, repo = _parse_repo_spec(full_name)

            if org and repo:
                org_repo_map.setdefault(org, set()).add(repo)

def fetch_orgs(base_url: str, api_secret: str) -> list[dict]:
    """GET {base_url}/api/v1/orgs with Bearer auth.
     Returns list of org dicts; empty list on error."""
    base_url = base_url.rstrip("/")
    url = f"{base_url}/api/v1/orgs"
    try:
        handler = RestApiHandler(auth_header=f"Bearer {api_secret}")
        response = handler.get_url(url=url)
        response_data = response.json()
        return response_data if isinstance(response_data, list) else []
    except (RequestException, ValueError) as err:
        logger.error(f"Failed to fetch orgs from {url}: {err}")
        return []

def fetch_repos_for_org(base_url: str, api_secret: str, org_name: str) -> list[dict]:
    """GET {base_url}/api/v1/orgs/{org_name}/-/repos with Bearer auth. Returns list of repo dicts; empty list on error."""
    base_url = base_url.rstrip("/")
    url = f"{base_url}/api/v1/orgs/{org_name}/-/repos"
    try:
        handler = RestApiHandler(auth_header=f"Bearer {api_secret}")
        response = handler.get_url(url=url)
        response_data = response.json()
        return response_data if isinstance(response_data, list) else []
    except (RequestException, ValueError) as err:
        logger.error(f"Failed to fetch repos for org {org_name} from {url}: {err}")
        return []

def get_orgs_and_repos_to_poll(
    activation_config: dict,
    base_url: str,
    api_secret: str,
) -> dict[str, list[str]]:
    """
    Resolve org -> list of repos from config.

    Modes:
        allOrgsAndRepos
        allReposInSelectedOrgs
        repolist
    """
    repos_config = _extract_repositories_config(activation_config)
    org_repo_map: dict[str, set[str]] = {}

    if repos_config.get("allOrgsAndRepos"):
        org_names = _fetch_all_org_names(base_url, api_secret)

    elif repos_config.get("allReposInSelectedOrgs"):
        org_names = _extract_selected_org_names(repos_config)

    else:
        return _build_repo_map_from_repo_list(repos_config)

    _populate_repos_for_orgs(
        org_repo_map=org_repo_map,
        org_names=org_names,
        base_url=base_url,
        api_secret=api_secret,
    )

    return _convert_sets_to_lists(org_repo_map)


def _url_from_link_segment(segment: str) -> str | None:
    """Extract URL from a Link segment like '</path?query>; rel="next"'. Returns None if no angle-bracketed URL."""
    start = segment.find("<")
    end = segment.find(">")
    if start == -1 or end == -1 or start >= end:
        return None
    return segment[start + 1 : end].strip()


def _parse_link_next_url(link_header: str | None, base_url: str) -> str | None:
    """
    Parse the Link response header and return the full URL for rel="next", or None.
    Handles relative paths (resolved against base_url) and absolute URLs.
    """
    if not link_header or not link_header.strip():
        return None
    base_url = base_url.rstrip("/")
    for segment in link_header.split(","):
        segment = segment.strip()
        if 'rel="next"' not in segment and "rel='next'" not in segment:
            continue
        url = _url_from_link_segment(segment)
        if not url:
            continue
        if url.startswith("http://") or url.startswith("https://"):
            return url
        return base_url + (url if url.startswith("/") else "/" + url)
    return None


def _job_started_at(job: dict[str, Any]) -> datetime:
    """Parse startedAt from a job dict for comparison."""
    raw = job.get("startedAt", "1970-01-01")
    return datetime.fromisoformat(str(raw).replace("T", " ")[:19])


def _earliest_allowed_date(days: int) -> datetime:
    """Return the cutoff datetime: jobs started before this are outside the window."""
    return datetime.now() - timedelta(days=days)


def _job_passes_filters(
    job: Any, earliest_allowed: datetime
) -> tuple[bool, bool]:
    """
    Decide whether to yield this job and whether to stop pagination.

    Returns:
        - (should_yield, should_stop_pagination)
        - should_yield: include this job (must be success and within window).
        - should_stop_pagination: seen a job before window; stop fetching more pages.
    """
    if not isinstance(job, dict):
        return (False, False)

    try:
        started_at = _job_started_at(job)
    except (ValueError, TypeError):
        return (False, False)

    is_before_window = started_at < earliest_allowed
    is_success = job.get("status") == "success"

    should_yield = is_success and not is_before_window
    should_stop = is_before_window

    return (should_yield, should_stop)


def _get_next_page_url(
    response: Any,
    base_url: str,
    org: str,
    repo: str,
    limit: int,
) -> str | None:
    """Get the next page URL from Link header or X-Next-Cursor."""
    base_url = base_url.rstrip("/")
    next_url = _parse_link_next_url(response.headers.get("Link"), base_url)
    if next_url:
        return next_url
    next_cursor = response.headers.get("X-Next-Cursor")
    if next_cursor:
        return (
            f"{base_url}/api/v1/repos/{org}/{repo}/-/jobs?limit={limit}&cursor={next_cursor}"
        )
    return None


def _fetch_one_jobs_page(handler: RestApiHandler, url: str) -> tuple[list[dict[str, Any]], Any | None]:
    """
    GET one page of jobs; return (list of job dicts, response or None).
    On request/parse error returns ([], None).
    """
    try:
        response = handler.get_url(url=url)
    except (RequestException, ValueError) as err:
        logger.error(f"Failed to fetch repo jobs for url {url}: {err}")
        return ([], None)
    try:
        data = response.json()
    except ValueError as err:
        logger.error(f"Invalid JSON from repo jobs url {url}: {err}")
        return ([], None)
    jobs = data if isinstance(data, list) else []
    return (jobs, response)


def iter_success_jobs_in_window(
    base_url: str,
    api_secret: str,
    org: str,
    repo: str,
    first_time_fetch_window_days: int,
    *,
    limit: int = MAX_JOBS_PER_PAGE,
) -> Iterator[dict[str, Any]]:
    """
    Generator that yields successful jobs within the first-time fetch window, from the
    repo jobs API. Follows cursor-based pagination (Link / X-Next-Cursor) and stops
    when the oldest job on a page is before the window. Only success + in-window jobs
    are yielded.
    """
    base_url = base_url.rstrip("/")
    url = f"{base_url}/api/v1/repos/{org}/{repo}/-/jobs?limit={limit}"
    earliest_allowed = _earliest_allowed_date(first_time_fetch_window_days)
    handler = RestApiHandler(auth_header=f"Bearer {api_secret}")

    while True:
        jobs, response = _fetch_one_jobs_page(handler, url)
        if response is None:
            return
        should_stop = False
        for job in jobs:
            should_yield, stop = _job_passes_filters(job, earliest_allowed)
            if stop:
                should_stop = True
            if should_yield:
                yield job
        if should_stop:
            logger.debug(
                f"Stopping pagination: job on page is before window ({first_time_fetch_window_days} days)",
                first_time_fetch_window_days,
            )
            return
        next_url = _get_next_page_url(response, base_url, org, repo, limit)
        if not next_url:
            break
        url = next_url


def fetch_repo_jobs(
    base_url: str,
    api_secret: str,
    org: str,
    repo: str,
    first_time_fetch_window_days: int,
    *,
    limit: int = MAX_JOBS_PER_PAGE,
) -> list:
    """GET .../repos/{org}/{repo}/-/jobs with pagination; return success jobs within window."""
    logger.info(f"Fetching all jobs for repo {repo} (paginated)")
    try:
        return list(
            iter_success_jobs_in_window(
                base_url,
                api_secret,
                org,
                repo,
                first_time_fetch_window_days,
                limit=limit,
            )
        )
    except Exception as err:
        logger.error(f"Failed to fetch repo jobs: {err}")
        return []


def fetch_logs_for_job_ndjson(
    job_id: str,
    base_url: str,
    api_secret: str,
    org: str,
    repo: str,
) -> str | None:
    """GET .../repos/{org}/{repo}/-/jobs/{job_id} and return response text (NDJSON)."""
    base_url = base_url.rstrip("/")
    url = f"{base_url}/api/v1/repos/{org}/{repo}/-/jobs/{job_id}"
    logger.info(f"Fetching job log (ndjson) for {org}/{repo} job {job_id}")
    try:
        handler = RestApiHandler(auth_header=f"Bearer {api_secret}")
        response = handler.get_url(url=url)
        return response.text or ""
    except RequestException as err:
        logger.error(f"Failed to fetch ndjson from {url}: {err}")
        return None
