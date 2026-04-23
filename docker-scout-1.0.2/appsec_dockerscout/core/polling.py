"""
Core orchestration: Docker Hub discovery, Scout run per image, parse, build events, push to Dynatrace.

Single entrypoint run_discovery_and_ingest: no storage, no job DB.
"""

from datetime import datetime, timezone
from typing import Any, List, Optional, Set, cast

from dynatrace_extension import StatusValue

from appsec_dockerscout.clients import DockerHubClient, DockerHubClientError
from appsec_dockerscout.core.scout_runner import (
    docker_login,
    docker_scout_cves,
    docker_scout_sbom,
)
from appsec_dockerscout.events import (
    build_vulnerability_finding,
    build_vulnerability_scan,
    make_scan_id,
)
from appsec_dockerscout.ingest.dynatrace import push_events_to_dynatrace
from appsec_dockerscout.models import ImageRef, ImageMetadata
from appsec_dockerscout.parsing import parse_sarif, parse_sbom
from appsec_dockerscout.utils.repo_filters import apply_repo_filter
from dynatrace_extension.sdk.extension import extension_logger as logger

# In-process only: ``org/repo:tag`` strings already scanned with docker scout in this
# extension process. Cleared on restart. Skips duplicate scout work between polls.
_scanned_image_keys: Set[str] = set()

# Push vulnerability events in small batches to limit peak memory (full list per image).
INGEST_EVENTS_BATCH_SIZE = 500


def _add_multi_status(multi_status: Optional[Any], value: Any, message: str) -> None:
    if multi_status is not None:
        multi_status.add_status(value, message)


def _discover_hub_images(
    username: str,
    password: str,
    org_filter: Optional[List[str]],
    multi_status: Optional[Any],
    hub_activity_lookback_hours: int,
) -> Optional[List[ImageRef]]:
    """
    Log into Docker Hub and list images to scan.

    On API/login failure, records a generic error on ``multi_status`` and returns ``None``.

    Args:
        username: Docker Hub username.
        password: Docker Hub password or PAT.
        org_filter: If set, restrict discovery to these organization names.
        multi_status: Optional extension ``MultiStatus`` for UI reporting.
        hub_activity_lookback_hours: Only repos/tags whose Hub ``last_updated`` /
            ``tag_last_pushed`` fall within this many hours (ending at discovery time).

    Returns:
        Discovered ``ImageRef`` list, or ``None`` if discovery failed.
    """
    try:
        hub = DockerHubClient(username=username, password=password)
        hub.login()
        logger.debug("Docker Hub login succeeded.")
        return hub.discover_images(
            org_filter=org_filter,
            hub_activity_lookback_hours=hub_activity_lookback_hours,
        )
    except DockerHubClientError as e:
        logger.warn("DEC:1F5 Docker Hub API image discovery failure issue");
        _add_multi_status(
            multi_status,
            StatusValue.GENERIC_ERROR,
            f"DEC:1F5 Docker Hub API image discovery failure issue: {e}",
        )
        return None


def _filter_discovered_images(
    images: List[ImageRef],
    all_repos_in_orgs: bool,
    repo_list: Optional[List[str]],
) -> List[ImageRef]:
    """
    Optionally narrow the discovered image list using repository filters.

    When ``all_repos_in_orgs`` is False and ``repo_list`` is non-empty, applies
    ``apply_repo_filter``; otherwise returns the same list. Logs counts before and after.

    Args:
        images: Images returned from Hub discovery.
        all_repos_in_orgs: If False, ``repo_list`` may filter which repos are kept.
        repo_list: Org or org/repo patterns when filtering is enabled.

    Returns:
        Possibly filtered list (may be empty).
    """
    logger.debug(
        f"Discovered {len(images)} image(s) before repo filter. images={images}"
    )
    if not all_repos_in_orgs and repo_list:
        images = apply_repo_filter(images, repo_list)
        logger.debug(f"After repo filter: {len(images)} image(s).")
    return images


def _ensure_scout_docker_login(
    username: str,
    password: str,
    multi_status: Optional[Any],
) -> bool:
    """
    Run ``docker login`` so the local engine can pull images for Docker Scout.

    On failure, logs a warning, appends a truncated stderr snippet to ``multi_status``,
    and returns False.

    Args:
        username: Registry username (same Hub credentials as discovery).
        password: Registry password or PAT.
        multi_status: Optional extension ``MultiStatus`` for UI reporting.

    Returns:
        True if login succeeded; False otherwise.
    """
    login_result = docker_login(username, password)
    if not login_result.success:
        logger.warning(f"docker login failed: {login_result.stderr}")
        err_tail = (login_result.stderr or "").strip()
        if len(err_tail) > 400:
            err_tail = err_tail[:400] + "…"
        _add_multi_status(
            multi_status,
            StatusValue.GENERIC_ERROR,
            f"docker login failed for Scout: {err_tail or '(no stderr)'}",
        )
        return False
    return True


def _ensure_dynatrace_ingest_ready(
    dynatrace_url: Optional[str],
    security_events_interface: Any,
    multi_status: Optional[Any],
) -> bool:
    """
    Verify Dynatrace ingest URL and authenticated REST interface are configured.

    If either is missing, logs a warning, records a generic error on ``multi_status``,
    and returns False so the caller can skip scanning/ingest.

    Args:
        dynatrace_url: Security events ingest base URL (optional until configured).
        security_events_interface: REST handler used to POST security events.
        multi_status: Optional extension ``MultiStatus`` for UI reporting.

    Returns:
        True when both URL and interface are present; False otherwise.
    """
    if not dynatrace_url or not security_events_interface:
        msg = "Dynatrace URL or security interface not set; skipping ingest."
        logger.warning(msg)
        _add_multi_status(multi_status, StatusValue.GENERIC_ERROR, msg)
        return False
    return True


def _scan_and_push_images(
    images: List[ImageRef],
    scan_started: str,
    dynatrace_url: str,
    security_events_interface: Any,
    multi_status: Optional[Any],
) -> None:
    """
    For each image, run Scout (unless already scanned in-process). Ingest happens inside
    ``_scan_image`` in batches of ``INGEST_EVENTS_BATCH_SIZE``.

    Skips images whose ``full_name`` is in ``_scanned_image_keys`` to avoid duplicate
    Scout work across polls. After a successful scan, adds the key to that set. Scan
    failures are logged and reported on ``multi_status`` without stopping the loop.

    Args:
        images: Images to scan and ingest.
        scan_started: ISO8601 scan start timestamp shared across events in this cycle.
        dynatrace_url: Security events ingest URL (must be non-empty; caller validates).
        security_events_interface: REST handler for posting events.
        multi_status: Optional extension ``MultiStatus`` for per-image failure reporting.

    Returns:
        None.
    """
    logger.debug(f"Scanning {len(images)} image(s); scan_started={scan_started}.")
    for image_ref in images:
        key = image_ref.full_name
        if key in _scanned_image_keys:
            logger.debug(f"Skipping already scanned image (in-memory): {key}")
            continue
        logger.debug(f"Processing image: {key}")
        try:
            event_count = _scan_image(
                image_ref,
                scan_started,
                dynatrace_url,
                security_events_interface,
                multi_status,
            )
            _scanned_image_keys.add(key)
            logger.debug(f"Image {key} produced {event_count} event(s).")
        except Exception as e:
            logger.error(f"Docker Scout scan failed for {image_ref.full_name}: {e}")
            _add_multi_status(
                multi_status,
                StatusValue.GENERIC_ERROR,
                f"Docker Scout scan failed for {image_ref.full_name}: {e}",
            )


def run_discovery_and_ingest(
    username: str,
    password: str,
    dynatrace_url: Optional[str],
    security_events_interface: Any,
    org_filter: Optional[List[str]] = None, 
    all_repos_in_orgs: bool = True,
    repo_list: Optional[List[str]] = None,
    multi_status: Optional[Any] = None,
    hub_activity_lookback_hours: int = 1,
) -> None:
    """
    Discover images via Docker Hub, run Scout per image, build events, push to Dynatrace.

    Images successfully scanned once in this process are remembered in memory; later polls
    skip ``docker scout`` for the same ``org/repo:tag`` until the extension restarts.

    Args:
        username: Docker Hub username.
        password: Docker Hub PAT.
        dynatrace_url: Dynatrace security ingest URL (platform/ingest/v1/security.events).
        security_events_interface: RestApiHandler with Api-Token auth for ingest.
        org_filter: If set, only these org names are used for discovery.
        all_repos_in_orgs: If False, repo_list is applied to filter images.
        repo_list: Repository filter (org or org/repo, partial match) when all_repos_in_orgs is False.
        multi_status: Optional ``MultiStatus``; when set, outcomes are reported for the extension UI.
        hub_activity_lookback_hours: Hub ``last_updated`` / ``tag_last_pushed`` must fall within
            this many hours before discovery time (typically same as ``securityFindingsFrequencyHours``).

    Returns:
        None.
    """
    logger.debug(
        f"run_discovery_and_ingest started: org_filter={org_filter}, "
        f"all_repos_in_orgs={all_repos_in_orgs}, repo_list={repo_list}, "
        f"hub_activity_lookback_hours={hub_activity_lookback_hours}"
    )
    images = _discover_hub_images(
        username,
        password,
        org_filter,
        multi_status,
        hub_activity_lookback_hours,
    )
    if images is None:
        return
    images = _filter_discovered_images(images, all_repos_in_orgs, repo_list)
    if not images:
        logger.debug("No images discovered (or none after filters).")
        _add_multi_status(
            multi_status,
            StatusValue.OK,
            "No Docker Hub images discovered (or none after repository filters).",
        )
        return
    if not _ensure_scout_docker_login(username, password, multi_status):
        return
    if not _ensure_dynatrace_ingest_ready(
        dynatrace_url, security_events_interface, multi_status
    ):
        return
    scan_started = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    _scan_and_push_images(
        images,
        scan_started,
        cast(str, dynatrace_url),
        security_events_interface,
        multi_status,
    )
    _add_multi_status(
        multi_status,
        StatusValue.OK,
        "Docker Scout discovery and ingest cycle completed.",
    )
    logger.debug("run_discovery_and_ingest ended.")


def _scan_image(
    image_ref: ImageRef,
    scan_started: str,
    dynatrace_url: str,
    security_events_interface: Any,
    multi_status: Optional[Any] = None,
) -> int:
    """
    Run ``docker scout cves`` and ``docker scout sbom`` for one image, build Dynatrace
    events, and POST them in batches of ``INGEST_EVENTS_BATCH_SIZE``.

    Args:
        image_ref: Image to scan (org/repo:tag).
        scan_started: ISO8601 scan start time for events.
        dynatrace_url: Security events ingest URL.
        security_events_interface: Authenticated client for POST.
        multi_status: Optional ``MultiStatus``; Scout CLI failures are reported here.

    Returns:
        Number of events produced and pushed (scan event plus findings).
    """
    logger.debug(f"_scan_image started for {image_ref.full_name}")
    cves_result = docker_scout_cves(image_ref, multi_status=multi_status)
    scan_completed = (
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    )
    sbom_result = docker_scout_sbom(image_ref, multi_status=multi_status)
    scan_id = make_scan_id(image_ref)
    logger.debug(f"make_scan_id: image_ref={image_ref.full_name}, scan_id={scan_id}")
    image_meta: Optional[ImageMetadata] = (
        parse_sbom(sbom_result.stdout) if sbom_result.success else None
    )
    if cves_result.success:
        findings, sarif_product_name = parse_sarif(cves_result.stdout)
    else:
        findings, sarif_product_name = [], None

    event_batch_buffer: List[dict] = []

    def append_event_and_push_full_batches(event: dict) -> None:
        event_batch_buffer.append(event)
        while len(event_batch_buffer) >= INGEST_EVENTS_BATCH_SIZE:
            batch_to_send = event_batch_buffer[:INGEST_EVENTS_BATCH_SIZE]
            push_events_to_dynatrace(
                dynatrace_url, batch_to_send, security_events_interface
            )
            del event_batch_buffer[:INGEST_EVENTS_BATCH_SIZE]

    logger.debug(f"Building VULNERABILITY_SCAN event: finding_count={len(findings)}")
    scan_ev = build_vulnerability_scan(
        image_ref,
        image_meta,
        scan_id,
        scan_started,
        scan_completed,
        finding_count=len(findings),
        product_name=sarif_product_name,
    )
    append_event_and_push_full_batches(scan_ev)
    logger.debug(f"Mapping {len(findings)} finding(s) to VULNERABILITY_FINDING events.")
    for idx, f in enumerate(findings):
        logger.debug(
            f"Mapping finding {idx + 1}/{len(findings)}: rule_id={f.rule_id}, "
            f"artifact_path={f.artifact_path or '(empty)'}"
        )
        finding_event = build_vulnerability_finding(
            f, image_ref, image_meta, scan_id, scan_started, scan_completed
        )
        append_event_and_push_full_batches(finding_event)
    if event_batch_buffer:
        push_events_to_dynatrace(
            dynatrace_url, event_batch_buffer, security_events_interface
        )
        event_batch_buffer.clear()
    total_events = 1 + len(findings)
    logger.debug(
        f"_scan_image ended for {image_ref.full_name}: {len(findings)} finding(s), "
        f"{total_events} total event(s) pushed in batches."
    )
    return total_events
