"""Parse job log NDJSON and build GHSA/OSV map and repository scan model."""

from ..core.osv import build_ghsa_to_osv_map
from ..models import OsvEnrichedInfo, RepositoryScan
from .job_log_classifier import classify_job_logs
from dynatrace_extension.sdk.extension import extension_logger as logger


def process_job_log_ndjson(
    ndjson_text: str,
    org: str,
    repo: str,
) -> tuple[dict[str, list[OsvEnrichedInfo]], RepositoryScan | None]:
    """
    Parse job log NDJSON into structured events (vulnerability findings, scan lifecycle, etc.)
    and log extraction counts. Returns (ghsa_to_osv, repository_scan) for event building.
    """
    parsed_log = classify_job_logs(ndjson_text)
    logger.debug(
        "Parsed job log actual values: vulnerability_finding_logs=%s, "
        "branches_info_event=%s, package_files_event=%s, "
        "repository_started_events=%s, repository_finished_events=%s",
        parsed_log.vulnerability_finding_logs,
        parsed_log.branches_info_event,
        parsed_log.package_files_event,
        parsed_log.repository_started_events,
        parsed_log.repository_finished_events,
    )

    ghsa_to_osv: dict[str, list[OsvEnrichedInfo]] = {}

    if parsed_log.vulnerability_finding_logs:
        ghsa_to_osv = build_ghsa_to_osv_map(
            parsed_log.vulnerability_finding_logs,
            parsed_log.branches_info_event,
            parsed_log.package_files_event,
        )
    else:
        logger.info(f"No 'Vulnerability GHSA' log lines in job output for {org}/{repo}; no finding events will be generated. "
            "Ensure the repo has vulnerability alerts and that the Renovate CE job produced those log lines.")

    repository_scan = None
    if parsed_log.repository_started_events and parsed_log.repository_finished_events:
        repository_scan = RepositoryScan(
            parsed_log.repository_started_events,
            parsed_log.repository_finished_events,
        )
        logger.info("Repository scan model: %s", repository_scan)

    return (ghsa_to_osv, repository_scan)
