"""
Poll Renovate CE for job logs, parse findings, and push events to Dynatrace.
"""

from ..clients import fetch_logs_for_job_ndjson, fetch_repo_jobs
from ..events import EventsForIngestBuilder
from ..ingest import push_events_to_dynatrace
from ..parsing import process_job_log_ndjson
from ..storage import JobDatabase
from dynatrace_extension.sdk.extension import extension_logger as logger


def _get_new_success_jobs(
    base_url: str, api_secret: str, org: str, repo: str, firstTimeFetchWindow: int
) -> list[dict]:
    """Fetch jobs from API and return only new successful ones (not yet in DB)."""
    jobs_from_api = fetch_repo_jobs(
        base_url, api_secret, org, repo,
        first_time_fetch_window_days=firstTimeFetchWindow,
    )
    with JobDatabase() as db:
        return db.sync_success_jobs(jobs_from_api, org, repo)


def _count_finding_and_scan(events: list) -> tuple[int, int]:
    """Return (vulnerability_finding_count, vulnerability_scan_count) from event list."""
    finding_count = sum(
        1 for ev in events if isinstance(ev, dict) and ev.get("event.type") == "VULNERABILITY_FINDING"
    )
    scan_count = sum(
        1 for ev in events if isinstance(ev, dict) and ev.get("event.type") == "VULNERABILITY_SCAN"
    )
    return (finding_count, scan_count)

def _build_events_for_job(
    job: dict,
    org: str,
    repo: str,
    base_url: str,
    api_secret: str,
) -> list:
    """
    Fetch job log, parse, and build events for one job. Returns the events list
    (no Dynatrace push). Logs per-job counts.
    """
    logger.info(
        "New successful job found for %s/%s: %s started at %s",
        org, repo, job["job_id"], job["started"],
    )
    ndjson_text = fetch_logs_for_job_ndjson(
        job["job_id"],
        base_url,
        api_secret,
        job["org_name"],
        job["repo_name"],
    )
    if ndjson_text is None:
        logger.warning(
            "No job log content for %s/%s job %s; skipping.",
            org, repo, job["job_id"],
        )
        return []
    ghsa_to_osv, repository_scan = process_job_log_ndjson(ndjson_text, org, repo)
    events = EventsForIngestBuilder(ghsa_to_osv, repository_scan).build()
    finding_count, scan_count = _count_finding_and_scan(events)
    logger.info(
        "Found %d vulnerability findings and %d vulnerability scans for %s/%s",
        finding_count, scan_count, org, repo,
    )
    return events


def poll_and_ingest_org_repos(
    org: str,
    repos: list[str],
    base_url: str,
    api_secret: str,
    dynatrace_url: str,
    security_events_interface,
    firstTimeFetchWindow: int
) -> None:
    """
    For one org, poll its repos: fetch new job logs, parse findings, build events,
    and ingest to Dynatrace. Exceptions are logged and re-raised.
    """
    for repo in repos:
        try:
            new_jobs = _get_new_success_jobs(base_url, api_secret, org, repo, firstTimeFetchWindow)
            all_events = []
            for job in new_jobs:
                events = _build_events_for_job(job, org, repo, base_url, api_secret)
                all_events.extend(events)
            if all_events and security_events_interface:
                try:
                    push_events_to_dynatrace(
                        dynatrace_url, all_events, security_events_interface,
                    )
                except Exception as err:
                    logger.error(
                        "Failed to push events to Dynatrace for %s/%s: %s",
                        org, repo, err,
                    )
        except Exception as err:
            logger.error("Failed to fetch job logs for %s/%s: %s", org, repo, err)
            raise

