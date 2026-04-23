"""Job filtering helpers: success status and first-time fetch window."""

from datetime import datetime, timedelta
from typing import Any, Iterable


def filter_success_jobs(api_data: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return only jobs with status == 'success'."""
    return [
        job
        for job in api_data
        if isinstance(job, dict) and job.get("status") == "success"
    ]


def filter_by_initial_window(
    jobs: list[dict[str, Any]], days_limit: int
) -> list[dict[str, Any]]:
    """
    Filter jobs to those started within the last days_limit days.
    Use to prevent processing ancient history on the first run.
    """
    earliest_allowed_date = datetime.now() - timedelta(days=days_limit)
    return [
        job
        for job in jobs
        if datetime.fromisoformat(
            job.get("startedAt", "1970-01-01").replace("T", " ")[:19]
        )
        >= earliest_allowed_date
    ]
