"""
Model for a single repository scan lifecycle (start + end).
Built from repository_started_events and repository_finished_events
"""

import json
class RepositoryScan:
    """
    One repository scan: paired "Repository started" and "Repository finished" events.
    """

    def __init__(self, start_details: dict, end_details: dict):
        """
        start_details: one object from repository_started_events (has logContext, time, ...).
        end_details: one object from repository_finished_events (has logContext, time, result, ...).
        """
        if not isinstance(start_details, dict) or not isinstance(end_details, dict):
            raise TypeError("start_details and end_details must be dicts")
        log_context = (
            start_details.get("logContext") or end_details.get("logContext") or ""
        )
        self.scan_id = log_context
        self.scan_name = log_context
        self.repository_name = (
            start_details.get("repository") or end_details.get("repository") or ""
        )
        self.scan_status = "Completed"
        self.scan_time_started = start_details.get("time")
        self.scan_time_completed = end_details.get("time")
        self.original_content = json.dumps(
            {
                "repository_scan_started_details": start_details,
                "repository_scan_ended_details": end_details,
            },
            default=str,
        )

    def __repr__(self) -> str:
        return (
            f"RepositoryScan(scan_id={self.scan_id!r}, scan_name={self.scan_name!r}, "
            f"repository_name={self.repository_name!r}, scan_status={self.scan_status!r}, "
            f"scan_time_started={self.scan_time_started!r}, scan_time_completed={self.scan_time_completed!r})"
        )
