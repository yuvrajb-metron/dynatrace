"""
Parse Renovate CE job log NDJSON into structured events for Vulnerability Finding and Scan mapping.
Extracts: vulnerability GHSA log lines, packageFiles event, branches info event, repository started/finished.
"""

import json
from dataclasses import dataclass
from dynatrace_extension.sdk.extension import extension_logger as logger

# Message patterns used in Renovate job logs
MSG_VULNERABILITY_GHSA_PREFIX = "Vulnerability GHSA"
MSG_BRANCHES_INFO_EXTENDED = "branches info extended"
MSG_PACKAGE_FILES_WITH_UPDATES = "packageFiles with updates"
MSG_REPOSITORY_STARTED = "Repository started"
MSG_REPOSITORY_FINISHED = "Repository finished"


@dataclass
class ParsedJobLog:
    """
    Structured result of parsing one job log NDJSON response.
    """

    vulnerability_finding_logs: list[dict]
    branches_info_event: dict
    package_files_event: dict
    repository_started_events: dict
    repository_finished_events: dict


def classify_job_logs(ndjson_text: str) -> ParsedJobLog:
    """
    Parse Renovate CE job log NDJSON into structured events in a single pass.

    Returns a ParsedJobLog containing:
    - vulnerability_finding_logs: list of raw log objects (msg starts with "Vulnerability GHSA...")
    - branches_info_event: single object with msg "branches info extended", or None
    - package_files_event: single object with msg "packageFiles with updates", or None
    - repository_started_events: single object with msg "Repository started", or None
    - repository_finished_events: single object with msg "Repository finished", or None
    """
    vulnerability_finding_logs: list[dict] = []
    branches_info_event: dict = {}
    package_files_event: dict = {}
    repository_started_events: dict = {}
    repository_finished_events: dict = {}
    lines_parsed = 0

    for line_number, line in enumerate(ndjson_text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            log_entry = json.loads(line)
        except json.JSONDecodeError as err:
            logger.debug("Line %d: invalid JSON, skipping: %s", line_number, err)
            continue
        if not isinstance(log_entry, dict):
            logger.debug("Line %d: skipped (not a JSON object)", line_number)
            continue
        lines_parsed += 1
        msg = log_entry.get("msg", "")

        if msg.startswith(MSG_VULNERABILITY_GHSA_PREFIX):
            vulnerability_finding_logs.append(log_entry)
        elif msg == MSG_BRANCHES_INFO_EXTENDED:
            branches_info_event = log_entry
        elif msg == MSG_PACKAGE_FILES_WITH_UPDATES:
            package_files_event = log_entry
        elif msg == MSG_REPOSITORY_STARTED:
            repository_started_events = log_entry
        elif msg == MSG_REPOSITORY_FINISHED:
            repository_finished_events = log_entry

    logger.info(f"Parsed {lines_parsed} NDJSON line(s); extracted {len(vulnerability_finding_logs)} vulnerability finding(s), "
        f"branchesInfo={branches_info_event is not None}, packageFiles={package_files_event is not None}, "
        f"repositoryStarted={repository_started_events is not None}, repositoryFinished={repository_finished_events is not None}",
    )
    return ParsedJobLog(
        vulnerability_finding_logs=vulnerability_finding_logs,
        branches_info_event=branches_info_event,
        package_files_event=package_files_event,
        repository_started_events=repository_started_events,
        repository_finished_events=repository_finished_events,
    )
