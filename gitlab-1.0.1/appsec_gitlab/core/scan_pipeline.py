"""
Partition security CI jobs and scope activation toggles by scan kind (dependency vs container).

When both collection toggles are on, dependency and container jobs are processed in separate
phases with ``enabled_report_types`` narrowed to a single ``CONTAINER_SCANNING`` or
``DEPENDENCY_SCANNING`` value. That keeps pipeline merge logic, findings, and object typing
from mixing across scan kinds.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..utils.constants import (
    CONTAINER_SCANNING,
    DEPENDENCY_SCANNING,
    REPORT_TYPE_BY_JOB_HINT,
)


def infer_job_report_type(job: dict) -> str | None:
    """
    Map a CI job to GitLab security report type from its name hint.

    Matches the default GitLab template job names exactly, then falls back to substring
    checks so renamed jobs (e.g. ``security:dependency_scanning``) still classify.

    Args:
        job: Raw GitLab job dict (uses ``name``, e.g. ``dependency_scanning``).

    Returns:
        ``DEPENDENCY_SCANNING``, ``CONTAINER_SCANNING``, or ``None`` if the name does not match.
    """
    name = job.get("name")
    hint = name.lower() if isinstance(name, str) and name else None
    if not hint:
        return None
    direct = REPORT_TYPE_BY_JOB_HINT.get(hint)
    if direct:
        return direct
    # Custom job names often keep the template token as a substring.
    if "container_scanning" in hint:
        return CONTAINER_SCANNING
    if "dependency_scanning" in hint:
        return DEPENDENCY_SCANNING
    return None


def partition_security_jobs_by_report_type(
    jobs: list[dict],
) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Split jobs into dependency-scan, container-scan, and unrecognized buckets.

    Args:
        jobs: New jobs returned for the project (typically security job names only).

    Returns:
        ``(dependency_jobs, container_jobs, unknown_jobs)``. Unknown names are processed
        in ``collect_project_events`` with full ``enabled_report_types`` (legacy behavior).
    """
    dependency_jobs: list[dict] = []
    container_jobs: list[dict] = []
    unknown_jobs: list[dict] = []
    for job in jobs:
        rt = infer_job_report_type(job)
        if rt == DEPENDENCY_SCANNING:
            dependency_jobs.append(job)
        elif rt == CONTAINER_SCANNING:
            container_jobs.append(job)
        else:
            unknown_jobs.append(job)
    return dependency_jobs, container_jobs, unknown_jobs


@dataclass(frozen=True)
class ReportTypeActivationScope:
    """
    Derives per-phase ``enabled_report_types`` from activation (dependency / container toggles).

    Use :meth:`scope_for_dependency_phase` and :meth:`scope_for_container_phase` when calling
    :func:`core.polling.build_job_models` so each job is evaluated only against its own kind.
    """

    enabled_report_types: frozenset[str]

    @classmethod
    def from_set(cls, enabled: set[str]) -> ReportTypeActivationScope:
        return cls(frozenset(enabled))

    def scope_for_dependency_phase(self) -> set[str]:
        """Report types allowed when processing dependency-scanning jobs only."""
        return set(self.enabled_report_types & {DEPENDENCY_SCANNING})

    def scope_for_container_phase(self) -> set[str]:
        """Report types allowed when processing container-scanning jobs only."""
        return set(self.enabled_report_types & {CONTAINER_SCANNING})

    def run_dependency_phase(self) -> bool:
        return bool(self.scope_for_dependency_phase())

    def run_container_phase(self) -> bool:
        return bool(self.scope_for_container_phase())
