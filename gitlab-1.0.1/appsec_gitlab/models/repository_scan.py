"""
Model for one GitLab security CI job run used to emit ``VULNERABILITY_SCAN``.

Responsibility:
    Capture scan metadata (ids, timestamps, branch, group/project, scanner product name)
    from raw API dicts. Report type is inferred from the job name.
"""

from __future__ import annotations

from ..utils.constants import DEFAULT_SCAN_PRODUCT_NAME, PRODUCT_VENDOR, REPORT_TYPE_BY_JOB_HINT
from ..utils.helpers import get_scanner_external_id, make_json_safe
from .gitlab_objects import GitLabGroup, GitLabJob, GitLabPipeline, GitLabProject


class RepositoryScan:
    """
    Scan-level context for one dependency or container scanning job.
    """

    def __init__(self, group: dict, project: dict, job: dict, pipeline: dict) -> None:
        """
        Args:
            group, project, job, pipeline: Raw GitLab REST objects for the job’s context.
        """
        self.group = GitLabGroup(group)
        self.project = GitLabProject(project)
        self.job = GitLabJob(job)
        self.pipeline = GitLabPipeline(pipeline)
        self.scan_id = self.job.id
        job_name = self.job.name if isinstance(self.job.name, str) else None
        self.report_type = REPORT_TYPE_BY_JOB_HINT.get(job_name.lower()) if job_name else None
        self.repository_name = self.project.path_with_namespace or self.project.name
        self.scan_name = self._build_scan_name()
        self.scan_status = self.job.status
        # GitLab sometimes omits started_at/finished_at; align with finding emit rules so scan + findings pair.
        self.scan_time_started = self.job.started_at or self.job.created_at
        self.scan_time_completed = (
            self.job.finished_at or self.job.started_at or self.job.created_at
        )
        # Job-name hints only: built from job/project/pipeline without a vulnerability, so GraphQL
        # ``scanner.externalId`` (see ``VulnerabilityDetails.product_name``) is not available here.
        # Artifact ``VULNERABILITY_SCAN`` payloads use the lead finding's ``product_name`` instead;
        # ``build_scan_event`` (repo-level scan) still uses ``RepositoryScan.product_name``.
        self.product_name = get_scanner_external_id(self.job.name) or DEFAULT_SCAN_PRODUCT_NAME
        self.product_vendor = PRODUCT_VENDOR
        self.original_content = make_json_safe(self.job.raw)

    def _build_scan_name(self) -> str | int | None:
        """
        Returns:
            Human-readable scan name: ``{repo}:{job_name}:{job_id}`` when possible.
        """
        repo = self.repository_name.strip() if isinstance(self.repository_name, str) else None
        if self.job.name and self.job.id is not None:
            base = f"{self.job.name}:{self.job.id}"
            return f"{repo}:{base}" if repo else base
        return self.job.name or self.job.id

    def has_required_mapping_values(self) -> bool:
        """
        Returns:
            True when all mandatory scan event fields are non-empty.
        """
        required_values = [
            self.scan_id,
            self.scan_name,
            self.scan_status,
            self.scan_time_started,
            self.scan_time_completed,
            self.product_name,
            self.repository_name,
        ]
        return all(value not in (None, "") for value in required_values)
