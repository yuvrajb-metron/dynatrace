"""
Model for one GitLab audit API row plus optional group/project scope.

Responsibility:
    Normalize identity, action, timestamps, and object fields for ``build_audit_log_event``.
    ``has_required_mapping_values`` gates incomplete rows.
"""

from __future__ import annotations

from ..utils.constants import DT_EXTENSION_NAME, EVENT_TYPE_LOG, PRODUCT_VENDOR
from .gitlab_objects import GitLabGroup, GitLabProject


class AuditLogDetails:
    """
    Intermediate representation for one audit log line sent via ``report_log_event``.
    """

    def __init__(
        self,
        group: dict | None = None,
        project: dict | None = None,
        audit_log: dict | None = None,
    ) -> None:
        """
        Args:
            group: Raw group dict (for ``gitlab.group.*`` and fallbacks).
            project: Raw project dict when the event is project-scoped; ``None`` for group-only audits.
            audit_log: Single item from the GitLab audit events API.
        """
        self.group = GitLabGroup(group or {}) if group else None
        self.project = GitLabProject(project or {}) if project else None
        self.audit_log = audit_log or {}
        self.details = self.audit_log.get("details") or {}

        self.action = (
            self.details.get("event_name") or self.audit_log.get("event_type")
        )
        self.identity = (
            self.details.get("author_email") or self.details.get("author_name")
        )
        self.result = "Succeeded"
        self.status = "Succeeded"
        self.time = self.audit_log.get("created_at")
        self.content = self.audit_log
        self.log_source = PRODUCT_VENDOR
        self.event_type = EVENT_TYPE_LOG
        self.audit_id = self.audit_log.get("id")
        self.loglevel = "INFO"
        self.dt_extension_name = DT_EXTENSION_NAME
        self.object_id = self.audit_log.get("entity_id")
        self.object_type = self.audit_log.get("entity_type")
        self.object_name = self.details.get("entity_path")

        if self.project and not self.object_name:
            self.object_name = self.project.path_with_namespace or self.project.name
        if self.group and not self.object_name:
            self.object_name = self.group.full_path or self.group.name

    def has_required_mapping_values(self) -> bool:
        """
        Returns:
            True if action, identity, time, content, and log source are all non-empty.
        """
        required_values = [
            self.action,
            self.identity,
            self.time,
            self.content,
            self.log_source,
        ]
        return all(value not in (None, "") for value in required_values)

    def __repr__(self) -> str:
        scope = None
        if self.project:
            scope = self.project.path_with_namespace or self.project.name
        elif self.group:
            scope = self.group.full_path or self.group.name
        return f"AuditLogDetails(scope={scope!r}, action={self.action!r}, time={self.time!r})"
