"""
Build Dynatrace **log** payloads for GitLab audit events (not security ingest).

Each payload uses fields such as ``level``, ``log.source``, ``content``, ``audit.*``,
and ``dt.extension.name``. The extension runtime ingests these via
``Extension.report_log_event`` (no direct HTTP log URL in this codebase).

**Notebooks:** Prefer filtering on ``log.source == "GitLab"`` (see ``PRODUCT_VENDOR``) and
``dt.extension.name`` equal to ``constants.DT_EXTENSION_NAME`` (same value as
``extension/extension.yaml`` ``name``). If logs do not appear, the extension id mismatch
was a common cause before ``DT_EXTENSION_NAME`` was aligned with the manifest.
"""

from __future__ import annotations

import json

from ..models import AuditLogDetails
from ..utils.helpers import make_json_safe

# Allowed keys for group-scoped audit log events (no gitlab.project.*).
AUDIT_LOG_KEYS_GROUP = frozenset({
    "level",
    "log.source",
    "content",
    "audit.identity",
    "audit.action",
    "audit.time",
    "audit.result",
    "audit.status",
    "dt.extension.name",
    "gitlab.audit.id",
    "object.id",
    "object.type",
    "object.name",
    "gitlab.group.id",
    "gitlab.group.name",
})
# Project-scoped events add project id and name.
AUDIT_LOG_KEYS_PROJECT = AUDIT_LOG_KEYS_GROUP | frozenset({"gitlab.project.id", "gitlab.project.name"})


def build_audit_log_event(audit_log_details: AuditLogDetails) -> dict | None:
    """
    Map ``AuditLogDetails`` to a single flat log dict for the Dynatrace SDK.

    Args:
        audit_log_details: Model wrapping one GitLab audit API row plus scope context.

    Returns:
        Filtered dict (only allowed keys, no ``None`` values), or ``None`` if required
        fields are missing.
    """
    if not audit_log_details.has_required_mapping_values():
        return None
    details = audit_log_details
    allowed = AUDIT_LOG_KEYS_PROJECT if details.project else AUDIT_LOG_KEYS_GROUP
    payload = {
        "level": details.loglevel,
        "log.source": details.log_source,
        "content": json.dumps(make_json_safe(details.content)),
        "audit.identity": details.identity,
        "audit.action": details.action,
        "audit.time": details.time,
        "audit.result": details.result,
        "audit.status": details.status,
        "dt.extension.name": details.dt_extension_name,
        "gitlab.audit.id": details.audit_id,
        "object.id": details.object_id,
        "object.type": details.object_type,
        "object.name": details.object_name,
    }
    if details.group:
        payload["gitlab.group.id"] = details.group.id
        payload["gitlab.group.name"] = details.group.full_path or details.group.name
    if details.project:
        payload["gitlab.project.id"] = details.project.id
        payload["gitlab.project.name"] = (
            details.project.path_with_namespace or details.project.name
        )
    filtered = {k: v for k, v in payload.items() if k in allowed and v is not None}
    # Log ingest / Grail typically expect string-typed attributes; mixed int/str can fail indexing.
    return {key: _stringify_log_attribute(val) for key, val in filtered.items()}


def _stringify_log_attribute(value: object) -> str:
    """Coerce log event field values to strings for Dynatrace log ingest compatibility."""
    if value is None:
        raise ValueError("None value should be filtered before log attribute stringification")
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(make_json_safe(value), ensure_ascii=False)
    return str(value)
