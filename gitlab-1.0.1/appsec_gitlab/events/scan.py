"""
Build Dynatrace ``VULNERABILITY_SCAN`` events from ``RepositoryScan`` and helpers.

**Exports**

* :func:`build_scan_event` — Repository-wide scan for one CI job; payload keys in ``SCAN_KEYS``.
* :func:`build_artifact_level_scan_event` — One ``VULNERABILITY_SCAN`` per artifact (code or
  container image); ``object.*`` matches the lead finding; per-artifact ``scan.id`` /
  ``scan.name`` are supplied by the caller; keys in ``ARTIFACT_SCAN_KEYS`` (adds ``artifact.*``,
  ``os.*``).

Callers (e.g. :class:`~appsec_gitlab.events.security_events_builder.SecurityEventsForIngestBuilder`)
emit one such scan per distinct artifact group, then findings that reference the same ``scan.*``.
"""

from __future__ import annotations

import json

from ..models import DynatraceSecurityEvent, RepositoryScan, VulnerabilityDetails
from ..utils.constants import CONTAINER_IMAGE, CONTAINER_SCANNING, EVENT_PROVIDER, EVENT_TYPE_VULNERABILITY_SCAN
from ..utils.helpers import make_json_safe
from .vulnerability_finding import (
    _ensure_string_list,
    artifact_fields_from_details,
    canonical_object_identity_for_events,
)

# Dynatrace flat-field allow-list for repository-level ``VULNERABILITY_SCAN`` payloads.
# Only keys in this set are emitted (after filtering ``None``).
SCAN_KEYS = frozenset({
    "event.provider",
    "event.type",
    "event.description",
    "event.original_content",
    "object.type",
    "object.id",
    "object.name",
    "product.vendor",
    "product.name",
    "scan.id",
    "scan.name",
    "scan.status",
    "scan.time.started",
    "scan.time.completed",
    "gitlab.project.id",
    "gitlab.project.name",
    "gitlab.project.branch",
    "gitlab.group.id",
    "gitlab.group.name",
    # Container scanning: ``container_image.*`` copied from ``container_image_finding`` when set.
    "container_image.digest",
    "container_image.registry",
    "container_image.repository",
    "container_image.tags",
})

# Artifact-only scans: same as ``SCAN_KEYS`` plus ``artifact.*`` and (for container findings) ``os.*``.
ARTIFACT_SCAN_KEYS = SCAN_KEYS | {
    "artifact.filename",
    "artifact.path",
    "artifact.name",
    "artifact.repository",
    "os.name",
    "os.version",
    "os.type",
}


class ScanEventBuilder:
    """
    Assembles the inner dict for a **repository-level** ``VULNERABILITY_SCAN`` (one security job).

    **Use** — Instantiate and call :meth:`build`; normally via :func:`build_scan_event`, which
    wraps the result in :class:`~appsec_gitlab.models.dynatrace_security_event.DynatraceSecurityEvent`.

    **Output** — Project path in ``object.*``, job id/name in ``scan.*``, GitLab scope fields,
    and for container jobs optional ``container_image.*`` copied from a finding.
    """

    def __init__(
        self,
        repository_scan: RepositoryScan,
        scan_object_target: str | None = None,
        *,
        container_image_finding: VulnerabilityDetails | None = None,
    ) -> None:
        """
        Store inputs for :meth:`build`.

        Args:
            repository_scan:
                Scan model for the job (group, project, pipeline, job, product, timestamps).
            scan_object_target:
                If set, overrides ``object.id`` and ``object.name``; otherwise the project
                path (``repository_scan.repository_name``) is used so the event describes
                the whole repository, not one lockfile or image.
            container_image_finding:
                When ``repository_scan`` is a container-scanning job, a finding from the same
                job whose ``container_image_digest``, ``registry``, ``repository``, and ``tags``
                are copied onto this scan event. Pass ``None`` for dependency-scanning jobs or
                when no finding is available (no ``container_image.*`` on the scan).
        """
        self.repository_scan = repository_scan
        self.scan_object_target = scan_object_target
        self.container_image_finding = container_image_finding

    def build(self) -> dict:
        """
        Construct the filtered payload dict for one repository scan event.

        Returns:
            Mapping of Dynatrace field names (e.g. ``event.type``, ``scan.id``) to values.
            Only keys present in ``SCAN_KEYS`` are included; values equal to ``None`` are dropped.

        Note:
            Does not validate ``repository_scan``; :func:`build_scan_event` returns ``None`` if
            ``has_required_mapping_values()`` fails before building.
        """
        scan = self.repository_scan
        is_container = scan.report_type == CONTAINER_SCANNING
        object_type = CONTAINER_IMAGE if is_container else "CODE_ARTIFACT"
        # object.id == object.name: project scope by default (repository_name). Optional override only
        # if callers need a non-default target (rare); findings keep artifact-level object.* separately.
        target = self.scan_object_target or scan.repository_name
        object_id = target
        object_name = target
        event_description = f"Scan completed for {scan.repository_name}"
        # original_content: only fields from other APIs (job, project, group)
        original_content = {
            "job": make_json_safe(scan.job.raw),
            "project": make_json_safe(scan.project.raw),
            "group": make_json_safe(scan.group.raw),
        }
        payload = {
            "event.provider": EVENT_PROVIDER,
            "event.type": EVENT_TYPE_VULNERABILITY_SCAN,
            "event.description": event_description,
            "event.original_content": json.dumps(original_content),
            "object.type": object_type,
            "object.id": object_id,
            "object.name": object_name,
            "product.vendor": scan.product_vendor,
            "product.name": scan.product_name,
            "scan.id": scan.scan_id,
            "scan.name": scan.scan_name,
            "scan.status": scan.scan_status,
            "scan.time.started": scan.scan_time_started,
            "scan.time.completed": scan.scan_time_completed,
            "gitlab.project.id": scan.project.id,
            "gitlab.project.name": scan.project.path_with_namespace or scan.project.name,
            "gitlab.project.branch": scan.pipeline.ref,
            "gitlab.group.id": scan.group.id,
            "gitlab.group.name": scan.group.full_path or scan.group.name,
        }
        source_finding = self.container_image_finding
        if is_container and source_finding is not None:
            payload["container_image.digest"] = source_finding.container_image_digest
            payload["container_image.registry"] = source_finding.container_image_registry
            payload["container_image.repository"] = source_finding.repository_path
            payload["container_image.tags"] = _ensure_string_list(source_finding.container_image_tags)
        return {k: v for k, v in payload.items() if k in SCAN_KEYS and v is not None}


def build_scan_event(
    repository_scan: RepositoryScan,
    scan_object_target: str | None = None,
    *,
    container_image_finding: VulnerabilityDetails | None = None,
) -> dict | None:
    """
    Build a single **repository-level** ``VULNERABILITY_SCAN`` ready for Dynatrace ingest.

    This is the primary scan line for a job: it represents scanning the **project/repository**,
    not an individual lockfile or container image (those appear on findings and optional
    artifact-level scans).

    Args:
        repository_scan:
            Job-level model. If :meth:`~RepositoryScan.has_required_mapping_values` is false,
            the function returns ``None`` and no event is built.
        scan_object_target:
            Optional string for ``object.id`` / ``object.name``. Rare; defaults to the project path.
        container_image_finding:
            For **container-scanning** jobs only: any ``VulnerabilityDetails`` from that job used
            to fill ``container_image.digest``, ``registry``, ``repository``, ``tags`` on the scan.
            For **dependency-scanning** jobs, pass ``None`` (ignored).

    Returns:
        A flat ``dict`` suitable for ``push_security_events_to_dynatrace`` (shallow copy via
        :meth:`~appsec_gitlab.models.dynatrace_security_event.DynatraceSecurityEvent.to_ingest_dict`),
        or ``None`` if the scan model is invalid.
    """
    if not repository_scan.has_required_mapping_values():
        return None
    return DynatraceSecurityEvent(
        payload=ScanEventBuilder(
            repository_scan,
            scan_object_target=scan_object_target,
            container_image_finding=container_image_finding,
        ).build()
    ).to_ingest_dict()


def build_artifact_level_scan_event(
    repository_scan: RepositoryScan,
    lead_finding: VulnerabilityDetails,
    *,
    synthetic_scan_id: str | int,
    synthetic_scan_name: str | int | None,
) -> dict | None:
    """
    Build one **artifact-scoped** ``VULNERABILITY_SCAN`` (dependency path or container image).

    ``object.id`` / ``object.name`` and ``product.name`` use the same ``lead_finding`` fields as
    :func:`~appsec_gitlab.events.vulnerability_finding.build_finding_event`. ``scan.id`` /
    ``scan.name`` are the caller-supplied values (typically the job scan id/name) shared with
    findings in that group.

    Args:
        repository_scan:
            Job model (must pass ``has_required_mapping_values``).
        lead_finding:
            Representative ``VulnerabilityDetails`` for this artifact group.
        synthetic_scan_id:
            ``scan.id`` for this artifact scan and its findings (e.g. job id).
        synthetic_scan_name:
            ``scan.name`` for this artifact scan and its findings (e.g. repo:job:name:id).

    Returns:
        Flat ingest ``dict`` filtered by ``ARTIFACT_SCAN_KEYS``, or ``None`` if ``repository_scan``
        is invalid or canonical object identity is empty.
    """
    if not repository_scan.has_required_mapping_values():
        return None
    object_key = canonical_object_identity_for_events(lead_finding)
    if not object_key:
        return None

    scan = repository_scan
    is_container_job = scan.report_type == CONTAINER_SCANNING
    is_container_artifact = lead_finding.object_type == CONTAINER_IMAGE
    original_content = {
        "job": make_json_safe(scan.job.raw),
        "project": make_json_safe(scan.project.raw),
        "group": make_json_safe(scan.group.raw),
    }
    artifact_field_map = artifact_fields_from_details(lead_finding)
    path_hint = artifact_field_map.get("artifact.path") or object_key
    payload = {
        "event.provider": EVENT_PROVIDER,
        "event.type": EVENT_TYPE_VULNERABILITY_SCAN,
        "event.description": f"Scan completed for {object_key}",
        "event.original_content": json.dumps(original_content),
        "object.type": lead_finding.object_type,
        "object.id": object_key,
        "object.name": object_key,
        "product.vendor": scan.product_vendor,
        "product.name": lead_finding.product_name,
        "scan.id": synthetic_scan_id,
        "scan.name": synthetic_scan_name,
        "scan.status": scan.scan_status,
        "scan.time.started": scan.scan_time_started,
        "scan.time.completed": scan.scan_time_completed,
        "gitlab.project.id": scan.project.id,
        "gitlab.project.name": scan.project.path_with_namespace or scan.project.name,
        "gitlab.project.branch": scan.pipeline.ref,
        "gitlab.group.id": scan.group.id,
        "gitlab.group.name": scan.group.full_path or scan.group.name,
        "artifact.filename": artifact_field_map.get("artifact.filename"),
        "artifact.path": artifact_field_map.get("artifact.path") or path_hint,
        "artifact.name": artifact_field_map.get("artifact.name"),
        "artifact.repository": artifact_field_map.get("artifact.repository"),
        "os.name": lead_finding.os_name,
        "os.version": lead_finding.os_version,
        "os.type": lead_finding.os_type,
    }
    if is_container_job and is_container_artifact:
        payload["container_image.digest"] = lead_finding.container_image_digest
        payload["container_image.registry"] = lead_finding.container_image_registry
        payload["container_image.repository"] = (
            lead_finding.repository_path if is_container_artifact else None
        )
        payload["container_image.tags"] = _ensure_string_list(lead_finding.container_image_tags)
    filtered = {k: v for k, v in payload.items() if k in ARTIFACT_SCAN_KEYS and v is not None}
    return DynatraceSecurityEvent(payload=filtered).to_ingest_dict()
