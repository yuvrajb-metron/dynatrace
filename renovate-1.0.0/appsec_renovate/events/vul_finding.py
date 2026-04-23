"""Build Dynatrace VULNERABILITY_FINDING events from OsvEnrichedInfo and optional RepositoryScan."""

import json
import uuid
from typing import Any, NamedTuple

from ..models import OsvEnrichedInfo, RepositoryScan
from .constants import (
    DT_RISK_LEVEL_MEDIUM,
    EVENT_PROVIDER,
    EVENT_TYPE_VULNERABILITY_FINDING,
    FINDING_TYPE,
    OBJECT_TYPE_FOR_VULNERABILITY_FINDING,
    PRODUCT_NAME,
    PRODUCT_VENDOR,
    REMEDIATION_STATUS_AVAILABLE,
    REMEDIATION_STATUS_NOT_AVAILABLE,
    SEVERITY_MODERATE,
    SOFTWARE_COMPONENT_TYPE,
    VALIDATION_LIST_DYNATRACE_FIELDS,
)
from .vul_scan import VulnerabilityScanEventBuilder
from dynatrace_extension.sdk.extension import extension_logger as logger


class _DependencyContext(NamedTuple):
    """Unpacked dependency details from OsvEnrichedInfo for event building."""

    package_file: str | None
    current_version: str | None
    dep_name: str | None
    pull_request_title: str
    update_type: str
    branch_name: str


class _EventBuildState(NamedTuple):
    """Computed values used when building event dict sections."""

    ctx: _DependencyContext
    repo_name: str | None
    package_file: str | None
    current_version: str | None
    dep_name: str | None
    artifact_name: str
    finding_id: str
    ghsa: str
    dt_risk_level: str

def _format_original_content(original_content: dict[str, Any] | None) -> str:
    """Serialize OSV API full response for event.original_content; empty string if None."""
    if original_content is None:
        return ""
    try:
        return json.dumps(original_content, default=str)
    except (TypeError, ValueError):
        return ""


class VulnerabilityFindingEventBuilder:
    """Builds one VULNERABILITY_FINDING flat event dict from OSV enrichment and optional scan context."""

    def __init__(
        self,
        osv: OsvEnrichedInfo,
        repository_scan: RepositoryScan | None,
    ) -> None:
        self.osv = osv
        self.repository_scan = repository_scan

    def _finding_id_suffix(self, package_file: str | None, repository_name: str | None) -> str:
        """Path suffix for finding.id: avoid duplicating repository_name in package_file."""
        if not package_file:
            return repository_name or ""
        if not repository_name:
            return package_file
        if repository_name in package_file:
            return package_file
        return f"{repository_name}/{package_file}"

    def _artifact_filename(self, package_file: str | None) -> str:
        """Last segment of package_file after '/'."""
        if not package_file:
            return ""
        return package_file.rsplit("/", 1)[-1]

    def _dep_context(self) -> _DependencyContext:
        """Unpack dependency details from OSV enrichment for event building."""
        dd = self.osv.dependency_details
        if not dd:
            return _DependencyContext(
                package_file=None,
                current_version=None,
                dep_name=self.osv.dependency_name,
                pull_request_title="",
                update_type="",
                branch_name="",
            )
        return _DependencyContext(
            package_file=dd.package_file,
            current_version=dd.current_version,
            dep_name=dd.dep_name,
            pull_request_title=dd.pr_title or "",
            update_type=dd.update_type or "",
            branch_name=dd.branch_name or "",
        )

    def _event_description(self, ctx: _DependencyContext) -> str:
        """Build event.description from OSV and dependency context."""
        object_ref = ctx.package_file or ""
        dep = ctx.dep_name or ""
        ver = ctx.current_version or ""
        return (
            f"Vulnerability {self.osv.ghsa_id or ''} was detected in CODE_ARTIFACT object ("
            f"{object_ref}) in {dep}:{ver} software component."
        )

    def _remediation_status(self) -> str:
        """Return AVAILABLE if remediation description is non-empty, else NOT_AVAILABLE."""
        if self.osv.remediation_description and self.osv.remediation_description.strip():
            return REMEDIATION_STATUS_AVAILABLE
        return REMEDIATION_STATUS_NOT_AVAILABLE

    def _event_section(self, state: _EventBuildState) -> dict[str, Any]:
        """Event-level fields (provider, type, id, description, original_content)."""
        return {
            "event.provider": EVENT_PROVIDER,
            "event.type": EVENT_TYPE_VULNERABILITY_FINDING,
            "event.id": str(uuid.uuid4()),
            "event.description": self._event_description(state.ctx),
            "event.original_content": _format_original_content(self.osv.original_content),
        }

    def _object_section(self, state: _EventBuildState) -> dict[str, Any]:
        """Object and product fields."""
        return {
            "object.type": OBJECT_TYPE_FOR_VULNERABILITY_FINDING,
            "object.id": state.package_file or "",
            "object.name": state.artifact_name,
            "product.vendor": PRODUCT_VENDOR,
            "product.name": PRODUCT_NAME,
        }

    def _finding_section(self, state: _EventBuildState) -> dict[str, Any]:
        """Finding fields (type, id, title, time, score, severity)."""
        return {
            "finding.type": FINDING_TYPE,
            "finding.id": state.finding_id,
            "finding.title": self.osv.msg or "",
            "finding.time.created": self.osv.time or "",
            "finding.score": self.osv.score,
            "finding.severity": self.osv.severity or "",
        }

    def _vulnerability_section(self, state: _EventBuildState) -> dict[str, Any]:
        """Vulnerability and remediation fields."""
        return {
            "vulnerability.id": state.ghsa,
            "vulnerability.title": self.osv.summary or "",
            "vulnerability.description": self.osv.enhanced_details or "",
            "vulnerability.cvss.base_score": self.osv.score,
            "vulnerability.cvss.version": self.osv.cvss_version or "",
            "vulnerability.references.cve": self.osv.cves or [],
            "vulnerability.remediation.fix_version": self.osv.remediation_version or [],
            "vulnerability.remediation.description": self.osv.remediation_description or "",
            "vulnerability.remediation.status": self._remediation_status(),
        }

    def _component_section(self, state: _EventBuildState) -> dict[str, Any]:
        """Software component and component (duplicated) fields."""
        return {
            "software_component.type": SOFTWARE_COMPONENT_TYPE,
            "software_component.purl": self.osv.purl or "",
            "software_component.version": state.current_version or "",
            "software_component.name": state.dep_name or "",
            "component.version": state.current_version or "",
            "component.name": state.dep_name or "",
        }

    def _artifact_section(self, state: _EventBuildState) -> dict[str, Any]:
        """Artifact and DT security risk fields."""
        return {
            "artifact.filename": state.artifact_name,
            "artifact.path": state.package_file or "",
            "artifact.name": state.artifact_name,
            "artifact.repository": state.repo_name or "",
            "dt.security.risk.level": state.dt_risk_level,
            "dt.security.risk.score": self.osv.score,
        }

    def _scan_section(self, state: _EventBuildState) -> dict[str, Any]:
        """Scan context (when repository_scan is present)."""
        rs = self.repository_scan
        return {
            "scan.id": rs.scan_id if rs else "",
            "scan.name": rs.scan_name if rs else "",
        }

    def _renovate_section(self, state: _EventBuildState) -> dict[str, Any]:
        """Renovate-specific fields from dependency context."""
        return {
            "renovate.pull_request.title": state.ctx.pull_request_title or "",
            "renovate.update_type": state.ctx.update_type or "",
            "renovate.branch_name": state.ctx.branch_name or "",
        }

    def build(self) -> dict[str, Any]:
        """Build one VULNERABILITY_FINDING flat event dict."""
        ctx = self._dep_context()
        repo_name = self.repository_scan.repository_name if self.repository_scan else None
        package_file = ctx.package_file
        current_version = ctx.current_version
        dep_name = ctx.dep_name
        artifact_name = self._artifact_filename(package_file)
        finding_id_suffix = self._finding_id_suffix(package_file, repo_name)
        ghsa = self.osv.ghsa_id or ""
        finding_id = f"{ghsa}:{finding_id_suffix}" if finding_id_suffix else ghsa
        dt_risk_level = (
            DT_RISK_LEVEL_MEDIUM
            if self.osv.severity == SEVERITY_MODERATE
            else (self.osv.severity or "")
        )
        state = _EventBuildState(
            ctx=ctx,
            repo_name=repo_name,
            package_file=package_file,
            current_version=current_version,
            dep_name=dep_name,
            artifact_name=artifact_name,
            finding_id=finding_id,
            ghsa=ghsa,
            dt_risk_level=dt_risk_level,
        )
        return {
            **self._event_section(state),
            **self._object_section(state),
            **self._finding_section(state),
            **self._vulnerability_section(state),
            **self._component_section(state),
            **self._artifact_section(state),
            **self._scan_section(state),
            **self._renovate_section(state),
        }


class EventsForIngestBuilder:
    """
    Builds the list of events to push to Dynatrace: one VULNERABILITY_FINDING per OSV entry,
    plus one VULNERABILITY_SCAN if repository_scan is present.
    """

    def __init__(
        self,
        ghsa_to_osv: dict[str, list[OsvEnrichedInfo]],
        repository_scan: RepositoryScan | None,
    ) -> None:
        self.ghsa_to_osv = ghsa_to_osv
        self.repository_scan = repository_scan

    def validate(self, event: dict[str, Any]) -> bool:
        for data in VALIDATION_LIST_DYNATRACE_FIELDS:
            if event.get(data,"") in [None, ""]:
                return False
        return True

    def build(self) -> list[dict[str, Any]]:
        """Return list of event dicts for ingest."""
        events: list[dict[str, Any]] = []
        total_entries = sum(len(v) for v in self.ghsa_to_osv.values())
        logger.debug(
            "GHSA_TO_OSV: %d unique GHSA(s), %d total mapping(s)",
            len(self.ghsa_to_osv), total_entries,
        )

        if self.repository_scan:
            scan_event = VulnerabilityScanEventBuilder(self.repository_scan).build()
            if self.validate(scan_event):
                events.append(scan_event)
            else:
                logger.debug("Validation of scan event failed, skipping finding event creation: %s", scan_event)
                return events

        for osv_list in self.ghsa_to_osv.values():
            for osv in osv_list:
                finding_event = VulnerabilityFindingEventBuilder(osv, self.repository_scan).build()
                if self.validate(finding_event):
                    events.append(finding_event)

        n_finding = len(events) - (1 if self.repository_scan else 0)
        n_scan = 1 if self.repository_scan else 0
        logger.debug(
            "EVENTS_TO_INGEST: %d events (%d finding, %d scan)",
            len(events), n_finding, n_scan,
        )
        return events