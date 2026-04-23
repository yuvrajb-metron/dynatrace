"""
Assemble Dynatrace security events for a single GitLab CI security job.

Output shape
    For each distinct artifact (dependency path or container image): one **artifact-scoped**
    ``VULNERABILITY_SCAN``, then all ``VULNERABILITY_FINDING`` events for that artifact.
    Findings share ``object.id`` / ``object.name`` and ``scan.id`` / ``scan.name`` with their
    artifact scan. No repository-wide (parent) scan event is emitted.

Where status is computed
    Ingest success/failure is handled by ``ExtensionImpl.report_vulnerabilities`` /
    ``poll_groups_and_ingest_security_events``; this module only builds payload dicts.
"""

from __future__ import annotations

import copy

from ..models import RepositoryScan, VulnerabilityDetails
from ..utils.constants import DEFAULT_SCAN_PRODUCT_NAME
from .scan import build_artifact_level_scan_event
from .vulnerability_finding import build_finding_event


def _merge_repository_scan_with_finding_fallback(
    repository_scan: RepositoryScan,
    pairing_finding: VulnerabilityDetails,
) -> RepositoryScan:
    """
    Clone a ``RepositoryScan`` and patch missing fields using data from a vulnerability.

    **Purpose** — :func:`~appsec_gitlab.events.scan.build_artifact_level_scan_event` requires a
    fully populated ``RepositoryScan``. When the REST job/project payload omits fields that exist
    on the merged GraphQL finding, this helper fills gaps so artifact scan events can still be built.

    Args:
        repository_scan:
            The scan model produced from the job; copied with :func:`copy.copy` (shallow).
        pairing_finding:
            Any ``VulnerabilityDetails`` from the same pipeline job. Supplies ``repository_path`` /
            ``project_name`` if ``repository_name`` was empty, ``product_name`` if still default,
            and start/finish times if missing.

    Returns:
        A new ``RepositoryScan`` instance (shallow copy of the original) with any of the above
        fields updated. The original ``repository_scan`` is not mutated.
    """
    merged = copy.copy(repository_scan)
    repository_name = merged.repository_name
    if not (isinstance(repository_name, str) and repository_name.strip()):
        path_candidate = pairing_finding.repository_path or pairing_finding.project_name
        if isinstance(path_candidate, str) and path_candidate.strip():
            merged.repository_name = path_candidate.strip()
            merged.scan_name = merged._build_scan_name()
    if merged.product_name == DEFAULT_SCAN_PRODUCT_NAME and pairing_finding.product_name:
        merged.product_name = pairing_finding.product_name
    if not merged.scan_time_started:
        merged.scan_time_started = merged.job.started_at or merged.job.created_at
    if not merged.scan_time_completed:
        merged.scan_time_completed = (
            merged.job.finished_at or merged.job.started_at or merged.job.created_at
        )
    return merged


def _artifact_group_scan_link_ids(repository_scan: RepositoryScan) -> tuple[str | int, str | int | None]:
    """Job ``scan.id`` / ``scan.name`` shared by artifact scan and finding events."""
    return repository_scan.scan_id, repository_scan.scan_name


class SecurityEventsForIngestBuilder:
    """
    Builds the ordered list of Dynatrace security-event payloads for **one** GitLab CI job.

    **Order** — For each artifact group: one ``VULNERABILITY_SCAN`` then ``VULNERABILITY_FINDING``
    events for vulnerabilities on that artifact. No repo-level scan.

    **Callers** — :mod:`appsec_gitlab.core.polling` after merging GitLab API data into models.
    """

    def __init__(
        self,
        repository_scan: RepositoryScan | None,
        vulnerability_details_list: list[VulnerabilityDetails],
    ) -> None:
        """
        Args:
            repository_scan:
                Scan model for this job (``None`` if unavailable; :meth:`build` then yields no events).
            vulnerability_details_list:
                Every CVE-backed vulnerability to consider for this job; may be empty.
        """
        self.repository_scan = repository_scan
        self.vulnerability_details_list = vulnerability_details_list

    def build(self) -> list[dict]:
        """
        Produce the full event list for this job.

        Returns:
            ``[]`` if ``repository_scan`` is ``None``, there are no findings, or the scan model
            cannot be validated. Otherwise ``[ artifact_scan, findings..., ... ]`` per artifact group.
            Finding dicts are skipped when :func:`~appsec_gitlab.events.vulnerability_finding.build_finding_event`
            returns ``None`` (e.g. missing CVEs).

        Note:
            Ingest HTTP status is handled outside this class; only payload dicts are returned here.
        """
        events: list[dict] = []

        if not self.vulnerability_details_list:
            return events

        scan_model: RepositoryScan | None = self.repository_scan
        if scan_model is None:
            return events

        if not scan_model.has_required_mapping_values():
            scan_model = _merge_repository_scan_with_finding_fallback(
                scan_model,
                self.vulnerability_details_list[0],
            )
        if not scan_model.has_required_mapping_values():
            return events

        findings_by_artifact_path: dict[str, list[VulnerabilityDetails]] = {}
        for finding_details in self.vulnerability_details_list:
            grouping_key = finding_details.artifact_full_path_for_synthetic_scan_event()
            if not grouping_key:
                grouping_key = finding_details.object_id or finding_details.finding_id or finding_details.vulnerability_id
            if not grouping_key:
                continue
            findings_by_artifact_path.setdefault(grouping_key, []).append(finding_details)

        for artifact_path in sorted(findings_by_artifact_path.keys()):
            findings_for_artifact = findings_by_artifact_path[artifact_path]
            representative_finding = findings_for_artifact[0]
            synthetic_scan_id, synthetic_scan_name = _artifact_group_scan_link_ids(scan_model)
            artifact_scan_payload = build_artifact_level_scan_event(
                scan_model,
                representative_finding,
                synthetic_scan_id=synthetic_scan_id,
                synthetic_scan_name=synthetic_scan_name,
            )
            if artifact_scan_payload is None:
                continue
            events.append(artifact_scan_payload)

            for finding_details in findings_for_artifact:
                finding_payload = build_finding_event(
                    finding_details,
                    scan_id_override=synthetic_scan_id,
                    scan_name_override=synthetic_scan_name,
                )
                if finding_payload is not None:
                    events.append(finding_payload)

        return events
