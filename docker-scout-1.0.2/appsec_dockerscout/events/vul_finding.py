"""
Build one VULNERABILITY_FINDING event for Dynatrace security ingest.

Uses parsed SARIF finding, image ref, optional SBOM metadata, and scan id/times.
"""

import copy
import json
import os
from typing import Any, Dict, List, Optional, Tuple

from appsec_dockerscout.utils.constants import (
    EVENT_PROVIDER,
    EVENT_TYPE_VULNERABILITY_FINDING,
    FINDING_TYPE_DEPENDENCY_VULNERABILITY,
    OBJECT_TYPE_CONTAINER_IMAGE,
    PRODUCT_NAME,
    PRODUCT_VENDOR,
    REMEDIATION_STATUS_AVAILABLE,
    REMEDIATION_STATUS_NOT_AVAILABLE,
)
from appsec_dockerscout.utils.vulnerability_constants import (
    NO_FIXED_VERSION_MARKERS,
    OS_PACKAGE_SBOM_TYPES,
)
from appsec_dockerscout.models import (
    ImageRef,
    ImageMetadata,
    ParsedFinding,
    SbomArtifactRecord,
)
from appsec_dockerscout.parsing.sbom_parser import collect_sbom_artifact_paths
from dynatrace_extension.sdk.extension import extension_logger as logger


def _is_actionable_fixed_version(fixed_version_raw: Optional[Any]) -> bool:
    """
    Return True if ``fixed_version`` looks like a real version, not a no-fix placeholder.

    Used only for ``vulnerability.remediation.status`` (AVAILABLE vs NOT_AVAILABLE), not
    for filtering the value sent in ``vulnerability.remediation.fix_version``.

    Normalizes by lowercasing and collapsing whitespace so ``not fixed`` and ``not_fixed``
    match the same sentinel.
    """
    if fixed_version_raw is None:
        return False
    trimmed = str(fixed_version_raw).strip()
    if not trimmed:
        return False
    normalized_token = "_".join(trimmed.lower().split())
    return normalized_token not in NO_FIXED_VERSION_MARKERS


def _purl_to_component(purl: Optional[str]) -> Dict[str, Any]:
    """
    Extract ``software_component`` fields from a package URL string.

    Args:
        purl: A ``pkg:`` URI (e.g. ``pkg:npm/cookie@0.4.0``), or missing/invalid.

    Returns:
        Dict with ``name``, ``version``, ``type`` (library or package), and ``ecosystem``.
        Missing string fields use ``None`` instead of empty strings.
    """
    package_name = ""
    package_version = ""
    ecosystem_type = ""
    component_kind = "library"
    if not purl or not purl.startswith("pkg:"):
        return {
            "name": None,
            "version": None,
            "type": component_kind,
            "ecosystem": None,
        }
    try:
        after_pkg_prefix = purl[4:]
        if "@" in after_pkg_prefix:
            coordinate_part, version_part = after_pkg_prefix.rsplit("@", 1)
            package_version = (
                version_part.split("?")[0] if "?" in version_part else version_part
            )
        else:
            coordinate_part = after_pkg_prefix
        if "/" in coordinate_part:
            ecosystem_type, package_name = coordinate_part.split("/", 1)
        else:
            ecosystem_type = coordinate_part
            package_name = coordinate_part
        if ecosystem_type in ("npm", "pypi", "maven", "nuget"):
            component_kind = "library"
        elif ecosystem_type in ("apk", "deb", "rpm"):
            component_kind = "package"
    except Exception:
        pass
    return {
        "name": package_name or None,
        "version": package_version or None,
        "type": component_kind,
        "ecosystem": ecosystem_type or None,
    }


def _purls_equal(first_purl: str, second_purl: str) -> bool:
    """
    Compare two package URLs by coordinate, ignoring ``?query`` parameter order.

    Args:
        first_purl: First purl.
        second_purl: Second purl.

    Returns:
        True if coordinates match (case-insensitive, query-stripped).
    """
    if not first_purl or not second_purl:
        return False
    first_coordinate = first_purl.strip().split("?", 1)[0].lower()
    second_coordinate = second_purl.strip().split("?", 1)[0].lower()
    return first_coordinate == second_coordinate


def _sbom_artifact_matches_finding(
    finding: ParsedFinding,
    sbom_artifact: SbomArtifactRecord,
) -> bool:
    """
    Return whether the SBOM artifact matches the SARIF finding by path and purl.

    Args:
        finding: Parsed SARIF row (artifact path and purls).
        sbom_artifact: SBOM artifact record with paths and purl.

    Returns:
        True if the artifact path is listed and any SARIF purl matches the SBOM purl.
    """
    artifact_uri = (finding.artifact_path or "").strip()
    if not artifact_uri or not sbom_artifact.paths:
        return False
    if artifact_uri not in sbom_artifact.paths:
        return False
    sarif_purls: List[str] = finding.purls or []
    if not sarif_purls or not sbom_artifact.purl:
        return False
    return any(
        _purls_equal(sarif_purl, sbom_artifact.purl) for sarif_purl in sarif_purls
    )


def find_matching_sbom_artifact(
    finding: ParsedFinding,
    image_meta: Optional[ImageMetadata],
) -> Optional[SbomArtifactRecord]:
    """
    Find the first SBOM artifact that matches this finding's path and purl rules.

    Args:
        finding: Parsed SARIF finding.
        image_meta: Parsed SBOM metadata for the image, or None.

    Returns:
        Matching ``SbomArtifactRecord``, or None.
    """
    if not image_meta or not image_meta.sbom_artifacts:
        return None
    for sbom_artifact in image_meta.sbom_artifacts:
        if _sbom_artifact_matches_finding(finding, sbom_artifact):
            return sbom_artifact
    return None


def _software_component_from_sbom_artifact(
    sbom_artifact: SbomArtifactRecord,
) -> Dict[str, Any]:
    """
    Map a matched SBOM artifact to Dynatrace ``software_component`` fields.

    Args:
        sbom_artifact: Matched SBOM artifact record.

    Returns:
        Dict with name, version, ecosystem, supplier, and purl.
    """
    supplier = (sbom_artifact.author or "").strip()
    return {
        "name": sbom_artifact.name or None,
        "version": sbom_artifact.version or None,
        "ecosystem": sbom_artifact.pkg_type or None,
        "supplier": supplier or None,
        "purl": sbom_artifact.purl or None,
    }


def _artifact_filename(path: Optional[str]) -> Optional[str]:
    """
    Return the file name portion of an artifact path for ``artifact.*`` fields.

    Args:
        path: SARIF ``artifactLocation.uri`` or empty.

    Returns:
        Base name, or ``None`` when path is missing or empty.
    """
    if not path:
        return None
    base = os.path.basename(path)
    return base or None


def resolve_object_identity(
    image_ref: ImageRef,
    image_meta: Optional[ImageMetadata],
) -> tuple[str, str, str]:
    """
    Resolve Dynatrace ``object.id``, ``object.name``, and repository string for an image.

    ``object.id`` uses SBOM ``attestations[].reference`` when present, else digest- or
    tag-based id. ``object.name`` is always ``org/repo:tag`` (``image_ref.full_name``).
    SBOM ``source.image.name`` is often tagless and must not override, or Dynatrace shows
    ``metronsecurity/scout-demo`` instead of ``metronsecurity/scout-demo:latest``.

    Args:
        image_ref: Image reference.
        image_meta: Parsed SBOM metadata, or None.

    Returns:
        Tuple ``(object_id, object_name, repo_name)`` where ``repo_name`` is ``org/repo``
        (no tag; for ``container_image.repository``).
    """
    repo_name = f"{image_ref.org}/{image_ref.repo}"
    if image_meta and image_meta.attestation_reference:
        object_id = image_meta.attestation_reference
    elif image_meta and image_meta.digest:
        object_id = f"{image_ref.org}/{image_ref.repo}@{image_meta.digest}"
    else:
        object_id = image_ref.full_name
    object_name = image_ref.full_name
    logger.debug(
        "resolve_object_identity: full_name=%s repo_name=%s object_id=%s object.name=%s "
        "sbom.name=%s sbom.tags=%s",
        image_ref.full_name,
        repo_name,
        object_id,
        object_name,
        image_meta.name if image_meta else None,
        image_meta.tags if image_meta else None,
    )
    return object_id, object_name, repo_name


def _finding_severity_from_security_score(score: Optional[float]) -> str:
    """
    Map SARIF ``security-severity`` to Dynatrace ``finding.severity`` bands.

    Bands: 9.0–10.0 CRITICAL, 7.0–8.9 HIGH, 4.0–6.9 MEDIUM, 0.1–3.9 LOW, 0.0 NONE.

    Args:
        score: Numeric severity from SARIF rule properties, or None.

    Returns:
        One of ``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW``, or ``NONE``.
    """
    if score is None:
        numeric_severity = 0.0
    else:
        try:
            numeric_severity = float(score)
        except (TypeError, ValueError):
            return "NONE"
    if numeric_severity != numeric_severity:  # NaN
        return "NONE"
    if numeric_severity <= 0.0:
        return "NONE"
    if numeric_severity < 4.0:
        return "LOW"
    if numeric_severity < 7.0:
        return "MEDIUM"
    if numeric_severity < 9.0:
        return "HIGH"
    return "CRITICAL"


def _split_rule_help_text(
    help_text: Optional[str],
) -> Tuple[Optional[str], Optional[str]]:
    """
    Split ``rules[].help.text`` into text before ``### Patches`` and from that heading onward.

    Args:
        help_text: Full SARIF help markdown.

    Returns:
        ``(before_patches, from_patches)``; either part is ``None`` when absent or empty.
    """
    if not help_text or not help_text.strip():
        return None, None
    help_text_lower = help_text.lower()
    patches_keyword = "patches"
    patches_heading_index = help_text_lower.find(patches_keyword)
    if patches_heading_index == -1:
        stripped = help_text.strip()
        return (stripped or None), None
    text_before_patches = help_text[:patches_heading_index].strip()
    text_from_patches_onward = help_text[patches_heading_index:].strip()
    return (text_before_patches or None), (text_from_patches_onward or None)


def _format_event_description(
    vulnerability_id: str,
    object_name: str,
    object_type: str,
    component_name: Optional[str],
) -> str:
    """
    Build the ``event.description`` sentence for a vulnerability finding.

    Args:
        vulnerability_id: Rule or CVE id.
        object_name: Resolved object name.
        object_type: Object type constant (e.g. container image).
        component_name: Affected component display name, or ``None`` (treated as generic
            ``component`` in the sentence).

    Returns:
        Human-readable one-line description.
    """
    display_component_name = component_name if component_name else "component"
    return (
        f"Vulnerability {vulnerability_id} was detected in {object_name} ({object_type}) "
        f"in {display_component_name} component"
    )


def _find_raw_sbom_artifact_dict(
    finding: ParsedFinding,
    sbom_root: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """
    Return the raw SBOM ``artifacts[]`` dict that matches path and purl for this finding.

    Args:
        finding: Parsed SARIF finding.
        sbom_root: Root SBOM object (must contain ``artifacts``).

    Returns:
        Matching artifact dict, or None.
    """
    artifact_uri = (finding.artifact_path or "").strip()
    if not artifact_uri:
        return None
    sarif_purls = finding.purls or []
    if not sarif_purls:
        return None
    for artifact_entry in sbom_root.get("artifacts") or []:
        if not isinstance(artifact_entry, dict):
            continue
        artifact_paths = collect_sbom_artifact_paths(artifact_entry)
        if artifact_uri not in artifact_paths:
            continue
        artifact_purl = artifact_entry.get("purl")
        if not isinstance(artifact_purl, str) or not artifact_purl.strip():
            continue
        if any(
            _purls_equal(sarif_purl, artifact_purl) for sarif_purl in sarif_purls
        ):
            return artifact_entry
    return None


def _sbom_excerpt_for_original_content(
    sbom_root: Dict[str, Any],
    matched_artifact: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Build the SBOM slice embedded in ``event.original_content``.

    Includes slim ``source.image``, ``attestations``, and optional matched artifact dict.

    Args:
        sbom_root: Full parsed SBOM.
        matched_artifact: Matched ``artifacts[]`` entry, or None for scan events.

    Returns:
        Dict suitable for JSON serialization under ``sbom`` in ``original_content``.
    """
    sbom_source = sbom_root.get("source") or {}
    slim_image: Dict[str, Any] = {}
    if isinstance(sbom_source, dict):
        source_image_block = sbom_source.get("image") or {}
        if isinstance(source_image_block, dict):
            for field_name in ("name", "digest", "tags", "distro", "platform"):
                if field_name in source_image_block:
                    slim_image[field_name] = source_image_block[field_name]
    slim_source: Dict[str, Any] = {"image": slim_image}
    if isinstance(sbom_source, dict) and sbom_source.get("type") is not None:
        slim_source["type"] = sbom_source.get("type")
    return {
        "source": slim_source,
        "attestations": sbom_root.get("attestations"),
        "matched_artifact": matched_artifact,
    }


def sbom_reference_excerpt(image_meta: Optional[ImageMetadata]) -> Optional[Dict[str, Any]]:
    """
    SBOM slice for ``VULNERABILITY_SCAN`` ``event.original_content`` (object identity context).

    Args:
        image_meta: Parsed SBOM metadata, or None.

    Returns:
        Excerpt dict with slim ``source.image`` and ``attestations``, or None if no SBOM.
    """
    sbom_root_dict = image_meta.sbom_root if image_meta else None
    if not isinstance(sbom_root_dict, dict) or not sbom_root_dict:
        return None
    return _sbom_excerpt_for_original_content(sbom_root_dict, None)


def _get_image_file_path_from_sarif_location(sarif_location: Any) -> str:
    """
    Extract the on-image file path from one SARIF ``result.locations[]`` object.

    Scout encodes that path as ``physicalLocation.artifactLocation.uri`` (for example
    ``/usr/share/doc/liblz4-1/copyright``).

    Args:
        sarif_location: One element from a SARIF result's ``locations`` array.

    Returns:
        Stripped path string, or ``""`` if the structure is missing or not a string.
    """
    if not isinstance(sarif_location, dict):
        return ""
    physical_location = sarif_location.get("physicalLocation")
    if not isinstance(physical_location, dict):
        physical_location = {}
    artifact_location = physical_location.get("artifactLocation")
    if not isinstance(artifact_location, dict):
        artifact_location = {}
    uri_raw = artifact_location.get("uri")
    if not isinstance(uri_raw, str):
        return ""
    return uri_raw.strip()


def _deep_copy_single_sarif_location_for_finding_file_path(
    all_sarif_locations: Any,
    finding_file_path_in_image: str,
) -> List[Dict[str, Any]]:
    """
    Build a one-element ``locations`` array for ``event.original_content`` JSON.

    Chooses the SARIF location whose URI equals ``ParsedFinding.artifact_path`` so the
    event only embeds the file path that defines this finding (not every path Scout
    attached to the same CVE result).

    Args:
        all_sarif_locations: Full ``result.locations`` list from parsing (unchanged on disk).
        finding_file_path_in_image: Same value as ``finding.artifact_path`` (trimmed inside).

    Returns:
        ``[deepcopy(matching_location)]``, or a one-element fallback when the path is
        empty or no URI matches (first dict location), or ``[]`` if there are no locations.
    """
    if not isinstance(all_sarif_locations, list) or not all_sarif_locations:
        return []
    finding_path_normalized = (finding_file_path_in_image or "").strip()
    if finding_path_normalized:
        for sarif_location in all_sarif_locations:
            if not isinstance(sarif_location, dict):
                continue
            if (
                _get_image_file_path_from_sarif_location(sarif_location)
                == finding_path_normalized
            ):
                return [copy.deepcopy(sarif_location)]
        first_location_dict = next(
            (loc for loc in all_sarif_locations if isinstance(loc, dict)),
            None,
        )
        return (
            [copy.deepcopy(first_location_dict)]
            if first_location_dict is not None
            else []
        )
    first_location_dict = next(
        (loc for loc in all_sarif_locations if isinstance(loc, dict)),
        None,
    )
    return [copy.deepcopy(first_location_dict)] if first_location_dict is not None else []


def _clone_sarif_result_with_only_finding_location_row(
    full_result_from_parser: Dict[str, Any],
    finding_file_path_in_image: str,
) -> Dict[str, Any]:
    """
    Produce a deep copy of one SARIF ``results[]`` object for JSON embedding.

    The copy's ``locations`` array is replaced with a single row for
    ``finding_file_path_in_image``. The live ``ParsedFinding.result_raw`` is left
    untouched so other code still sees every Scout location.

    Args:
        full_result_from_parser: ``finding.result_raw`` (full ``locations`` list).
        finding_file_path_in_image: ``finding.artifact_path``.

    Returns:
        Independent dict safe to serialize under ``original_content.sarif.result``.
    """
    sarif_result_copy = copy.deepcopy(full_result_from_parser)
    sarif_result_copy["locations"] = _deep_copy_single_sarif_location_for_finding_file_path(
        full_result_from_parser.get("locations"),
        finding_file_path_in_image,
    )
    return sarif_result_copy


def _deep_copy_one_sbom_row_matching_finding_path(
    sbom_path_rows: Any,
    finding_file_path_in_image: str,
) -> List[Dict[str, Any]]:
    """
    From SBOM ``matched_artifact.locations`` or ``matched_artifact.files``, take one row.

    Each row is a dict with a ``path`` field. Only the row whose ``path`` equals the
    finding's image file path is kept, as a deep copy, inside a one-element list.

    Args:
        sbom_path_rows: Either ``locations`` or ``files`` array from the matched artifact.
        finding_file_path_in_image: ``finding.artifact_path``.

    Returns:
        ``[deepcopy(row)]`` when a matching ``path`` exists, otherwise ``[]``.
    """
    finding_path_normalized = (finding_file_path_in_image or "").strip()
    if not finding_path_normalized or not isinstance(sbom_path_rows, list):
        return []
    for sbom_row in sbom_path_rows:
        if not isinstance(sbom_row, dict):
            continue
        row_path = sbom_row.get("path")
        if isinstance(row_path, str) and row_path.strip() == finding_path_normalized:
            return [copy.deepcopy(sbom_row)]
    return []


def _clone_sbom_matched_artifact_with_single_path_rows(
    full_matched_artifact_from_sbom: Dict[str, Any],
    finding_file_path_in_image: str,
) -> Dict[str, Any]:
    """
    Copy the SBOM artifact dict that matched the finding, shrinking path-heavy arrays.

    ``locations`` and ``files`` on the real SBOM object can list dozens of paths. For
    ``original_content`` we only need the single path tied to this finding. This returns
    a shallow top-level copy with those two keys rewritten to short lists so we never
    mutate ``sbom_root``.

    Args:
        full_matched_artifact_from_sbom: Reference from ``_find_raw_sbom_artifact_dict``.
        finding_file_path_in_image: ``finding.artifact_path``.

    Returns:
        New dict suitable for ``_sbom_excerpt_for_original_content(..., matched_artifact=…)``.
    """
    matched_artifact_copy = dict(full_matched_artifact_from_sbom)
    if "locations" in matched_artifact_copy:
        matched_artifact_copy["locations"] = _deep_copy_one_sbom_row_matching_finding_path(
            full_matched_artifact_from_sbom.get("locations"),
            finding_file_path_in_image,
        )
    if "files" in matched_artifact_copy:
        matched_artifact_copy["files"] = _deep_copy_one_sbom_row_matching_finding_path(
            full_matched_artifact_from_sbom.get("files"),
            finding_file_path_in_image,
        )
    return matched_artifact_copy


def _build_original_content(
    finding: ParsedFinding,
    image_meta: Optional[ImageMetadata],
) -> str:
    """
    Serialize SARIF rule/result plus optional SBOM excerpt for ``event.original_content``.

    Large arrays are shrunk only here: SARIF ``result.locations`` and SBOM
    ``matched_artifact.locations`` / ``matched_artifact.files`` each collapse to the
    single file path that identifies this finding, which keeps ingest payloads small.

    Args:
        finding: Parsed finding with rule and result payloads.
        image_meta: Optional SBOM metadata for matched artifact excerpt.

    Returns:
        JSON string for the event field.
    """
    sarif_result_for_original_content_json = (
        _clone_sarif_result_with_only_finding_location_row(
            finding.result_raw,
            finding.artifact_path,
        )
    )
    sarif_payload: Dict[str, Any] = {
        "rule": finding.rule_raw,
        "result": sarif_result_for_original_content_json,
    }
    if finding.sarif_version:
        sarif_payload["version"] = finding.sarif_version
    if finding.sarif_schema:
        sarif_payload["$schema"] = finding.sarif_schema
    original_content_payload: Dict[str, Any] = {"sarif": sarif_payload}
    sbom_root_dict = image_meta.sbom_root if image_meta else None
    if isinstance(sbom_root_dict, dict) and sbom_root_dict:
        matched_artifact_from_sbom_root = _find_raw_sbom_artifact_dict(
            finding, sbom_root_dict
        )
        sbom_matched_artifact_for_original_content: Optional[Dict[str, Any]] = None
        if matched_artifact_from_sbom_root is not None:
            sbom_matched_artifact_for_original_content = (
                _clone_sbom_matched_artifact_with_single_path_rows(
                    matched_artifact_from_sbom_root,
                    finding.artifact_path,
                )
            )
        original_content_payload["sbom"] = _sbom_excerpt_for_original_content(
            sbom_root_dict,
            sbom_matched_artifact_for_original_content,
        )
    return json.dumps(original_content_payload, ensure_ascii=False)


def build_vulnerability_finding(
    finding: ParsedFinding,
    image_ref: ImageRef,
    image_meta: Optional[ImageMetadata],
    scan_id: str,
    scan_started: str,
    scan_completed: str,
) -> Dict[str, Any]:
    """
    Build one VULNERABILITY_FINDING event for Dynatrace security ingest.

    Args:
        finding: Parsed SARIF finding (rule_id, severity, purls, etc.).
        image_ref: Image reference (org/repo:tag).
        image_meta: Optional SBOM image metadata (digest, tags, os).
        scan_id: Scan identifier.
        scan_started: ISO8601 scan start time.
        scan_completed: ISO8601 scan end time.

    Returns:
        Single event dict for security.events ingest. The ``finding.*`` namespace uses
        ``finding.id`` = ``ruleId:artifactLocation.uri``, ``finding.title`` with
        ``object.id``, ``finding.description`` = SARIF ``results[].message.text``,
        ``finding.score`` / severity from ``rules[].properties.security-severity``
        (severity mapped to CRITICAL/HIGH/MEDIUM/LOW/NONE), and
        ``finding.time.created`` = scan completion time.

        ``vulnerability.*`` uses ``rules[].id``, ``shortDescription.text``, ``help.text``
        split at ``### Patches`` (description = before, remediation.description = from
        Patches onward; if no Patches block, description is full ``help.text`` or
        ``results[].message.text`` when help is empty). ``vulnerability.remediation.fix_version``
        carries ``properties.fixed_version`` as reported (unchanged). Remediation status is
        ``AVAILABLE`` only when that value looks like a real version (not placeholders such as
        ``not_fixed``, ``not fixed``, or ``not_provided``).

        ``software_component.*`` / ``component.*`` / ``os.*``: when SBOM ``artifacts[]``
        matches this finding's SARIF ``artifactLocation.uri`` and a ``purls`` entry
        matches the artifact ``purl``, fields come from that artifact (name, version,
        ecosystem, author, purl). ``software_component.type`` is always ``library``.
        If the artifact ``type`` is ``apk``, ``deb``,
        or ``rpm``, treat as an OS-distro vulnerability: ``component.*`` and ``os.*``
        use ``source.image.distro`` / ``platform``; otherwise ``component`` mirrors
        ``software_component`` and ``os.*`` keys are omitted.

        ``event.original_content`` is JSON with ``sarif`` (version/schema, rule, result)
        and, when SBOM was parsed, ``sbom`` (slim ``source.image``, ``attestations``,
        and ``matched_artifact`` for this finding's path + purl). SARIF ``result.locations``
        and SBOM ``matched_artifact.locations`` / ``files`` are reduced to the single
        path for this finding to keep the payload small.
    """
    logger.debug(
        f"build_vulnerability_finding: rule_id={finding.rule_id}, image_ref={image_ref.full_name}"
    )
    object_id, object_name, repository_qualifier = resolve_object_identity(
        image_ref, image_meta
    )
    dynatrace_finding_id = f"{finding.rule_id}:{finding.artifact_path}"
    raw_security_score = finding.security_score
    risk_score = 0.0 if raw_security_score is None else raw_security_score
    finding_severity = _finding_severity_from_security_score(finding.security_score)
    primary_purl: Optional[str] = finding.purls[0] if finding.purls else None
    matched_sbom_artifact = find_matching_sbom_artifact(finding, image_meta)
    if matched_sbom_artifact:
        software_component = _software_component_from_sbom_artifact(
            matched_sbom_artifact
        )
        is_os_package_vulnerability = (
            matched_sbom_artifact.pkg_type in OS_PACKAGE_SBOM_TYPES
        )
    else:
        software_component = _purl_to_component(primary_purl)
        software_component["supplier"] = None
        software_component["purl"] = primary_purl
        is_os_package_vulnerability = False
    reported_fix_version = finding.fixed_version
    has_actionable_fix = _is_actionable_fixed_version(reported_fix_version)
    remediation_status = (
        REMEDIATION_STATUS_AVAILABLE
        if has_actionable_fix
        else REMEDIATION_STATUS_NOT_AVAILABLE
    )
    fix_version_list = (
        [str(reported_fix_version)] if reported_fix_version is not None else []
    )
    rule_identifier = finding.rule_id
    cve_reference_ids = (
        [rule_identifier] if rule_identifier.startswith("CVE-") else []
    )
    rule_help_markdown = finding.help_text or None
    (
        description_before_patches,
        remediation_text_from_patches,
    ) = _split_rule_help_text(rule_help_markdown)
    if remediation_text_from_patches:
        vulnerability_description = description_before_patches
        remediation_description = remediation_text_from_patches
    elif description_before_patches:
        vulnerability_description = description_before_patches
        remediation_description = None
    else:
        vulnerability_description = finding.message or None
        remediation_description = None
    affected_component_name: Optional[str] = software_component.get("name") or None
    if is_os_package_vulnerability and image_meta:
        event_component_display_name = (
            image_meta.os_name or None
        ) or affected_component_name
    else:
        event_component_display_name = affected_component_name
    original_content_json = _build_original_content(finding, image_meta)
    scanner_product_name = finding.tool_driver_full_name or PRODUCT_NAME

    event: Dict[str, Any] = {
        "event.provider": EVENT_PROVIDER,
        "event.type": EVENT_TYPE_VULNERABILITY_FINDING,
        "event.description": _format_event_description(
            finding.rule_id,
            object_name,
            OBJECT_TYPE_CONTAINER_IMAGE,
            event_component_display_name,
        ),
        "event.original_content": original_content_json,
        "product.vendor": PRODUCT_VENDOR,
        "product.name": scanner_product_name,
        "object.type": OBJECT_TYPE_CONTAINER_IMAGE,
        "object.id": object_id,
        "object.name": object_name,
        "artifact.filename": _artifact_filename(finding.artifact_path),
        "artifact.path": finding.artifact_path or None,
        "artifact.name": _artifact_filename(finding.artifact_path),
        "artifact.repository": repository_qualifier,
        "scan.id": scan_id,
        "scan.name": scan_id,
        "dt.security.risk.level": finding_severity,
        "dt.security.risk.score": risk_score,
        "vulnerability.id": finding.rule_id or None,
        "vulnerability.title": finding.short_description or finding.rule_id or None,
        "vulnerability.description": vulnerability_description,
        "vulnerability.references.cve": cve_reference_ids,
        "vulnerability.remediation.status": remediation_status,
        "vulnerability.remediation.fix_version": fix_version_list,
        "vulnerability.remediation.description": remediation_description,
        "finding.id": dynatrace_finding_id,
        "finding.type": FINDING_TYPE_DEPENDENCY_VULNERABILITY,
        "finding.title": f"Vulnerability {finding.rule_id} found in {object_id}",
        "finding.description": finding.message or None,
        "finding.time.created": scan_completed,
        "finding.score": risk_score,
        "finding.severity": finding_severity,
        "software_component.name": software_component.get("name") or None,
        "software_component.version": software_component.get("version") or None,
        "software_component.type": "library",
        "software_component.ecosystem": software_component.get("ecosystem") or None,
        "software_component.supplier.name": software_component.get("supplier") or None,
        "software_component.purl": software_component.get("purl") or primary_purl or None,
        "container_image.registry": "docker.io",
        "container_image.repository": repository_qualifier,
        "container_image.tags": image_meta.tags if image_meta else [image_ref.tag],
    }
    if image_meta and image_meta.digest:
        event["container_image.digest"] = image_meta.digest
    if is_os_package_vulnerability and image_meta:
        event["os.architecture"] = image_meta.architecture or None
        event["os.name"] = image_meta.os_name or None
        event["os.type"] = image_meta.platform_os or None
        event["os.version"] = image_meta.os_version or None
        event["component.name"] = image_meta.os_name or None
        event["component.version"] = image_meta.os_version or None
    else:
        event["component.name"] = software_component.get("name") or None
        event["component.version"] = software_component.get("version") or None
    return event