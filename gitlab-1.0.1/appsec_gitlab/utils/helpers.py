"""
Shared helpers for GitLab → Dynatrace mapping.

Responsibilities (by area):
    - **JSON / sizing**: ``make_json_safe``, ``split_by_size`` for ingest payloads.
    - **Identifiers**: CVE extraction, scanner ids, PURL building, object ids for findings.
    - **Scope filters**: ``filter_groups``, ``filter_projects`` for activation lists.
    - **Container images**: parse image strings, short refs, artifact paths, OS-level heuristics.
    - **Remediation**: ``parse_fix_versions`` from GitLab solution text.

Functions document their own arguments and return values below.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence

from dynatrace_extension.sdk.extension import extension_logger

from .urlutil import join_urls
from .constants import (
    CODE_ARTIFACT,
    CONTAINER_IMAGE,
    CONTAINER_SCANNING,
    CVE_EXTERNAL_TYPE,
    DEPENDENCY_SCANNING,
    SCANNER_EXTERNAL_ID_BY_HINT ,
    PACKAGE_TYPE_BY_FILE_NAME,
    PKG,)


def _get_positive_int(
    advanced_options: Mapping[str, object],
    key: str,
    default: int,
) -> int:
    """
    Read an activation ``advanced_options`` integer that must be >= 1.

    Args:
        advanced_options: ``advanced_options`` mapping from activation config.
        key: Option name (use ``utils.constants`` key constants).
        default: Fallback when the key is absent, empty, invalid, or not positive.

    Returns:
        Parsed positive int, or ``default`` when the value cannot be used.

    Note:
        Warnings use :data:`dynatrace_extension.sdk.extension.extension_logger`, which
        ``ExtensionImpl.initialize`` sets to the same level as the extension logger.
    """
    raw = advanced_options.get(key)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        extension_logger.warning(f"Invalid value for {key}={raw!r}; using default={default}")
        return default
    if value < 1:
        extension_logger.warning(f"Non-positive value for {key}={raw!r}; using default={default}")
        return default
    return value


def make_json_safe(value):
    """
    Recursively convert a value to JSON-serializable structures.

    Args:
        value: Any nested structure (dicts, lists, scalars).

    Returns:
        JSON-friendly object; non-mapping/list values fall back to ``str(value)``.
    """
    if value is None:
        return {}
    if isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): make_json_safe(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [make_json_safe(item) for item in value]
    return str(value)


def extract_gitlab_vulnerability_numeric_id(vulnerability_gid_or_id: str | int | None) -> str | None:
    """
    Parse the numeric id used in GitLab Security UI URLs from a vulnerability id.

    Args:
        vulnerability_gid_or_id: ``gid://gitlab/Vulnerability/270061206`` or plain ``270061206``.

    Returns:
        The trailing numeric segment, or ``None`` if not parseable.
    """
    if vulnerability_gid_or_id is None:
        return None
    s = str(vulnerability_gid_or_id).strip()
    if not s:
        return None
    if s.startswith("gid://"):
        tail = s.rsplit("/", 1)[-1]
        return tail if tail.isdigit() else None
    return s if s.isdigit() else None


def build_gitlab_vulnerability_ui_url(project_web_url: str | None, vulnerability_gid_or_id: str | int | None) -> str | None:
    """
    Build the project vulnerability detail page URL (Security → Vulnerability report).

    Pattern: ``{project.web_url}/-/security/vulnerabilities/{numeric_id}``.

    Args:
        project_web_url: GitLab project ``web_url`` (e.g. ``https://gitlab.com/group/project``).
        vulnerability_gid_or_id: GraphQL global id or numeric id from ``finding.id``.

    Returns:
        Full URL, or ``None`` if ``web_url`` or id is missing / invalid.
    """
    base = (project_web_url or "").strip().rstrip("/")
    vid = extract_gitlab_vulnerability_numeric_id(vulnerability_gid_or_id)
    if not base or not vid:
        return None
    return join_urls(base, "-", "security", "vulnerabilities", vid)


def first_finding_link_url(links: list | None) -> str | None:
    """
    Return the best HTTP(S) URL from GitLab ``finding.links`` (GraphQL ``VulnerabilityLink``).

    Prefers links whose path looks like the Security UI vulnerability route; otherwise
    returns the first valid ``http``/``https`` ``url`` field.

    Args:
        links: List of link dicts (``name``, ``url``) or similar; may be empty.

    Returns:
        A stripped URL, or ``None``.
    """
    if not links:
        return None
    candidates: list[str] = []
    for item in links:
        if isinstance(item, str):
            u = item.strip()
            if u.startswith(("http://", "https://")):
                candidates.append(u)
            continue
        if isinstance(item, Mapping):
            url = item.get("url") or item.get("href")
            if isinstance(url, str):
                u = url.strip()
                if u.startswith(("http://", "https://")):
                    if "/-/security/vulnerabilities/" in u or "/security/vulnerabilities/" in u:
                        return u
                    candidates.append(u)
    return candidates[0] if candidates else None


def resolve_gitlab_finding_url(
    project_web_url: str | None,
    vulnerability_gid_or_id: str | int | None,
    finding_links: list | None,
) -> str | None:
    """
    Prefer the built Security UI URL; fall back to ``finding.links`` when build fails.
    """
    built = build_gitlab_vulnerability_ui_url(project_web_url, vulnerability_gid_or_id)
    if built:
        return built
    return first_finding_link_url(finding_links)



def parse_fix_versions(solution: str | None) -> list[str]:
    """
    Extract version tokens from GitLab ``solution`` / remediation text.

    Args:
        solution: Raw remediation string, or None.

    Returns:
        Deduplicated list of version-like substrings; empty if ``solution`` is empty.
    """
    if not solution:
        return []

    text = solution.strip()

    match = re.search(
        r"(?:upgrade|update|fixed in|patched in|resolved in|use)\s+(.*)",
        text,
        flags=re.IGNORECASE,
    )
    candidate_text = match.group(1) if match else text

    versions = re.findall(
        r"\b\d+(?:\.\d+)+(?:[-._+~:]?[A-Za-z0-9]+)*\b",
        candidate_text,
    )

    return list(dict.fromkeys(versions))



def build_enabled_report_types(dependency_scanning_enabled: bool, container_scanning_enabled: bool) -> list[str]:
    """
    Map feature toggles to GitLab ``reportType`` strings used when filtering findings.

    Args:
        dependency_scanning_enabled: Include ``DEPENDENCY_SCANNING``.
        container_scanning_enabled: Include ``CONTAINER_SCANNING``.

    Returns:
        List of uppercase report type constants (may be empty if both false).
    """
    report_types: list[str] = []
    if dependency_scanning_enabled:
        report_types.append(DEPENDENCY_SCANNING)
    if container_scanning_enabled:
        report_types.append(CONTAINER_SCANNING)
    return report_types


def get_scanner_external_id(job_name: str | None, finding_scanner: dict | None = None) -> str | None:
    """
    Resolve ``product.name`` / scanner external id for Dynatrace.

    Args:
        job_name: CI job name (hint table when scanner block has no external id).
        finding_scanner: ``scanner`` object from GraphQL vulnerability node.

    Returns:
        External id string, or None if unknown.
    """
    scanner = finding_scanner or {}
    if scanner.get("externalId"):
        return scanner.get("externalId")
    normalized_job_name = str(job_name or "").lower()
    for hint, scanner_external_id in SCANNER_EXTERNAL_ID_BY_HINT.items():
        if hint in normalized_job_name:
            return scanner_external_id
    return None


def get_identifier_value(identifier: dict | None, *keys: str) -> str | None:
    """
    Return the first non-empty field among ``keys`` on an identifier dict.

    Args:
        identifier: Single identifier entry from a finding.
        *keys: Field names to try in order (e.g. ``externalId``, ``name``).

    Returns:
        First non-empty string value, or None.
    """
    if not isinstance(identifier, dict):
        return None
    for key in keys:
        value = identifier.get(key)
        if value not in (None, ""):
            return value
    return None


def find_identifier_by_type(identifiers: list[dict], identifier_type: str) -> dict | None:
    """
    Find the first identifier with a matching ``externalType`` (case-insensitive).

    Args:
        identifiers: List of identifier dicts from GitLab.
        identifier_type: Expected ``externalType`` (e.g. ``CVE_EXTERNAL_TYPE``).

    Returns:
        Matching identifier dict, or None.
    """
    expected_type = str(identifier_type or "").lower()
    for identifier in identifiers or []:
        current_type = str(get_identifier_value(identifier, "externalType") or "").lower()
        if current_type == expected_type:
            return identifier
    return None


def get_primary_identifier(identifiers: list[dict]) -> str | None:
    """
    Pick a display identifier (``externalId`` or ``name``) from the identifiers list.

    Args:
        identifiers: GitLab vulnerability identifiers.

    Returns:
        First useful id string, or None.
    """
    for identifier in identifiers or []:
        value = get_identifier_value(identifier, "externalId", "name")
        if value:
            return value
    return None


def get_cve_ids(identifiers: list[dict]) -> list[str]:
    """
    Collect CVE strings from identifiers with ``externalType`` matching ``CVE_EXTERNAL_TYPE``.

    Args:
        identifiers: GitLab vulnerability ``identifiers`` list.

    Returns:
        Ordered unique list of CVE ids (from ``externalId`` or ``name``).
    """
    cve_values: list[str] = []
    expected = CVE_EXTERNAL_TYPE.lower()
    for identifier in identifiers or []:
        if not isinstance(identifier, dict):
            continue
        current_type = str(get_identifier_value(identifier, "externalType") or "").lower()
        if current_type != expected:
            continue
        cve_value = get_identifier_value(identifier, "externalId", "name")
        if cve_value and str(cve_value).strip() and cve_value not in cve_values:
            cve_values.append(cve_value)
    return cve_values


def does_group_match(group: dict, selected_groups: set[str]) -> bool:
    """
    Args:
        group: Raw GitLab group dict.
        selected_groups: Lowercased paths/names configured by the user (empty set = match all).

    Returns:
        True if the group should be included.
    """
    if not selected_groups:
        return True
    candidates = {
        str(group.get("full_path", "")).lower(),
        str(group.get("path", "")).lower(),
        str(group.get("name", "")).lower(),
    }
    return any(candidate in selected_groups for candidate in candidates if candidate)


def filter_groups(groups: list[dict], all_groups: bool, selected_groups: list[str]) -> list[dict]:
    """
    Args:
        groups: Groups returned by the GitLab API.
        all_groups: If True, return ``groups`` unchanged.
        selected_groups: When ``all_groups`` is False, allow-list of group path/name strings.

    Returns:
        Filtered list of group dicts.
    """
    if all_groups:
        return groups
    selected_group_values = {str(value).strip().lower() for value in (selected_groups or []) if str(value).strip()}
    return [group for group in groups if does_group_match(group, selected_group_values)]


def does_project_match(project: dict, selected_projects: set[str]) -> bool:
    """
    Args:
        project: Raw GitLab project dict.
        selected_projects: Lowercased paths/names (empty = match all).

    Returns:
        True if the project should be included.
    """
    if not selected_projects:
        return True
    candidates = {
        str(project.get("path_with_namespace", "")).lower(),
        str(project.get("path", "")).lower(),
        str(project.get("name", "")).lower(),
    }
    return any(candidate in selected_projects for candidate in candidates if candidate)


def filter_projects(projects: list[dict], all_projects: bool, selected_projects: list[str]) -> list[dict]:
    """
    Args:
        projects: Projects under a group.
        all_projects: If True, return all.
        selected_projects: Allow-list when ``all_projects`` is False.

    Returns:
        Filtered project dicts.
    """
    if all_projects:
        return projects
    selected_project_values = {str(value).strip().lower() for value in (selected_projects or []) if str(value).strip()}
    return [project for project in projects if does_project_match(project, selected_project_values)]


def build_software_component_purl(report_type: str | None, location: dict) -> str | None:
    """
    Build a Package URL-style string for ``software_component.purl``.

    Args:
        report_type: ``CONTAINER_SCANNING`` vs dependency scanning drives the namespace segment.
        location: GitLab vulnerability ``location`` object.

    Returns:
        PURL string, or None if package name is missing.
    """
    component_name = location.get("dependency", {}).get("package", {}).get("name")
    if not component_name:
        return None
    if str(report_type or "").upper() == CONTAINER_SCANNING:
        operating_system = str(location.get("operatingSystem") or location.get("operating_system") or "").strip().lower()
        return f"{PKG}:{(operating_system.split()[0] if operating_system else 'generic')}/{component_name}"
    file = PACKAGE_TYPE_BY_FILE_NAME.get(location.get('file'), '').lower()
    return f"{PKG}:{file}/{component_name}"


def get_object_type(report_type: str | None) -> str:
    """
    Args:
        report_type: GitLab ``reportType`` string.

    Returns:
        ``CONTAINER_IMAGE`` or ``CODE_ARTIFACT`` constant.
    """
    return CONTAINER_IMAGE if str(report_type or "").upper() == CONTAINER_SCANNING else CODE_ARTIFACT


def get_object_name(project_name: str | None, report_type: str | None, location: dict) -> str | None:
    """
    Args:
        project_name: Fallback for dependency scans.
        report_type: Determines container vs code artifact.
        location: Vulnerability location (image vs lockfile path).

    Returns:
        Human-readable object name segment for ``object.id`` / display.
    """
    if get_object_type(report_type) == CONTAINER_IMAGE:
        return location.get("image")
    return location.get("file") or project_name


def build_object_id(project_path: str | None, object_name: str | None) -> str | None:
    """
    Args:
        project_path: GitLab project path with namespace.
        object_name: Lockfile path or image reference fragment.

    Returns:
        Combined ``project_path/object_name``, or whichever part exists.
    """
    if project_path and object_name:
        return f"{project_path}/{object_name}"
    return project_path or object_name


def split_container_image(location: dict) -> tuple[str | None, str | None, list[str]]:
    """
    Split ``location["image"]`` into registry host, repository path, and tag list.

    Args:
        location: Vulnerability location dict.

    Returns:
        ``(registry, repository, tags)``. Tag list is empty when reference has no ``:tag``
        (or uses digest-only form stripped before parsing).
    """
    image = str((location or {}).get("image") or "").strip()
    if not image:
        return None, None, []

    image_without_digest = image.split("@", 1)[0]
    registry = None
    repository_with_tag = image_without_digest

    first_segment = image_without_digest.split("/", 1)[0]
    if "/" in image_without_digest and ("." in first_segment or ":" in first_segment or first_segment == "localhost"):
        registry, repository_with_tag = image_without_digest.split("/", 1)

    last_slash = repository_with_tag.rfind("/")
    last_colon = repository_with_tag.rfind(":")
    if last_colon <= last_slash:
        return registry, repository_with_tag, []

    repository = repository_with_tag[:last_colon]
    tag = repository_with_tag[last_colon + 1 :]
    return registry, repository, [tag] if tag else []


def get_container_image_basename(location: dict) -> str | None:
    """
    Args:
        location: Vulnerability location with ``image`` field.

    Returns:
        Last path segment of the repository plus optional tag (e.g. ``eclipse-temurin:latest``),
        for ``artifact.filename``, ``object.id``, and ``object.name`` on container findings.
    """
    _, repository, tags = split_container_image(location)
    if not repository:
        return None
    base = repository.rsplit("/", 1)[-1]
    if tags:
        return f"{base}:{tags[0]}"
    return base or None


def get_short_container_image_reference(location: dict) -> str | None:
    """
    Args:
        location: Vulnerability location with ``image`` field.

    Returns:
        Short ``image:tag`` (last repository segment + tag); same as :func:`get_container_image_basename`.
    """
    return get_container_image_basename(location)


def shorten_container_image_object_string(value: str | None) -> str | None:
    """
    Collapse a long image reference to ``last_segment:tag`` for ``object.id`` / ``object.name``.

    GitLab sometimes reports paths like ``group/project/image:tag``; this keeps only the
    final repository segment plus tag (e.g. ``metron-security/java/eclipse-temurin:latest``
    → ``eclipse-temurin:latest``).
    """
    if not value or not str(value).strip():
        return None
    s = str(value).strip()
    if ":" in s:
        head, _, tag = s.rpartition(":")
        if "/" in head:
            head = head.rsplit("/", 1)[-1]
        return f"{head}:{tag}" if tag else (head or None)
    if "/" in s:
        return s.rsplit("/", 1)[-1] or None
    return s


def resolve_container_image_repository_for_ingest(
    repository: str | None,
    repository_path: str | None,
) -> str | None:
    """
    Parsed registry repository path after ``split_container_image`` (may include image name).

    Used on ``VulnerabilityDetails`` for ``artifact.path`` assembly and similar. The Dynatrace
    field ``container_image.repository`` on emitted events is set from the GitLab project
    ``repository_path`` instead (see ``events/vulnerability_finding`` / ``events/scan``).
    """
    if not repository:
        return None
    rp = (repository_path or "").strip().rstrip("/")
    if not rp:
        return repository
    rpl = repository.lower()
    rplow = rp.lower()
    if rpl == rplow or rpl.startswith(rplow + "/"):
        return repository
    if "/" in repository:
        return repository
    return f"{rp}/{repository}"


def strip_repository_path_prefix_from_image(image: str, repository_path: str | None) -> str:
    """
    If ``image`` starts with the GitLab project path plus ``/``, drop that prefix once.

    Some payloads duplicate ``path_with_namespace`` before the image name.
    """
    raw = (image or "").strip()
    rp = (repository_path or "").strip().rstrip("/")
    if not raw or not rp:
        return raw
    prefix = f"{rp}/"
    if raw.lower().startswith(prefix.lower()):
        return raw[len(prefix) :]
    return raw


def get_container_image_artifact_path(location: dict) -> str | None:
    """
    Args:
        location: Vulnerability location with ``image`` field.

    Returns:
        ``registry/repository`` without tag (for ``artifact.path`` on containers).
    """
    registry, repository, _tags = split_container_image(location)
    if not repository:
        return None
    if registry:
        return f"{registry}/{repository}"
    return repository


# Substrings in dependency version strings that indicate distro/OS packaging (dpkg/rpm-style),
# as opposed to bare application semver (e.g. 1.2.3 with no distro revision).
_DISTRO_PACKAGE_VERSION_MARKERS: tuple[str, ...] = (
    "deb",  # Debian: +deb13u1, deb12, etc.
    "ubuntu",  # Ubuntu: 2ubuntu17.4, 2ubuntu10.6
    "rhel",
    ".el",
    "el7",
    "el8",
    "el9",
    "amzn",
    "alpine",
    "+deb",
    "-ubuntu",
    ".fc",  # Fedora
    "rocky",
    "almalinux",
    "opensuse",
    "suse",
)


def looks_like_distro_package_version(version: str | None) -> bool:
    """
    Heuristic: distro package revision strings (deb/rpm-style) vs plain semver.

    Args:
        version: Dependency version from GitLab location.

    Returns:
        True if substring markers indicate OS/distro packaging.
    """
    if version is None:
        return False
    v = str(version).strip().lower()
    if not v:
        return False
    return any(marker in v for marker in _DISTRO_PACKAGE_VERSION_MARKERS)


def is_container_os_level_vulnerability(location: Mapping | None) -> bool:
    """
    Decide whether to emit ``os.name`` / ``os.version`` / ``os.type`` for a container finding.

    When True, ``FindingEventBuilder`` sets ``component.name`` / ``component.version`` from
    the same OS fields so component rows match the OS table (distro-level CVEs). ``software_component.*``
    stays on the vulnerable package from GitLab.

    Args:
        location: GitLab vulnerability ``location`` mapping.

    Returns:
        True if ``operatingSystem`` is set and dependency ``version`` looks like a distro build.
    """
    if not location:
        return False
    os_str = str(
        location.get("operatingSystem") or location.get("operating_system") or ""
    ).strip()
    if not os_str:
        return False
    dep = location.get("dependency")
    if not isinstance(dep, Mapping):
        return False
    ver = dep.get("version")
    ver_s = str(ver).strip() if ver is not None else ""
    return looks_like_distro_package_version(ver_s or None)


def parse_operating_system(operating_system: str | None) -> tuple[str | None, str | None, str | None]:
    """
    Args:
        operating_system: GitLab string such as ``debian 13.1``.

    Returns:
        ``(os_name, os_version, os_type)`` with ``os_type`` fixed to ``linux`` when set,
        else ``(None, None, None)``.
    """
    normalized = str(operating_system or "").strip()
    if not normalized:
        return None, None, None
    parts = normalized.split()
    os_name = parts[0] if parts else None
    os_version = " ".join(parts[1:]) if len(parts) > 1 else None
    return os_name, os_version, "linux"


def split_by_size(records: list[dict], max_bytes: int) -> list[list[dict]]:
    """
    Partition event dicts so each chunk's JSON serialization stays under a byte budget.

    Args:
        records: Flat security event dicts.
        max_bytes: Maximum UTF-8 byte length per chunk (including JSON array framing).

    Returns:
        List of chunks, each a list of dicts.
    """
    chunks: list[list[dict]] = []
    current_chunk: list[dict] = []
    current_size = 2

    for record in records:
        record_size = len(json.dumps(make_json_safe(record), separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        separator_size = 1 if current_chunk else 0
        next_size = current_size + separator_size + record_size

        if current_chunk and next_size > max_bytes:
            chunks.append(current_chunk)
            current_chunk = [record]
            current_size = 2 + record_size
            continue

        current_chunk.append(record)
        current_size = next_size

    if current_chunk:
        chunks.append(current_chunk)

    return chunks
