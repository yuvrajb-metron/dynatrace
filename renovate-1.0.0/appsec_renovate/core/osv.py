"""
OSV (Open Source Vulnerabilities) API logic: enrich vulnerability findings from Renovate logs.
Builds a GHSA ID -> enriched info map from Renovate log lines and OSV API responses.
"""

import re
from typing import Any, List, Dict, Optional
from ..clients.http_client import RestApiHandler
from ..models import DependencyDetails, OsvEnrichedInfo
from dynatrace_extension.sdk.extension import extension_logger as logger
from cvss import CVSS4 , CVSS3, CVSS2

CVSS_MAPPING = {
    "CVSS_V4": CVSS4,
    "CVSS_V3": CVSS3,
    "CVSS_V2": CVSS2,
}

OSV_API_BASE = "https://api.osv.dev"
OSV_VULNS_PATH = "/v1/vulns/"

RISK_LEVEL_MAPPING = {
    "critical": 10.0,
    "high": 8.9,
    "medium": 6.9,
    "moderate": 6.9,
    "low": 3.9
}

def parse_vulnerability_msg(msg: str) -> tuple[str, str] | None:
    """
    Pulls GHSA ID and dependency name from a Renovate log message.
    Input: one log line (e.g. "Vulnerability GHSA-xxx affects debug 2.2.0").
    Returns (ghsa_id, dependency_name) or None if the line is not a vulnerability message.
    """
    parts = msg.split(" ")
    ghsa_id = None
    dependency_name = None
    if len(parts) > 1:
        ghsa_id = parts[1]
        dependency_name = parts[-2]
    return (ghsa_id, dependency_name)

def get_cvss_score(cvss_type, vector , severity) -> float:
    # Get the class from our map
    cvss_class = CVSS_MAPPING.get(cvss_type,"")
    logger.debug(f"Calculating CVSS score for type '{cvss_type}' with vector '{vector}' and severity '{severity}'") 
    if cvss_class:
        return max(cvss_class(vector).scores())
    elif severity:
        score = RISK_LEVEL_MAPPING.get(severity.lower(), 0.0)
        logger.debug(f"No CVSS vector found, mapping severity '{severity}' to score {score}.")
        return score
    else:
        logger.debug(f"Warning: Unsupported CVSS type '{cvss_type}'")
        return 0.0

def get_cvss_details(severity_list: list[dict[str, Any]], severity: str | None = None) -> Optional[tuple[str, float]]:
    """
    Finds the highest CVSS version entry and returns its (version, score).
    """
    if severity_list:
        highest_entry = max(severity_list, key=lambda x: x.get('type', ''))
        cvss_type = highest_entry.get('type')
        vector = highest_entry.get('score', '')
    else:
        cvss_type , vector= "", ""
        logger.debug("No severity list provided.")
    score = get_cvss_score(cvss_type, vector,severity)
    try:
        # Example: "CVSS:3.1/AV:N..." -> "3.1"
        cvss_version = vector.split(':')[1].split('/')[0]
    except (IndexError, AttributeError):
        cvss_version = 0.0
        # If type is unknown, return None instead of a confusing (None, 0.0)
        logger.debug(f"Warning: Unsupported CVSS type '{cvss_type}'")
    return cvss_version , score

def _extract_remediation_versions(affected: list[Any]) -> list[str]:
    """
    Collects every "fixed" (or "last_affected") version from OSV affected ranges.
    Input: OSV response "affected" array. Used to show which versions fix the vuln.
    Returns a list of version strings, no duplicates.
    """
    versions: list[str] = []
    seen: set[str] = set()
    for affected_item in affected or []:
        for range_item in affected_item.get("ranges") or []:
            for range_event in range_item.get("events") or []:
                fixed = range_event.get("fixed") or range_event.get("last_affected")
                if fixed and isinstance(fixed, str) and fixed not in seen:
                    seen.add(fixed)
                    versions.append(fixed)
    return versions


def _split_details_for_remediation(details: str | None) -> tuple[str | None, str]:
    """
    Splits OSV "details" text into description vs patches/recommendation.
    Input: raw details string from OSV. Splits at "Patches" or "Recommendation".
    Returns (description_part, remediation_part); description can be None.
    """
    if not details or not isinstance(details, str):
        return (None, "")
    idx_patches = details.find("Patches")
    idx_recommendation = details.find("Recommendation")
    candidates = [i for i in (idx_patches, idx_recommendation) if i >= 0]
    if not candidates:
        return (details.strip() or None, "")
    split_at = min(candidates)
    enhanced = details[:split_at].strip() or None
    remediation = details[split_at:].strip()
    return (enhanced, remediation)


def _extract_purl(affected: list[Any]) -> str | None:
    """
    Gets the first package URL (purl) from OSV "affected" entries.
    Input: OSV response "affected" array. Purl identifies the package (e.g. npm, pypi).
    Returns the purl string or None if not present.
    """
    for affected_item in affected or []:
        package = affected_item.get("package")
        if isinstance(package, dict):
            purl = package.get("purl")
            if purl and isinstance(purl, str):
                return purl
    return None


def _search_text_for_cve_patterns(text: str) -> List[str]:
    """
    Scans a string for the standard CVE pattern (CVE-YYYY-NNNNN).
    This is used as a utility for scanning URLs and descriptions.
    """
    if not text:
        return []
    # Matches CVE- followed by 4 digits, a dash, and 4 or more digits
    cve_regex = r'CVE-\d{4}-\d{4,}'
    matches = re.findall(cve_regex, text, re.IGNORECASE)
    # Normalize to uppercase for consistency
    return [match.upper() for match in matches]

def _extract_cve_identifiers(osv_response: Dict[str, Any]) -> List[str]:
    """
    Extracts CVE IDs from an OSV record using a priority-based fallback strategy:
    1. Direct Aliases
    2. Reference URLs
    3. Detailed Description Text
    """
    # 1. Primary Check: 'aliases' field
    aliases = osv_response.get("aliases") or []
    cve_ids = [
        alias.upper() for alias in aliases 
        if isinstance(alias, str) and alias.upper().startswith("CVE-")
    ]
    
    # 2. Secondary Check: 'references'
    if not cve_ids:
        references = osv_response.get("references") or []
        for ref in references:
            url = ref.get("url", "")
            cve_ids.extend(_search_text_for_cve_patterns(url))
            logger.debug(f"Extracted CVEs from URL '{url}': {cve_ids}")
    # 3. Tertiary Check: 'details'
    if not cve_ids:
        description_text = osv_response.get("details") or ""
        cve_ids = _search_text_for_cve_patterns(description_text)
        logger.debug(f"Extracted CVEs from description text: {cve_ids}")

    # Remove duplicates while preserving discovery order
    return list(dict.fromkeys(cve_ids))


def build_osv_info_value(
    osv_response: dict[str, Any],
    msg: str,
    dependency_name: str,
    log_time: str,
    ghsa_id: str,
    branches_info_event: dict,
    package_files_event: dict,
) -> OsvEnrichedInfo:
    """
    Builds one enriched record (summary, severity, CVEs, fix versions, etc.) for a GHSA.
    Input: OSV API response for that GHSA, plus Renovate log msg/time, branch info, and package files event.
    Returns OsvEnrichedInfo used later for Dynatrace events.
    """
    osv_details = osv_response.get("osv_details", {})
    affected = osv_details.get("affected") or []
    db_specific = osv_details.get("database_specific") or {}
    severity_list = osv_details.get("severity") or []
    raw_details = osv_details.get("details")

    remediation_versions = _extract_remediation_versions(affected)
    enhanced_details, remediation_description = _split_details_for_remediation(raw_details)
    cves = _extract_cve_identifiers(osv_details)

    severity = db_specific.get("severity")
    cvss_version , score = get_cvss_details(severity_list, severity)
    dependency_details = find_dependency_details(
        branches_info_event, dependency_name, package_files_event
    )
    osv_response["finding_details"] = dependency_details.to_dict() if dependency_details else None
    value_dict = {
        "msg": msg,
        "dependencyName": dependency_name,
        "time": log_time,
        "summary": osv_details.get("summary"),
        "details": raw_details,
        "remediation_version": remediation_versions,
        "enhanced_details": enhanced_details,
        "remediation_description": remediation_description,
        "severity": db_specific.get("severity"),
        "purl": _extract_purl(affected),
        "score": score,
        "cves": cves,
        "original_content": osv_response,
        "ghsa_id": ghsa_id,
        "cvss_version": cvss_version,
    }

    return OsvEnrichedInfo(value_dict, dependency_details=dependency_details)


def fetch_osv_vuln(ghsa_id: str) -> dict[str, Any] | None:
    """
    Calls OSV API to get full vulnerability details for one GHSA ID.
    Input: GHSA string (e.g. GHSA-xxxx-yyyy-zzzz). No auth required.
    Returns the OSV JSON object or None on network/parse error.
    """
    url = f"{OSV_API_BASE}{OSV_VULNS_PATH}{ghsa_id}"
    try:
        logger.debug(f"Fetching OSV vuln: {ghsa_id}")
        response = RestApiHandler().get_url(url=url)
        return response.json()
    except Exception as err:
        logger.error(f"Failed to fetch OSV vuln {ghsa_id}: {err}")
        return None

def _resolve_package_file(group: dict, dep: dict) -> str:
    """
    Resolve package file path: group level, then dep-level (e.g. managerData.packageFile
    for Gradle/Maven deps like org.json:json).
    """
    return (
        group.get("packageFile")
        or (dep.get("managerData") or {}).get("packageFile")
        or dep.get("packageFile")
        or ""
    )


def _extract_update_fields(dep: dict) -> tuple[str, str, str]:
    """Get newVersion, updateType, branchName from first update entry or from dep."""
    first_update = (dep.get("updates") or [None])[0]
    if isinstance(first_update, dict):
        return (
            first_update.get("newVersion", ""),
            first_update.get("updateType", ""),
            first_update.get("branchName", ""),
        )
    return (
        dep.get("newVersion", ""),
        dep.get("updateType", ""),
        dep.get("branchName", ""),
    )


def _dep_matches_dependency_name(dep: dict, dependency_name: str) -> bool:
    """True if dep has a depName that matches the given dependency name."""
    dep_name = dep.get("depName")
    return bool(dep_name and dep_name == dependency_name)


def _build_dependency_details_from_dep(dep: dict, group: dict) -> DependencyDetails:
    """Build DependencyDetails from a matched dep and its package file group."""
    package_file = _resolve_package_file(group, dep)
    new_version, update_type, branch_name = _extract_update_fields(dep)
    data = {
        "depName": dep.get("depName"),
        "currentVersion": dep.get("currentVersion") or dep.get("currentValue"),
        "packageFile": package_file,
        "packageName": dep.get("packageName"),
        "newVersion": new_version,
        "prTitle": "",
        "updateType": update_type,
        "branchName": branch_name,
    }
    return DependencyDetails(data)


def _find_matching_dep_in_package_config(
    config: dict,
    dependency_name: str,
) -> DependencyDetails | None:
    """
    Walk config (manager -> list of package file groups -> deps) and return
    DependencyDetails for the first dep whose depName matches dependency_name.
    """
    for manager_key, package_file_groups in config.items():
        if not isinstance(package_file_groups, list):
            continue
        for group in package_file_groups:
            if not isinstance(group, dict):
                continue
            for dep in group.get("deps") or []:
                if not isinstance(dep, dict):
                    continue
                if not _dep_matches_dependency_name(dep, dependency_name):
                    continue
                return _build_dependency_details_from_dep(dep, group)
    return None


def fetch_dependency_details_from_package_event(
    package_files_event: dict,
    dependency_name: str,
) -> DependencyDetails | None:
    """
    Look up a dependency in the Renovate "packageFiles with updates" event.
    Searches config (manager -> package file groups -> deps). When depName matches
    (or is contained in dependency_name), builds DependencyDetails; prTitle is left
    empty (not present in this event). Returns None if not found.
    """
    if not package_files_event or not dependency_name:
        return None
    config = package_files_event.get("config") or {}
    return _find_matching_dep_in_package_config(config, dependency_name)


def find_dependency_details(
    branches_info_event: dict,
    dependency_name: str,
    package_files_event: dict,
) -> DependencyDetails | None:
    """
    Looks up branch/PR context for a dependency from Renovate "branches info" event.
    If not found, falls back to fetch_dependency_details_from_package_event.
    Input: branches info payload, dependency name (e.g. "debug"), and package files event.
    Returns DependencyDetails (upgrade, branch, PR title) or None if not found.
    """
    for branch in branches_info_event.get("branchesInformation", []):
        prTitle = branch.get("prTitle", "")
        branchName = branch.get("branchName", "")
        for upgrade in branch.get("upgrades", []):
            if upgrade.get("depName") == dependency_name:
                upgrade["prTitle"] = prTitle
                upgrade["branchName"] = branchName
                return DependencyDetails(upgrade)
    return fetch_dependency_details_from_package_event(
        package_files_event, dependency_name
    )

def build_ghsa_to_osv_map(
    vulnerability_finding_logs: list[dict],
    branches_info_event: dict,
    package_files_event: dict,
) -> dict[str, list[OsvEnrichedInfo]]:
    """
    Turns Renovate vulnerability log lines into a GHSA -> enriched OSV info map.
    Input: list of finding log dicts, branches info, and package files event.
    Calls OSV once per GHSA. Dependency details are resolved from branches info, then package files as fallback.
    Returns dict: each GHSA ID maps to a list of OsvEnrichedInfo (one per dependency).
    """
    result: dict[str, list[OsvEnrichedInfo]] = {}
    osv_cache: dict[str, dict | None] = {}
    for finding_log in vulnerability_finding_logs:
        msg = (finding_log.get("msg") or "").strip()
        event_time = (finding_log.get("time") or "").strip()
        parsed = parse_vulnerability_msg(msg)
        if not parsed:
            continue
        ghsa_id, dependency_name = parsed
        if ghsa_id not in result:
            result[ghsa_id] = []
        if ghsa_id not in osv_cache:
            osv_cache[ghsa_id] = fetch_osv_vuln(ghsa_id)
        osv_response = {}
        osv_response["osv_details"] = osv_cache[ghsa_id]
        osv_response["vulnerability_event_details"] = finding_log
        result[ghsa_id].append(
            build_osv_info_value(
                osv_response=osv_response,
                msg=msg,
                dependency_name=dependency_name,
                log_time=event_time,
                ghsa_id=ghsa_id,
                branches_info_event=branches_info_event,
                package_files_event=package_files_event,
            )
        )
    total_findings = sum(len(enriched_list) for enriched_list in result.values())
    logger.info(
        "Built OSV map for %d unique GHSA ID(s), %d total finding(s)",
        len(result), total_findings,
    )
    return result
