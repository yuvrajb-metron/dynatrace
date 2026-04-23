"""
Parse SARIF JSON from docker scout cves --format sarif.

Uses runs[0].tool.driver.rules (indexed by id) and runs[0].results.
Returns a list of ParsedFinding.
"""

import json
from typing import Any, Dict, List, Optional, Tuple

from appsec_dockerscout.models import ParsedFinding
from dynatrace_extension.sdk.extension import extension_logger as logger


def _artifact_uris(sarif_result: dict) -> List[str]:
    """
    Collect ordered ``artifactLocation.uri`` values from a SARIF result's ``locations``.

    Args:
        sarif_result: One SARIF ``results[]`` object.

    Returns:
        Non-empty URI strings in list order.
    """
    location_uri_list: List[str] = []
    for location in sarif_result.get("locations") or []:
        if not isinstance(location, dict):
            continue
        physical_location = location.get("physicalLocation")
        if not isinstance(physical_location, dict):
            physical_location = {}
        artifact_location = physical_location.get("artifactLocation")
        if not isinstance(artifact_location, dict):
            artifact_location = {}
        uri_raw = artifact_location.get("uri")
        if not isinstance(uri_raw, str):
            continue
        normalized_uri = uri_raw.strip()
        if normalized_uri:
            location_uri_list.append(normalized_uri)
    return location_uri_list


def parse_sarif(sarif_json: str) -> Tuple[List[ParsedFinding], Optional[str]]:
    """
    Parse SARIF JSON from docker scout cves --format sarif.

    Args:
        sarif_json: Raw SARIF JSON string.

    Returns:
        (findings, tool_driver_full_name) where tool_driver_full_name is
        runs[0].tool.driver.fullName (e.g. \"Docker Scout\") when present.
        Uses runs[0].tool.driver.rules and runs[0].results; empty list on decode error.
        One ParsedFinding per artifact location URI per result; each carries the full
        SARIF result in ``result_raw`` (all locations). ``event.original_content`` embeds
        a copy of the result with ``locations`` trimmed to that finding's URI only.
    """
    sarif_input_length = len(sarif_json) if sarif_json else 0
    logger.debug(f"parse_sarif started: input_len={sarif_input_length}")
    findings: List[ParsedFinding] = []
    try:
        sarif_root = json.loads(sarif_json)
    except json.JSONDecodeError as decode_error:
        logger.warning(f"SARIF JSON decode error: {decode_error}")
        return findings, None
    sarif_version = sarif_root.get("version")
    if sarif_version is not None and not isinstance(sarif_version, str):
        sarif_version = str(sarif_version)
    sarif_schema = sarif_root.get("$schema")
    if sarif_schema is not None and not isinstance(sarif_schema, str):
        sarif_schema = str(sarif_schema)

    sarif_runs = sarif_root.get("runs") or []
    logger.debug(f"parse_sarif: runs count={len(sarif_runs)}")
    if not sarif_runs:
        return findings, None
    primary_run = sarif_runs[0]
    run_tool = primary_run.get("tool") or {}
    tool_driver = run_tool.get("driver") or {}
    driver_full_name_raw = tool_driver.get("fullName")
    tool_driver_full_name: Optional[str] = None
    if driver_full_name_raw is not None:
        tool_driver_full_name = (
            driver_full_name_raw
            if isinstance(driver_full_name_raw, str)
            else str(driver_full_name_raw)
        )
    driver_rules = tool_driver.get("rules") or []
    rules_by_id: Dict[str, dict] = {
        rule_dict.get("id", ""): rule_dict
        for rule_dict in driver_rules
        if rule_dict.get("id")
    }
    run_results = primary_run.get("results") or []
    logger.debug(
        f"parse_sarif: rules_by_id count={len(rules_by_id)}, "
        f"results count={len(run_results)}"
    )
    for result_dict in run_results:
        if not isinstance(result_dict, dict):
            continue
        rule_id = result_dict.get("ruleId") or ""
        rule_for_id = rules_by_id.get(rule_id) or {}
        result_message = result_dict.get("message") or {}
        result_message_text = (
            result_message.get("text")
            if isinstance(result_message.get("text"), str)
            else ""
        )
        rule_properties = rule_for_id.get("properties") or {}
        property_tags = rule_properties.get("tags")
        if isinstance(property_tags, list):
            severity_value = (
                rule_properties.get("cvssV3_severity")
                or property_tags
                or ["UNSPECIFIED"]
            )[0]
        else:
            severity_value = (
                rule_properties.get("cvssV3_severity") or "UNSPECIFIED"
            )
        if isinstance(severity_value, list):
            severity_value = severity_value[0] if severity_value else "UNSPECIFIED"
        security_score = rule_properties.get("security-severity")
        if security_score is not None and not isinstance(
            security_score, (int, float)
        ):
            try:
                security_score = float(security_score)
            except (TypeError, ValueError):
                security_score = None
        property_purls = rule_properties.get("purls") or []
        if not isinstance(property_purls, list):
            property_purls = []
        short_description_obj = rule_for_id.get("shortDescription") or {}
        short_description_text = ""
        if isinstance(short_description_obj, dict):
            short_description_text = short_description_obj.get("text") or ""
        help_metadata = rule_for_id.get("help") or {}
        help_text = (
            help_metadata.get("text")
            if isinstance(help_metadata.get("text"), str)
            else ""
        )
        help_uri = rule_for_id.get("helpUri")
        rule_raw = dict(rule_for_id) if rule_for_id else {}
        result_raw: Dict[str, Any] = dict(result_dict)

        artifact_location_uris = _artifact_uris(result_dict)
        location_uri_count = len(artifact_location_uris)
        findings_emitted_for_result = location_uri_count if location_uri_count else 1
        log_rule_identifier = rule_id if rule_id else "(no ruleId)"
        logger.info(
            f"parse_sarif: {log_rule_identifier} → {findings_emitted_for_result} "
            f"finding record(s) ({location_uri_count} artifact URI(s))"
        )

        for artifact_path in artifact_location_uris or [""]:
            findings.append(
                ParsedFinding(
                    rule_id=rule_id,
                    message=result_message_text,
                    artifact_path=artifact_path,
                    severity=str(severity_value),
                    security_score=security_score,
                    purls=property_purls,
                    affected_version=rule_properties.get("affected_version"),
                    fixed_version=rule_properties.get("fixed_version"),
                    short_description=short_description_text,
                    help_text=help_text,
                    help_uri=help_uri,
                    sarif_version=sarif_version,
                    sarif_schema=sarif_schema,
                    rule_raw=rule_raw,
                    result_raw=result_raw,
                    tool_driver_full_name=tool_driver_full_name,
                )
            )
    logger.debug(f"parse_sarif finished: {len(findings)} finding(s).")
    return findings, tool_driver_full_name
