import uuid
from datetime import datetime
from urllib.parse import urljoin

from dynatrace_extension.sdk.extension import extension_logger as logger
from requests.exceptions import HTTPError

from ...models.webapp_scanning.findings import WebAppFinding
from ...models.webapp_scanning.scans import WAScan
from ...models.webapp_scanning.vulnerabilities import Vulnerability, VulnerabilityDetails, VulnerabilityStore
from ...rest_interface import RestApiHandler
from ..shared import get_risk_score_from_level, paged_endpoint, parse_url


def get_vulns_data(
    tio_manual_interface: RestApiHandler,
    datetime_day_to_query: str,
    datetime_to_query: datetime,
) -> VulnerabilityStore:
    was_vulns = VulnerabilityStore()
    for vuln in paged_endpoint(
        tio_manual_interface.post_url,
        urljoin(tio_manual_interface.url, "/was/v2/vulnerabilities/search"),
        headers=[],
        params={
            "limit": 100,
        },
        json={"field": "vulns.created_at", "operator": "gte", "value": datetime_day_to_query},
    ):
        vulnerability = Vulnerability(vuln)

        if datetime.fromisoformat(vulnerability.created_at.replace("Z", "+00:00")) >= datetime_to_query:
            # logger.debug(f"Getting vuln details for {vulnerability.vuln_id}")
            try:
                vulnerability_details = tio_manual_interface.get_url(
                    urljoin(tio_manual_interface.url, f"/was/v2/vulnerabilities/{vulnerability.vuln_id}"),
                    headers=[],
                )
                was_vulns.add_vulnerability(
                    vuln_id=vulnerability.vuln_id,
                    scan_id=vulnerability.scan_id,
                    plugin_id=vulnerability.plugin_id,
                    vulnerability_details=VulnerabilityDetails(vulnerability_details.json()),
                )
            except HTTPError:
                logger.warning(
                    f"Unable to get WAS vulnerability details for vulnerability {vulnerability.vuln_id}"
                )
                raise

    return was_vulns


def generate_event_from_webapp_finding(
    finding: WebAppFinding,
    recent_was_scans_history: dict[str, WAScan],
    was_vulns: VulnerabilityStore,
    tenable_url: str,
    ingest_as_logs: bool = False,
) -> list[dict]:
    try:
        # Scan details
        scan_uuid = finding.scan.uuid
        # schedule_uuid = finding.scan.schedule_uuid
        scan = recent_was_scans_history.get(scan_uuid)
        if scan:
            # Scan found for this particular UUID
            scan_name = scan.scanner.group_name
            scan_status = scan.status
            scan_end_time = scan.finalized_at if scan.finalized_at else None
            scan_start_time = scan.started_at if scan.started_at else None
            scan_target = scan.target
        else:
            logger.warning(f"Scan {finding.scan.uuid} not found for webapp finding {finding.finding_id}")
            new_scan_event = WAScan(
                {
                    "asset_id": finding.asset.uuid,
                    "scan_id": finding.scan.uuid,
                    "target": finding.url,
                    "finalized_at": finding.scan.completed_at,
                    "started_at": finding.scan.completed_at,
                    "status": "completed",
                    "scanner": {
                        "group_name": finding.scan.uuid,
                    },
                    "from_vuln": True,
                }
            )
            recent_was_scans_history[finding.scan.uuid] = new_scan_event
            scan_name = new_scan_event.scanner.group_name
            scan_status = new_scan_event.status
            scan_end_time = new_scan_event.finalized_at
            scan_start_time = new_scan_event.started_at
            scan_target = new_scan_event.target

        plugin = finding.plugin
        if plugin:  # should always be true
            plugin_id = plugin.id
            plugin_cpes = plugin.cpe  # might be empty, is list
            plugin_name = plugin.name
            plugin_description = plugin.description
            plugin_cves = plugin.cve  # might not exist, is list
            plugin_has_patch = plugin.has_patch
            plugin_exploit_available = plugin.exploit_available
            plugin_solution = plugin.solution  # might not exist

        # To simplify, we don't do this yet
        # Find corresponding vulnerability details
        # vuln = was_vulns.get_vulnerability(finding.scan.uuid, finding.plugin.id)
        # if vuln is not None and vuln.uri == finding.url:
        #     logger.debug(f"Found vulnerability {vuln.vuln_id} corresponding to finding {finding.finding_id}")

        dt_security_risk_level = finding.severity.upper() if finding.severity.upper() != "INFO" else "NONE"
        dt_security_risk_score = get_risk_score_from_level(dt_security_risk_level)

        url_details = parse_url(finding.url)

        if ingest_as_logs:
            event_header = {
                "security.event.kind": "SECURITY_EVENT",
                "security.content": finding.data,
                "security.event.id": str(uuid.uuid4()),
                "security.event.version": "1.304",
                "security.event.provider": "Tenable",
                "security.event.description": (
                    f"Vulnerability {plugin_name} was found in {url_details.get('url_full')}."
                ),
                "security.event.category": "VULNERABILITY_MANAGEMENT",
                "security.event.name": "Vulnerability finding event",
                "security.event.type": "VULNERABILITY_FINDING",
            }
        else:
            event_header = {
                "event.kind": "SECURITY_EVENT",
                "event.original_content": finding.data,
                "event.id": str(uuid.uuid4()),
                "event.version": "1.304",
                "event.provider": "Tenable",
                "event.description": (
                    f"Vulnerability {plugin_name} was found in {url_details.get('url_full')}."
                ),
                "event.category": "VULNERABILITY_MANAGEMENT",
                "event.name": "Vulnerability finding event",
                "event.type": "VULNERABILITY_FINDING",
            }
        # fmt: off
        base_event = {
           **event_header,

            "product.vendor": "Tenable",
            "product.name": "Tenable Web App Scanning",


            "dt.security.risk.level": dt_security_risk_level,
            "dt.security.risk.score": dt_security_risk_score,

            "finding.id": f"{finding.finding_id}",
            "finding.title": f"{plugin_name} detected in {finding.asset.fqdn}",
            "finding.description": finding.output,
            "finding.time.created": finding.last_found,
            "finding.severity": finding.severity,
            "finding.url": (
                f"{tenable_url}/tio/app.html#/findings/webapp-vulnerabilities/"
                f"details/{finding.finding_id}/asset/{finding.asset.uuid}/identification"
            ),

            "vulnerability.id": f"{plugin_id}",
            "vulnerability.title": plugin_name,
            "vulnerability.description": plugin_description,
            "vulnerability.references.cve": plugin_cves,
            "vulnerability.remediation.status": "AVAILABLE" if plugin_has_patch else "NOT_AVAILABLE",
            "vulnerability.remediation.description": plugin_solution,
            "vulnerability.exploit.status": "AVAIALBLE" if plugin_exploit_available else "NOT_AVAILABLE",

            "scan.id": scan_uuid,
            "scan.name": scan_name,
            "scan.status": scan_status,
            "scan.time.started": scan_start_time,
            "scan.time.completed": scan_end_time,

            "object.id": finding.asset.uuid,
            "object.type": "URL",
            "object.name": finding.asset.fqdn,

            "url.scheme": url_details.get("url_scheme"),
            "url.domain": url_details.get("url_domain"),
            "url.path": url_details.get("url_path"),
            "url.port": url_details.get("url_port"),
            "url.query": url_details.get("url_query"),
            "url.full": url_details.get("url_full"),

            "server.address": finding.asset.fqdn,
            "server.resolved_ips": finding.asset.ipv4s,
            "server.port": url_details.get("url_port"),

            "tenable.vpr": finding.plugin.vpr.score,
            "tenable.asset.id": finding.asset.uuid,
            "tenable.asset.name": finding.asset.fqdn,
            "tenable.target": scan_target,
            "tenable.proof": finding.proof if finding.proof != "" else None,
            "tenable.last_found": finding.last_found,
            "tenable.first_found": finding.first_found,
            "tenable.last_fixed": finding.last_fixed,
        }
        # fmt: on

        vulnerability_events: list[dict] = []

        for cpe in plugin_cpes:
            vulnerability_events.append({**base_event, "component.name": cpe})

        if vulnerability_events == []:
            vulnerability_events.append({**base_event, "component.name": scan_target})

    except Exception as e:
        logger.warning(
            f"Unable to generate events for web app vulnerability {finding.data}. Exception raised {e}"
        )
        vulnerability_events = []

    return vulnerability_events
