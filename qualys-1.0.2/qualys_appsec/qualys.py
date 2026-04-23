import logging
from typing import Optional
import logging
from datetime import datetime
import urllib
import urllib.parse
import uuid
import json
import math

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

from .http_client import HttpClient, GatewayClient
from .utils import urlparse, convert_to_ip, qualys_timestamp_from_datetime
from .qualys_models import (
    Host,
    Vulnerability,
    Detection,
    ScanSummary,
    Scan,
    HostAsset,
    HostAssetVuln,
    AuditRecord,
)
from .pagination import PaginatedElementsList

log = logging.getLogger(__name__)

SD_VERSION = "1.309"
EVENT_SOURCE = "Qualys"


class Qualys:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        log=log,
        proxies: Optional[dict] = {},
        private_platform=False,
    ):
        self.log = log
        self.proxies = proxies

        url_parse_result = urllib.parse.urlparse(host)
        if not url_parse_result.scheme and url_parse_result.netloc:
            raise Exception(f"'{host}' is not a valid URL")
        if url_parse_result.scheme != "https":
            raise Exception(
                f"Non-HTTPS protocol being used. This is insecure and will result in clear-text credentials on the network. Switch to an HTTPS endpoint."
            )
        else:
            self.api_server_base = (
                f"{url_parse_result.scheme}://{url_parse_result.netloc}"
            )

            self.web_base = f"{url_parse_result.scheme}://{url_parse_result.netloc.replace('qualysapi', 'qualysguard')}"
            if private_platform:
                self.gateway_base = f"{url_parse_result.scheme}://{url_parse_result.netloc.replace('qualysapi', 'qualysgateway')}"
            else:
                self.gateway_base = f"{url_parse_result.scheme}://{url_parse_result.netloc.replace('qualysapi', 'gateway')}"

        self.api_server_client: HttpClient = HttpClient(
            base_url=self.api_server_base,
            username=username,
            password=password,
            proxies=proxies,
            log=self.log
        )

        self.gateway_client: GatewayClient = GatewayClient(
            base_url=self.gateway_base,
            username=username,
            password=password,
            proxies=proxies,
            log=self.log
        )

        parsed_url = urlparse(host)

        self.dimensions: dict[str, str] = {
            "qualys_host": f"{parsed_url.hostname}",
            "device.address": convert_to_ip(parsed_url.hostname),
        }

    def collect_audit_logs(
        self, from_time: datetime = None, to_time: datetime = None
    ) -> list[dict]:

        records: list[AuditRecord] = []
        log_events_to_return: list[dict] = []

        page_size = 200
        page_number = 0
        body_filters = {
            "startDate": from_time.timestamp() * 1000,
            "endDate": to_time.timestamp() * 1000,
            "pageSize": page_size,
            "pageNumber": page_number,
        }
        self.log.debug(
            f"Requesting audit logs with initial request body: {body_filters}"
        )
        resp = self.gateway_client.make_request(
            "/audit-log/admin/search",
            headers={"Content-Type": "application/json"},
            body=body_filters,
            method="POST",
        )
        result = resp.json()
        total_count = result["totalCount"]
        pages_remaining = int(math.ceil(total_count / page_size)) - 1
        self.log.debug(
            f"Page {page_number} audit log records: {len(result['auditRecords'])} (total: {total_count})"
        )

        for record in result["auditRecords"]:
            records.append(AuditRecord(record))

        while pages_remaining > 0:
            page_number += 1
            pages_remaining -= 1
            body_filters.update({"pageNumber": page_number})
            resp = self.gateway_client.make_request(
                "/audit-log/admin/search",
                headers={"Content-Type": "application/json"},
                body=body_filters,
                method="POST",
            )
            result = resp.json()
            self.log.debug(
                f"Page {page_number} audit log records: {len(result['auditRecords'])}"
            )

            for record in result["auditRecords"]:
                records.append(AuditRecord(record))

        for record in records:
            log_events_to_return.append(
                {
                    "level": "INFO",
                    "log.source": EVENT_SOURCE,
                    "content": json.dumps(record.original_content),
                    "audit.identity": record.user_name,
                    "audit.action": record.action,
                    "audit.time": record.created_date.isoformat(),
                    "audit.result": record.status,
                    "client.ip": record.source_ip,
                    "client.app.name": record.client,
                    "qualys.module.name": record.module_name,
                    "qualys.module.code": record.module_code,
                    "qualys.target.type": record.target_type,
                    "qualys.target.name": record.target_name,
                    "qualys.customer_uuid": record.customer_uuid,
                    "dt.extension.name": "com.dynatrace.extension.qualys",
                }
            )

        return log_events_to_return

    def retrieve_elements_paginated(
        self, url_path: str, url_params: dict, element_path: str
    ):
        all_elements: list[ET.Element] = []
        next_url = url_path
        params = url_params
        while next_url:
            response = self.api_server_client.make_request(next_url, params)
            response.raise_for_status()
            tree = ET.ElementTree(ET.fromstring(response.text))
            root = tree.getroot()
            all_elements.extend(root.findall(element_path))
            warning_element = root.find("WARNING")
            if warning_element is not None:
                next_url = (
                    warning_element.find("URL").text
                    if warning_element.find("URL") is not None
                    else None
                )
            else:
                next_url = None

        return all_elements

    def get_host_assets_for_scans(
        self,
        vulns_updated_since: datetime,
        vulns_updated_to: datetime,
        result_limit: int = 100,
        start_from_offset: int = 1,
    ) -> tuple[list[HostAsset], bool]:

        elements: list[ET.Element] = []

        headers = {"Content-Type": "application/json"}
        # this should NOT be url encoded
        fields_query_parms = "?fields=name,qwebHostId,address,fqdn,os,dnsHostName,tags,lastVulnScan,vulnsUpdated,trackingMethod,vuln.*.*.*,software.*.*.*"
        service_request: dict = {
            "ServiceRequest": {
                "preferences": {
                    "limitResults": result_limit,
                    "startFromOffset": start_from_offset,
                },
                "filters": {
                    "Criteria": [
                        {
                            "field": "vulnsUpdated",
                            "operator": "GREATER",
                            "value": qualys_timestamp_from_datetime(
                                vulns_updated_since
                            ),
                        },
                        {
                            "field": "vulnsUpdated",
                            "operator": "LESSER",
                            "value": qualys_timestamp_from_datetime(vulns_updated_to),
                        },
                    ]
                },
            }
        }
        self.log.debug(
            f"Host asset service request payload: {json.dumps(service_request)}"
        )
        resp = self.api_server_client.make_request(
            f"/qps/rest/2.0/search/am/hostasset{fields_query_parms}",
            headers=headers,
            data=json.dumps(service_request),
            method="POST",
        )
        tree = ET.ElementTree(ET.fromstring(resp.text))
        root = tree.getroot()
        has_more_element = root.find("hasMoreRecords")
        if has_more_element:
            has_more = True if has_more_element.text == "true" else False
        else:
            has_more = False
        elements = [HostAsset(ha) for ha in root.findall("data/HostAsset")]

        return elements, has_more

    def generate_security_events_from_scans(self, scans: list[ScanSummary]):
        # TODO (if needed)
        pass

    def find_matching_scan(
        self, scans: list[ScanSummary], host: Host
    ) -> ScanSummary | None:
        matched_scan = None
        for scan in scans:
            if scan.includes_host(host):
                matched_scan = scan
                break
        return matched_scan

    def generate_security_events_from_detections(
        self,
        hosts: list[Host],
        host_asset_map: dict[str, HostAsset],
        kb_map: dict[str, Vulnerability],
        scans: list[ScanSummary],
    ):
        """
        Create the list of security events to return for ingestion. Works on the one
        'batch' at a time. As a basis we'll identify scans based on the update
        times on the host assets. This will be the solution for CA scans regardless.
        For VMDR scans we can try and map these to the reported scans if a
        good solution is found - otherwise the generated scans will do.
        """
        events: list[dict] = []

        common_fields = {
            "event.kind": "SECURITY_EVENT",
            "event.version": SD_VERSION,
            "event.provider": EVENT_SOURCE,
            "event.category": "VULNERABILITY_MANAGEMENT",
            "product.name": "Vulnerability Management, Detection & Response",
            "product.vendor": "Qualys",
        }

        for host in hosts:
            host_asset = host_asset_map[host.id]
            """
            We really only need this vuln map because we need the "hostInstanceVulnId" to
            construct the finding url which is only available in the host asset output.
            """
            host_instance_vuln_map: dict[str, HostAssetVuln] = {
                f"{ha.qid}/{ha.last_found.isoformat()}": ha
                for ha in host_asset.vuln_list
            }

            """
            Might need to do some different processing/reporting 
            of scans depending on the scan type which can be
            inferred from the tracking method.
            """
            if host_asset.tracking_method == "QAGENT":
                pass
            else:
                pass

            host_fields = {
                "object.type": "HOST",
                "object.id": host.id,
                "object.name": host.hostname if host.hostname else host.ip,
                "host.name": host.hostname,
                "host.ip": host.ip,
                "host.fqdn": host.fqdn,
                "os.name": host.os,
                "product.vendor": "Qualys",
                "product.name": "Vulnerability Management, Detection & Response",
            }

            scan_event = {
                **common_fields,
                **host_fields,
                "event.type": "VULNERABILITY_SCAN",
                "event.name": "Vulnerability scan",
                "event.original_content": host_asset.original_content_xml(),
                "event.description": f"Vulnerability scan completed of {host_asset.address}.",
                "scan.id": f"{host_asset.tracking_method}/{host_asset.qweb_host_id}/{host_asset.last_vuln_scan.isoformat()}",
                "scan.name": f"{host_asset.tracking_method} Vulnerability Scan of {host_asset.address}",
                "scan.time.completed": host_asset.last_vuln_scan.isoformat(),
            }

            events.append(scan_event)

            scan_fields = {
                "scan.id": scan_event["scan.id"],
                "scan.name": scan_event["scan.name"],
            }

            host_finding_fields = {
                "event.type": "VULNERABILITY_FINDING",
                "event.name": "Vulnerability finding event",
                "qualys.host.asset_id": host.asset_id,
                "qualys.host.tracking_method": (
                    "Cloud Agent"
                    if host_asset.tracking_method == "QAGENT"
                    else "Vulnerability Management, Detection & Response"
                ),
            }

            for detection in host.detection_list:
                kb = kb_map[detection.qid]
                host_asset_vuln: HostAssetVuln = host_instance_vuln_map.get(
                    f"{detection.qid}/{detection.last_found_datetime.isoformat()}"
                )

                components = self.determine_components(
                    kb, host_asset, host_asset_vuln, detection, host
                )

                for component in components:
                    finding_event = {
                        **common_fields,
                        **host_fields,
                        **host_finding_fields,
                        **scan_fields,
                        "component.name": component,
                        "event.id": str(uuid.uuid4()),
                        "event.description": f"Vulnerability {kb.title} was found on {host.hostname if host.hostname else host.ip}",
                        "finding.title": f"{kb.title} found on {host.hostname if host.hostname else host.ip}",
                        "finding.id": detection.unique_vuln_id,
                        "finding.type": f"{kb.category} vulnerability",
                        "finding.description": detection.results,
                        "finding.time.created": detection.last_found_datetime.isoformat(),
                        "finding.severity": detection.severity,
                        "finding.score": detection.qds,
                        "finding.severity": detection.qds_severity,
                        "finding.url": f"{self.web_base}/vm/#/vulndetails/{host_asset_vuln.host_instance_vuln_id}",
                        "vulnerability.id": detection.qid,
                        "vulnerability.title": kb.title,
                        "vulnerability.description": kb.diagnosis,
                        "vulnerability.references.cve": [cve.id for cve in kb.cve_list],
                        "vulnerability.remediation.status": (
                            "AVAILABLE" if kb.patchable else "NOT_AVAILABLE"
                        ),
                        "vulnerability.remediation.description": kb.solution,
                        "vulnerability.exploit.status": (
                            "AVAILABLE" if len(kb.exploit_list) > 0 else "NOT_AVAILABLE"
                        ),
                        "qualys.detection.first_found": detection.first_found_datetime.isoformat(),
                        "qualys.detection.last_found": detection.last_found_datetime.isoformat(),
                        "qualys.detection.times_found": detection.times_found,
                        "qualys.detection.qds_factors": {
                            factor.name: factor.factor
                            for factor in detection.qds_factors
                        },
                        "dt.security.risk.level": detection.qds_severity,
                        "dt.security.risk.score": detection.qds / 10,
                        "event.original_content": detection.original_content_xml(),
                    }

                    events.append(finding_event)

        return events

    def determine_components(
        self,
        vuln: Vulnerability,
        host_asset: HostAsset,
        host_asset_vuln: HostAssetVuln,
        detection: Detection,
        host: Host,
    ) -> list[str]:
        """
        Evaluates all the details of the finding to determine which 'software' to report for component.
        Can be multiple.
        """
        if vuln.software_list:  # KB vuln has affected software
            vulnerability_software = set(
                [s.product for s in vuln.software_list if s.product.lower() != "none"]
            )
            host_detected_software = set([s.name for s in host_asset.software_list])
            running_affected_components = list(
                vulnerability_software.intersection(host_detected_software)
            )

            if running_affected_components:  # running software identified - use this
                return running_affected_components

            else:  # return all the affected software because we do not know for certain
                return list(vulnerability_software)

        else:  # we have to find an alternative to reported software
            if host.os:  # use the OS if available
                return [host.os]
            else:  # we really have nothing
                return [f"Unknown component at {host_asset.address}"]

    def get_host_detections(self) -> list[Host]:
        discovered_qids: list[str] = []
        hosts = self.retrieve_elements_paginated(
            "/api/2.0/fo/asset/host/vm/detection",
            {"action": "list"},
            "RESPONSE/HOST_LIST/HOST",
        )
        for host in hosts:
            try:
                host = Host(host)
                for detection in host.detection_list:
                    discovered_qids.append(detection.qid)
            except Exception as e:
                self.log.exception(f"Error parsing host detection record: {e}")

        self.lookup_knowledge_base(discovered_qids)

    def lookup_knowledge_base(self, qids: list[str] = []) -> dict[str, Vulnerability]:
        vulns = self.retrieve_elements_paginated(
            "/api/2.0/fo/knowledge_base/vuln",
            {"action": "list", "ids": ",".join(qids)},
            "RESPONSE/VULN_LIST/VULN",
        )
        vuln_map = {}
        for vuln in vulns:
            try:
                vuln = Vulnerability(vuln)
                vuln_map.update({vuln.qid: vuln})
            except Exception as e:
                self.log.exception(f"Error parsing vulnerability from KB: {e}")
        return vuln_map
