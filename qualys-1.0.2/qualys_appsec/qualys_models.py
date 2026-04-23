from .qualys_object import QualysObject
from datetime import datetime, timezone
import itertools
import ipaddress
from .utils import convert_to_bytes

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


def safe_text(element: ET.Element | None) -> str | None:
    if element is not None:
        return element.text
    else:
        return None


def safe_date(element: ET.Element | None) -> datetime | None:
    timestamp = safe_text(element)
    if timestamp:
        return datetime.strptime(timestamp, r"%Y-%m-%dT%H:%M:%SZ")
    else:
        return None


class Software(QualysObject):
    def __init__(self, e: ET.Element):
        self.product: str = safe_text(e.find("PRODUCT"))
        self.vendor: str = safe_text(e.find("VENDOR"))
        self.original_element: ET.Element = e


class ThreatIntelligence(QualysObject):
    def __init__(self, e: ET.Element):
        self.threat_intel: str = safe_text(e.find("THREAT_INTEL"))
        self.original_element: ET.Element = e


class Exploit(QualysObject):
    def __init__(self, e: ET.Element):
        self.ref: str = safe_text(e.find("REF"))
        self.desc: str = safe_text(e.find("DESC"))
        self.link: str = safe_text(e.find("LINK"))
        self.original_element: ET.Element = e


class ExploitSource(QualysObject):
    def __init__(self, e: ET.Element):
        self.src_name: str = safe_text(e.find("SRC_NAME"))
        self.explt_list: list[Exploit] = [
            Exploit(explt) for explt in e.findall("EXPLT_LIST")
        ]
        self.original_element: ET.Element = e


class CVE(QualysObject):
    def __init__(self, e: ET.Element):
        self.id: str = safe_text(e.find("ID"))
        self.url: str = safe_text(e.find("URL"))
        self.original_element: ET.Element = e


class Vulnerability(QualysObject):
    def __init__(self, e: ET.Element):
        self.qid: str = safe_text(e.find("QID"))
        self.vuln_type: str = safe_text(e.find("VULN_TYPE"))
        self.severity_level: str = safe_text(e.find("SEVERITY_LEVEL"))
        self.title: str = safe_text(e.find("TITLE"))
        self.category: str = safe_text(e.find("CATEGORY"))
        self.patchable: bool = bool(int(safe_text(e.find("PATCHABLE"))))
        self.software_list: list[Software] = [
            Software(s) for s in e.findall("SOFTWARE_LIST/SOFTWARE")
        ]
        self.diagnosis: str = safe_text(e.find("DIAGNOSIS"))
        self.consequence: str = safe_text(e.find("CONSEQUENCE"))
        self.solution: str = safe_text(e.find("SOLUTION"))
        self.threat_intelligence: list[ThreatIntelligence] = [
            ThreatIntelligence(ti)
            for ti in e.findall("THREAT_INTELLIGENCE/THREAT_INTEL")
        ]
        self.cve_list: list[CVE] = [CVE(cve) for cve in e.findall("CVE_LIST/CVE")]
        self.exploit_list: list[ExploitSource] = [
            ExploitSource(explt_source)
            for explt_source in e.findall("CORRELATION/EXPLOITS/EXPLT_SRC")
        ]
        self.original_element: ET.Element = e


class QdsFactor(QualysObject):
    def __init__(self, e: ET.Element):
        self.name: str = e.attrib.get("name")
        self.factor: str = safe_text(e)
        self.original_element: ET.Element = e


class Detection(QualysObject):
    def __init__(self, e: ET.Element):
        self.unique_vuln_id: str = safe_text(e.find("UNIQUE_VULN_ID"))
        self.qid: str = safe_text(e.find("QID"))
        self.type: str = safe_text(e.find("TYPE"))
        self.severity: str = safe_text(e.find("SEVERITY"))
        self.port: str = safe_text(e.find("PORT"))
        self.protocol: str = safe_text(e.find("PROTOCOL"))
        self.ssl: bool = bool(safe_text(e.find("SSL")))
        self.status: str = safe_text(e.find("STATUS"))
        self.first_found_datetime: datetime = safe_date(e.find("FIRST_FOUND_DATETIME"))
        self.last_found_datetime: datetime = safe_date(e.find("LAST_FOUND_DATETIME"))
        self.times_found: int = safe_text(e.find("TIMES_FOUND"))
        self.results: str = safe_text(e.find("RESULTS"))
        self.qds: int = int(safe_text(e.find("QDS")))
        self.qds_severity: str = e.find("QDS").attrib.get("severity")
        self.qds_factors: list[QdsFactor] = [
            QdsFactor(qds) for qds in e.findall("QDS_FACTORS/QDS_FACTOR")
        ]
        self.original_element: ET.Element = e


class Host(QualysObject):
    def __init__(self, e: ET.Element):
        self.id: str | None = safe_text(e.find("ID"))
        self.asset_id: str | None = safe_text(e.find("ASSET_ID"))
        self.qg_hostid: str | None = safe_text(
            e.find("QG_HOSTID")
        )  # only agent or authenticated scans
        self.ip: str | None = safe_text(e.find("IP"))
        self.ip_v6: str | None = safe_text(e.find("IPV6"))
        self.network_id: str | None = safe_text(e.find("NETWORK_ID"))
        self.network_name: str | None = safe_text(e.find("NETWORK_NAME"))
        self.netbios: str | None = safe_text(e.find("NETBIOS"))
        self.os: str | None = safe_text(e.find("OS"))
        self.tracking_method: str = safe_text(e.find("TRACKING_METHOD"))
        self.original_element: ET.Element = e

        # DNS
        dns = e.find("DNS_DATA")
        self.hostname: str | None = safe_text(dns.find("HOSTNAME"))
        self.fqdn: str | None = safe_text(dns.find("FQDN"))
        self.original_element: ET.Element = e

        # Cloud
        self.cloud_provider: str | None = safe_text(e.find("CLOUD_PROVIDER"))
        self.cloud_service: str | None = safe_text(e.find("CLOUD_SERVICE"))
        self.cloud_resource_id: str | None = safe_text(e.find("CLOUD_RESOURCE_ID"))
        self.ec2_instance_id: str | None = safe_text(e.find("EC2_INSTANCE_ID"))

        # Scans
        # Ref: https://success.qualys.com/support/s/article/000006546
        self.last_scan_datetime: datetime = safe_date(e.find("LAST_SCAN_DATETIME"))

        # Detections (vulnerabilities)
        self.detection_list: list[Detection] = [
            Detection(d) for d in e.findall("DETECTION_LIST/DETECTION")
        ]
        self.original_element: ET.Element = e


class AssetGroup(QualysObject):
    def __init__(self, e: ET.Element):
        self.id: str = safe_text(e.find("ID"))
        self.name: str = safe_text(e.find("NAME"))
        self.original_element: ET.Element = e


class ScanTarget(QualysObject):
    def __init__(self, e: ET.Element):
        self.ip_list: list[str] = [safe_text(ip) for ip in e.findall("IP_DATA")]
        self.asset_group_list: list[AssetGroup] = [
            AssetGroup(ag) for ag in e.findall("ASSET_GROUP_LIST")
        ]
        self.original_element: ET.Element = e


class ScanDetails(QualysObject):
    def __init__(self, e: ET.Element):
        self.status: str = safe_text(e.find("STATUS"))
        self.launch_datetime: datetime = safe_date(e.find("LAUNCH_DATETIME"))
        self.duration: int = int(safe_text(e.find("DURATION")))
        self.original_element: ET.Element = e


class ScanInput(QualysObject):
    def __init__(self, e: ET.Element):
        self.title: str = safe_text(e.find("TITLE"))
        self.scheduled: bool = 1 if bool(safe_text(e.find("SCHEDULED"))) else 0
        self.scan_datetime: datetime = safe_date(e.find("SCAN_DATETIME"))
        self.user: str = safe_text(e.find("USER/USERNAME"))
        self.targets: list[ScanTarget] = [ScanTarget(st) for st in e.findall("TARGETS")]
        self.original_element: ET.Element = e


class HostsData(QualysObject):
    def __init__(self, e: ET.Element):
        self.ip_list_csv: list[str] = list(
            itertools.chain.from_iterable(
                [safe_text(ip).split(",") for ip in e.findall("IP_LIST/IP_DATA/IP_CSV")]
            )
        )  # e.g. 10.0.0.1,10.0.0.2
        self.ip_list_range: list[str] = [
            safe_text(range) for range in e.findall("IP_LIST/IP_DATA/RANGES/RANGE")
        ]  # e.g. 10.10.30.10-10.10.30.12
        self.dns_list_csv: list[str] = list(
            itertools.chain.from_iterable(
                [
                    safe_text(dns).split(",")
                    for dns in e.findall("DNS_LIST/DNS_DATA/DNS_CSV")
                ]
            )
        )
        self.netbios_list_csv: list[str] = list(
            itertools.chain.from_iterable(
                [
                    safe_text(netbios).split(",")
                    for netbios in e.findall("NETBIOS_LIST/NETBIOS_DATA/NETBIOS_CSV")
                ]
            )
        )
        self.instance_id_csv: list[str] = list(
            itertools.chain.from_iterable(
                [
                    safe_text(inst).split(",")
                    for inst in e.findall(
                        "INSTANCE_ID_LIST/INSTANCE_ID_DATA/INSTANCE_ID_CSV"
                    )
                ]
            )
        )
        self.original_element: ET.Element = e


class ScanResults(QualysObject):
    def __init__(self, e: ET.Element):
        self.hosts_count: int = int(safe_text(e.find("HOSTS/COUNT")))
        self.scanned: HostsData = (
            HostsData(e.find("HOSTS/HOSTS_DATA/SCANNED"))
            if e.find("HOSTS/HOSTS_DATA/SCANNED")
            else None
        )
        self.excluded: HostsData = (
            HostsData(e.find("HOSTS/HOSTS_DATA/EXCLUDED"))
            if e.find("HOSTS/HOSTS_DATA/EXCLUDED")
            else None
        )
        self.cancelled: HostsData = (
            HostsData(e.find("HOSTS/HOSTS_DATA/CANCELLED"))
            if e.find("HOSTS/HOSTS_DATA/CANCELLED")
            else None
        )
        self.unresolved: HostsData = (
            HostsData(e.find("HOSTS/HOSTS_DATA/UNRESOLVED"))
            if e.find("HOSTS/HOSTS_DATA/UNRESOLVED")
            else None
        )
        self.duplicate: HostsData = (
            HostsData(e.find("HOSTS/HOSTS_DATA/DUPLICATE"))
            if e.find("HOSTS/HOSTS_DATA/DUPLICATE")
            else None
        )
        self.not_vulnerable: HostsData = (
            HostsData(e.find("HOSTS/HOSTS_DATA/NOT_VULNERABLE"))
            if e.find("HOSTS/HOSTS_DATA/NOT_VULNERABLE")
            else None
        )
        self.dead: HostsData = (
            HostsData(e.find("HOSTS/HOSTS_DATA/DEAD"))
            if e.find("HOSTS/HOSTS_DATA/DEAD")
            else None
        )
        self.aborted: HostsData = (
            HostsData(e.find("HOSTS/HOSTS_DATA/ABORTED"))
            if e.find("HOSTS/HOSTS_DATA/ABORTED")
            else None
        )
        self.blocked: HostsData = (
            HostsData(e.find("HOSTS/HOSTS_DATA/BLOCKED"))
            if e.find("HOSTS/HOSTS_DATA/BLOCKED")
            else None
        )
        self.failed_slice: HostsData = (
            HostsData(e.find("HOSTS/HOSTS_DATA/FAILED_SLICE"))
            if e.find("HOSTS/HOSTS_DATA/FAILED_SLICE")
            else None
        )
        self.exceed_scan_duration: HostsData = (
            HostsData(e.find("HOSTS/HOSTS_DATA/EXCEEDED_SCAN_DURATION"))
            if e.find("HOSTS/HOSTS_DATA/EXCEEDED_SCAN_DURATION")
            else None
        )
        self.original_element: ET.Element = e


class ScanSummary(QualysObject):
    def __init__(self, e: ET.Element):
        self.scan_reference: str = safe_text(e.find("SCAN_REFERENCE"))
        self.scan_input: ScanInput = ScanInput(e.find("SCAN_INPUT"))
        self.scan_details: ScanDetails = ScanDetails(e.find("SCAN_DETAILS"))
        self.scan_results: ScanResults = ScanResults(e.find("SCAN_RESULTS"))
        self.original_element: ET.Element = e

    def includes_host(self, host: Host) -> bool:
        """
        This is used to parse all the fields in the 'scanned' section of the results
        to see if we can match to one of the identifiers reported for the host.

        Start with the more likely and least heavy checks.
        """
        match = False
        if self.scan_results.scanned:
            if host.ip in self.scan_results.scanned.ip_list_csv:
                match = True
            elif host.fqdn in self.scan_results.scanned.dns_list_csv:
                match = True
            elif host.netbios in self.scan_results.scanned.netbios_list_csv:
                match = True
            elif host.ec2_instance_id in self.scan_results.scanned.instance_id_csv:
                match = True
            else:
                for ip_range in self.scan_results.scanned.ip_list_range:
                    start_ip, end_ip = ip_range.split("-")
                    if (
                        ipaddress.ip_address(start_ip)
                        < ipaddress.ip_address(host.ip)
                        < ipaddress.ip_address(end_ip)
                    ):
                        match = True
                        break
        return match


class Scan(QualysObject):
    def __init__(self, e: ET.Element):
        self.ref: str = safe_text(e.find("REF"))
        self.launch_datetime: datetime = safe_date(e.find("LAUNCH_DATETIME"))
        self.original_element: ET.Element = e


class HostAssetTag(QualysObject):
    def __init__(self, e: ET.ElementTree):
        self.id: str = safe_text(e.find("id"))
        self.name: str = safe_text(e.find("name"))
        self.tag_uuid: str = safe_text(e.find("tagUuid"))
        self.original_element: ET.Element = e


class HostAssetVuln(QualysObject):
    def __init__(self, e: ET.Element):
        self.qid: str = safe_text(e.find("qid"))
        self.host_instance_vuln_id: str = safe_text(e.find("hostInstanceVulnId"))
        self.first_found: datetime = safe_date(e.find("firstFound"))
        self.last_found: datetime = safe_date(e.find("lastFound"))


class HostAssetSoftware(QualysObject):
    def __init__(self, e: ET.Element):
        self.name: str = safe_text(e.find("name"))
        self.version: str = safe_text(e.find("version"))


class HostAsset(QualysObject):
    def __init__(self, e: ET.Element):
        self.name: str = safe_text(e.find("name"))
        self.tracking_method: str = safe_text(e.find("trackingMethod"))
        self.qweb_host_id: str = safe_text(e.find("qwebHostId"))
        self.address: str = safe_text(e.find("address"))
        self.fqdn: str = safe_text(e.find("fqdn"))
        self.os: str = safe_text(e.find("os"))
        self.dns_host_name: str = safe_text(e.find("dnsHostName"))
        self.tags: list[HostAssetTag] = [
            HostAssetTag(t) for t in e.findall("tags/list/TagSimple")
        ]
        self.last_vuln_scan: datetime = safe_date(e.find("lastVulnScan"))
        self.vulns_updated: datetime = safe_date(e.find("vulnsUpdated"))
        self.vuln_list: list[HostAssetVuln] = [
            HostAssetVuln(v) for v in e.findall("vuln/list/HostAssetVuln")
        ]
        self.software_list: list[HostAssetSoftware] = [
            HostAssetSoftware(v) for v in e.findall("software/list/HostAssetSoftware")
        ]
        self.original_element: ET.Element = e


class AuditRecord:
    def __init__(self, record: dict):
        self.id: str = record.get("id")
        self.module_name: str = record.get("moduleName")
        self.module_code: str = record.get("moduleCode")
        self.user_name: str = record.get("userName")
        self.user_role: str = record.get("userRole")
        self.user_uuid: str = record.get("userUuid")
        self.customer_uuid: str = record.get("customerUuid")
        self.client: str = record.get("client")
        self.source_ip: str = record.get("sourceIp")
        self.created_date: datetime = datetime.fromtimestamp(
            record.get("createdDate") / 1000
        )
        self.target_type: str = record.get("targetType")
        self.target_name: str = record.get("targetName")
        self.action: str = record.get("action")
        self.status: str = record.get("status")
        self.audit_comment: str = record.get("auditComment")
        self.external_change_link: str = record.get("externalChangeLink")
        self.original_content: dict = record
