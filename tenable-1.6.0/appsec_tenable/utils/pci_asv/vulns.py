import uuid

from dynatrace_extension.sdk.extension import extension_logger as logger
from tenable.errors import NotFoundError
from tenable.io import TenableIO

from ...models.pci_asv.host_details import HostData
from ...models.pci_asv.plugin_details import Plugin
from ...utils.shared import get_risk_score_from_level


def get_details_for_host(tenable_api: TenableIO, scan_id, host_id: int, history_uuid: str = None) -> HostData:
    return HostData(tenable_api.scans.host_details(scan_id, host_id, history_uuid=history_uuid))


def get_details_for_plugin(tenable_api: TenableIO, plugin_id: int) -> Plugin:
    return Plugin(tenable_api.plugins.plugin_details(plugin_id))


def risk_level_mapping(severity: int) -> str:
    risk_level = "NONE"
    if severity == 0:
        risk_level = "NONE"
    elif severity == 1:
        risk_level = "LOW"
    elif severity == 2:
        risk_level = "MEDIUM"
    elif severity == 3:
        risk_level = "HIGH"
    elif severity == 4:
        risk_level = "CRITICAL"
    return risk_level


def generate_vulns_for_host(
    tenable_api: TenableIO,
    host_details: HostData,
    plugins: dict[int, Plugin],
    host_uuid: str,
    host_name: str,
    scan_id: int,
    scan_uuid: str,
    scan_name: str,
    scan_start_time: str,
    scan_end_time: str,
    scan_status: str,
    ingest_info_vulns: bool,
    ingest_as_logs: bool = False,
) -> list[dict]:
    vulns = []
    for vuln in host_details.vulnerabilities + host_details.compliance:
        try:
            if not ingest_info_vulns and vuln.severity == 0:
                pass
            else:
                dt_security_risk_level = risk_level_mapping(vuln.severity)
                dt_security_risk_score = get_risk_score_from_level(dt_security_risk_level)
                host_os_list = (
                    host_details.info.operating_system
                    if host_details.info.operating_system is not None
                    else []
                )  # is list
                host_os = host_os_list[0] if host_os_list != [] else None

                # Get plugin details
                plugin_id = vuln.plugin_id
                plugin_name = vuln.plugin_name
                plugin_details = plugins.get(plugin_id)
                if plugin_details is None:
                    try:
                        plugin_details = get_details_for_plugin(tenable_api, plugin_id)
                        plugins[plugin_id] = plugin_details
                    except NotFoundError:
                        logger.warning(f"Unable to find details for plugin {plugin_id}. Ignoring.")
                        plugins[plugin_id] = False

                if plugin_details:
                    plugin_description = None
                    plugin_solution = None
                    solution_found = False
                    description_found = False
                    for attribute in plugin_details.attributes:
                        if solution_found and description_found:
                            break
                        if attribute.attribute_name == "solution":
                            plugin_solution = plugin_solution
                            solution_found = True
                        elif attribute.attribute_name == "description":
                            plugin_description = plugin_description
                            description_found = True

                    # fmt: off
                    if ingest_as_logs:
                        event_header = {
                            "security.event.kind": "SECURITY_EVENT",
                            "content": vuln.original_data,
                            "security.event.id": str(uuid.uuid4()),
                            "security.event.version": "1.304",
                            "security.event.provider": "Tenable",
                            "security.event.type": "VULNERABILITY_FINDING",
                            "security.event.category": "VULNERABILITY_MANAGEMENT",
                            "security.event.name": "Vulnerability finding event",
                            "security.event.description": (
                                    f"Vulnerability {plugin_name} was found in"
                                    f"{host_name} in {host_os}."
                                ) if host_os is not None else (
                                    f"Vulnerability {plugin_name} was found in"
                                    f"{host_name}."
                                ),
                        }
                    else:
                        event_header = {
                            "event.kind": "SECURITY_EVENT",
                            "event.original_content": vuln.original_data,
                            "event.id": str(uuid.uuid4()),
                            "event.version": "1.304",
                            "event.provider": "Tenable",
                            "event.type": "VULNERABILITY_FINDING",
                            "event.category": "VULNERABILITY_MANAGEMENT",
                            "event.name": "Vulnerability finding event",
                            "event.description": (
                                    f"Vulnerability {plugin_name} was found in"
                                    f"{host_name} in {host_os}."
                                ) if host_os is not None else (
                                    f"Vulnerability {plugin_name} was found in"
                                    f"{host_name}."
                                ),
                        }

                    base_event = {
                       **event_header,

                        "product.vendor": "Tenable",
                        "product.name": "Tenable PCI ASV (plugin)",

                        "dt.security.risk.level": dt_security_risk_level,
                        "dt.security.risk.score": dt_security_risk_score,

                        "finding.id": f"{host_uuid}/{plugin_id}/{scan_uuid}",
                        "finding.title": f"{plugin_name} detected in {host_name}",
                        "finding.description": plugin_name,
                        "finding.time.created": host_details.info.host_end,
                        "finding.severity": dt_security_risk_level,
                        "finding.url": f"https://cloud.tenable.com/tio/app.html#/assess/scans/vm-scans/folders/all-scans/scan-details/{scan_id}/{scan_uuid}/by-asset/asset-details/{host_uuid}/vulns",

                        "vulnerability.id": f"{plugin_id}",
                        "vulnerability.title": plugin_name,
                        "vulnerability.description": plugin_description,
                        "vulnerability.remediation.description": plugin_solution,
                        "vulnerability.remediation.status": "AVAILABLE" if plugin_solution
                        else "NOT_AVAILABLE",

                        "scan.id": scan_uuid,
                        "scan.name": scan_name,
                        "scan.status": scan_status,
                        "scan.time.started": scan_start_time,
                        "scan.time.completed": scan_end_time,

                        "object.id": host_uuid,
                        "object.type": "HOST",
                        "object.name": host_name,

                        "host.name": host_name,
                        "host.ip": host_details.info.host_ip,
                        "host.fqdn": host_details.info.host_fqdn,

                        "os.name": host_os,

                        "component.name": host_os
                    }
                    # fmt: on

                    vulns.append(base_event)

        except NotFoundError as e:
            logger.warning(
                f"Unable to generate PCI-ASV vulns for scan {scan_name}, "
                f"history {scan_uuid}, host {host_uuid} and plugin {plugin_id}. "
                f"Exception raised {e} "
                f"Ignoring this plugin in the future"
            )
            plugins[plugin_id] = plugin_details

        except Exception as e:
            logger.warning(
                f"Unable to generate PCI-ASV vulns for scan {scan_name}, "
                f"history {scan_uuid}, host {host_uuid} and plugin {plugin_id}. "
                f"Exception raised {e}"
            )

    return vulns
