import json
import sqlite3
import uuid
from datetime import datetime, timezone

from dynatrace_extension.sdk.extension import extension_logger as logger
from tenable.io import TenableIO

from appsec_tenable.models.pci_asv.plugin_details import Plugin
from appsec_tenable.models.vulnerability_management.scans import ScanDetails
from appsec_tenable.utils.pci_asv.vulns import generate_vulns_for_host, get_details_for_host


def generate_events_from_single_pci_asv_scan(
    tenable_access_key: str,
    tenable_secret_key: str,
    tenable_url: str,
    scan: ScanDetails,
    scan_id: int,
    plugins: dict[str, Plugin],
    conn: sqlite3.Connection,
    ingest_info_vulns: bool,
    vulns_batch_size: int = 100,
    ingest_as_logs: bool = False,
) -> list[dict]:
    scan_events = []
    logger.debug(
        f"Generating PCI scan events and vulns findings for scan {scan.info.schedule_uuid}, "
        f"history {scan.info.uuid}"
    )
    try:
        scan_end = (
            datetime.fromtimestamp(scan.info.scan_end, timezone.utc).isoformat().replace("+00:00", "Z")
            if scan.info.scan_end
            else None
        )
        scan_start = (
            datetime.fromtimestamp(scan.info.scan_start, timezone.utc).isoformat().replace("+00:00", "Z")
            if scan.info.scan_start
            else None
        )
        scan_name = scan.info.name

        host_vulns: list[dict] = []
        for host in scan.hosts:
            host_details = get_details_for_host(
                TenableIO(tenable_access_key, tenable_secret_key, url=tenable_url),
                scan.info.schedule_uuid,
                host.host_id,
                history_uuid=scan.info.uuid,
            )
            host_fqdn = host_details.info.host_fqdn  # is list
            host_ip = host_details.info.host_ip  # is list
            host_os = (
                host_details.info.operating_system if host_details.info.operating_system is not None else []
            )  # is list
            host_id = host.uuid
            host_name = host.hostname

            if ingest_as_logs:
                event_header = {
                    "security.event.kind": "SECURITY_EVENT",
                    "security.event.provider": "Tenable",
                    "content": scan.info.data,
                    "security.event.id": str(uuid.uuid4()),
                    "security.event.version": "1.304",
                    "security.event.type": "VULNERABILITY_SCAN",
                    "security.event.category": "VULNERABILITY_MANAGEMENT",
                    "security.event.name": "Vulnerability scan event",
                    "security.event.description": f"Vulnerability scan completed on {scan_name}",
                }
            else:
                event_header = {
                    "event.kind": "SECURITY_EVENT",
                    "event.provider": "Tenable",
                    "event.original_content": scan.info.data,
                    "event.id": str(uuid.uuid4()),
                    "event.version": "1.304",
                    "event.type": "VULNERABILITY_SCAN",
                    "event.category": "VULNERABILITY_MANAGEMENT",
                    "event.name": "Vulnerability scan event",
                    "event.description": f"Vulnerability scan completed on {scan_name}",
                }

            scan_events.append(
                {
                    **event_header,
                    "product.vendor": "Tenable",
                    "product.name": "Tenable PCI ASV (plugin)",
                    "object.id": host_id,
                    "object.type": "HOST",
                    "object.name": host_name,
                    "scan.id": scan.info.uuid,
                    "scan.name": scan_name,
                    "scan.status": scan.info.status,
                    "scan.time.started": scan_start,
                    "scan.time.completed": scan_end,
                    "host.name": host_name,
                    "host.ip": host_ip,
                    "host.fqdn": host_fqdn,
                    "os.name": host_os[0] if host_os != [] else None,
                    "tenable.url": f"https://cloud.tenable.com/tio/app.html#/assess/scans/vm-scans/folders/all-scans/scan-details/{scan_id}/{scan.info.uuid}/by-plugin",
                }
            )

            # Generate vulns:
            try:
                host_vulns.extend(
                    generate_vulns_for_host(
                        TenableIO(tenable_access_key, tenable_secret_key, url=tenable_url),
                        host_details,
                        plugins,
                        host_id,
                        host_name,
                        scan_id,
                        scan.info.uuid,
                        scan.info.name,
                        scan_start,
                        scan_end,
                        scan.info.status,
                        ingest_info_vulns,
                    )
                )
                host_vulns_to_store = ((json.dumps(vuln),) for vuln in host_vulns)
                if len(host_vulns) >= vulns_batch_size:
                    with conn:
                        conn.executemany("INSERT INTO pci_asv_vulns VALUES (?)", host_vulns_to_store)
                    logger.debug(f"Saved {len(host_vulns)} PCI vulnerabilities into database")
                    host_vulns = []

            except Exception as e:
                logger.warning(
                    f"Unable to generate PCI-ASV vulns for scan {scan.info.schedule_uuid}, "
                    f"history {scan.info.uuid} and host {host.uuid}. "
                    f"Exception raised {e}"
                )

        try:
            with conn:
                conn.executemany("INSERT INTO pci_asv_vulns VALUES (?)", host_vulns_to_store)
        except UnboundLocalError:
            pass
        except Exception as e:
            logger.warning(
                f"Unable to generate final batch of PCI-ASV vulns for scan {scan.info.schedule_uuid}, "
                f"history {scan.info.uuid}. "
                f"Exception raised {e}"
            )

        logger.debug(f"Saved {len(host_vulns)} PCI vulnerabilities into database")

    except Exception as e:
        logger.warning(f"Unable to generate events for scan {scan.info.uuid}. Exception raised {e}")

    return scan_events


def generate_and_ingest_pci_asv_scan_events(
    tenable_access_key: str,
    tenable_secret_key: str,
    tenable_url: str,
    plugins: dict[str, Plugin],
    conn: sqlite3.Connection,
    ingest_function: callable,
    batch_size: int,
    ingest_info_vulns: bool,
    failed_scan_chunks,
    ingest_as_logs: bool = False,
) -> int:
    number_of_events = 0
    with conn:
        cursor = conn.execute("SELECT scan_id, scan_history_object FROM pci_asv_scan_history")
        scan_details_raw = cursor.fetchone()
        scan_events: list[dict] = []
        while scan_details_raw is not None:
            scan_details = ScanDetails(json.loads(scan_details_raw[1]))
            scan_events.extend(
                generate_events_from_single_pci_asv_scan(
                    tenable_access_key,
                    tenable_secret_key,
                    tenable_url,
                    scan_details,
                    scan_details_raw[0],
                    plugins,
                    conn,
                    ingest_info_vulns,
                    ingest_as_logs=ingest_as_logs,
                )
            )
            if len(scan_events) > batch_size:
                ingest_function(scan_events, failed_scan_chunks)
                number_of_events += len(scan_events)
                scan_events = []
            scan_details_raw = cursor.fetchone()

        if len(scan_events) > 0:
            ingest_function(scan_events, failed_scan_chunks)
            number_of_events += len(scan_events)

    ingest_function(scan_events, failed_scan_chunks)
    return number_of_events
