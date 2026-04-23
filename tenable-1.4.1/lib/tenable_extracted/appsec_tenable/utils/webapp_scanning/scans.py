import uuid
from datetime import datetime
from urllib.parse import urljoin

from dynatrace_extension.sdk.extension import extension_logger as logger

from ...models.webapp_scanning.scans import WAScan
from ...rest_interface import RestApiHandler
from ..shared import paged_endpoint, parse_url


def get_webapp_scan_history(
    tenable_api: RestApiHandler, scan_config_id: str, last_executed: datetime
) -> list[dict[str, WAScan]]:
    """
    Get scan details for all the scan executions of WAS `scan_config_id` which finished after `last_executed`
    """
    scan_details = [
        WAScan(details)
        for details in paged_endpoint(
            tenable_api.post_url,
            url=urljoin(tenable_api.url, f"/was/v2/configs/{scan_config_id}/scans/search"),
            headers=[],
            params={
                "limit": 100,
            },
        )
    ]

    scan_history: list[dict[str, WAScan]] = []
    for details in scan_details:
        if (
            details.finalized_at is None  # allow for uncompleted scans
            or datetime.fromisoformat(details.finalized_at.replace("Z", "+00:00")) >= last_executed
        ):
            scan_history.append({details.scan_id: details})
        elif datetime.fromisoformat(details.finalized_at.replace("Z", "+00:00")) < last_executed:
            break

    return scan_history


def generate_events_from_webapp_scan_details(scan: WAScan, ingest_as_logs: bool = False):
    try:
        scan_name = scan.scanner.group_name
        url_details = parse_url(scan.target)

        if ingest_as_logs:
            event_header = {
                "security.event.kind": "SECURITY_EVENT",
                "security.event.provider": "Tenable",
                "content": scan.original_data,
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
                "event.original_content": scan.original_data,
                "event.id": str(uuid.uuid4()),
                "event.version": "1.304",
                "event.type": "VULNERABILITY_SCAN",
                "event.category": "VULNERABILITY_MANAGEMENT",
                "event.name": "Vulnerability scan event",
                "event.description": f"Vulnerability scan completed on {scan_name}",
            }

        scan_event = {
            **event_header,
            "product.vendor": "Tenable",
            "product.name": "Tenable Web App Scanning",
            "object.id": scan.asset_id,
            "object.type": "URL",
            "object.name": url_details.get("url_domain"),
            "scan.id": scan.scan_id,
            "scan.name": scan_name,
            "scan.status": scan.status,
            "scan.time.started": scan.started_at,
            "scan.time.completed": scan.finalized_at,
            "url.scheme": url_details.get("url_scheme"),
            "url.domain": url_details.get("url_domain"),
            "url.path": url_details.get("url_path"),
            "url.port": url_details.get("url_port"),
            "url.query": url_details.get("url_query"),
            "url.full": url_details.get("url_full"),
        }

    except Exception as e:
        logger.warning(f"Unable to generate events for scan {scan}. Exception raised {e}")
        scan_event = None

    return scan_event
