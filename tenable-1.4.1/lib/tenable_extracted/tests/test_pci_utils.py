import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from appsec_tenable.models.pci_asv.host_details import HostData
from appsec_tenable.models.pci_asv.plugin_details import Plugin
from appsec_tenable.models.vulnerability_management.scans import ScanDetails
from appsec_tenable.utils.pci_asv.vulns import generate_vulns_for_host

SAMPLE_DATA_PATH = Path(__file__).parent / "sample_data" / "test_pci_utils"


# class TestGenerateEvent:
@pytest.fixture
def plugin_details():
    with open(SAMPLE_DATA_PATH / "sample_plugin_details.json") as f:
        return Plugin(json.load(f))


@pytest.fixture
def scan_details():
    with open(SAMPLE_DATA_PATH / "sample_scan_details.json") as f:
        return ScanDetails(json.load(f))


@pytest.fixture
def host_details():
    with open(SAMPLE_DATA_PATH / "sample_host_details.json") as f:
        return HostData(json.load(f))


@pytest.fixture
def finding_event():
    with open(SAMPLE_DATA_PATH / "sample_finding_event.json") as f:
        return json.load(f)


# @pytest.fixture
# def scan_event():
#     with open(SAMPLE_DATA_PATH / "sample_scan_event.json") as f:
#         return json.load(f)


def test_pci_finding(plugin_details, scan_details, host_details, finding_event):
    # Data from scan
    scan_end = (
        datetime.fromtimestamp(scan_details.info.scan_end, timezone.utc).isoformat().replace("+00:00", "Z")
        if scan_details.info.scan_end
        else None
    )
    scan_start = (
        datetime.fromtimestamp(scan_details.info.scan_start, timezone.utc).isoformat().replace("+00:00", "Z")
        if scan_details.info.scan_start
        else None
    )
    host_id = scan_details.hosts[0].uuid
    host_name = scan_details.hosts[0].hostname

    event_list: list[dict] = generate_vulns_for_host(
        None,
        host_details,
        {10107: plugin_details},
        host_id,
        host_name,
        1,
        scan_details.info.uuid,
        scan_details.info.name,
        scan_start,
        scan_end,
        scan_details.info.status,
        True,
    )

    assert len(event_list) == 1

    event = event_list[0]
    del event["event.id"]
    del finding_event["event.id"]
    assert event == finding_event


# def test_scan_finding(scan_details, scan_event):
#     event_list = [generate_events_from_webapp_scan_details(list(scan_details.values())[0])]

#     event = event_list[0]
#     del event["event.id"]
#     del scan_event["event.id"]
#     assert event == scan_event
