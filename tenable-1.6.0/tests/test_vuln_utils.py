import json
from pathlib import Path

import pytest

from appsec_tenable.models.vulnerability_management.assets import Asset
from appsec_tenable.models.vulnerability_management.scans import ScanDetails
from appsec_tenable.models.vulnerability_management.vulns import VulnerabilityDetails
from appsec_tenable.utils.vulnerability_management.scans import generate_events_from_single_scan
from appsec_tenable.utils.vulnerability_management.vulns import generate_event_from_vuln

SAMPLE_DATA_PATH = Path(__file__).parent / "sample_data" / "test_vuln_utils"


# class TestGenerateEvent:
@pytest.fixture
def vulnerability_details():
    with open(SAMPLE_DATA_PATH / "sample_vulnerability.json") as f:
        return VulnerabilityDetails(json.load(f))


@pytest.fixture
def asset():
    with open(SAMPLE_DATA_PATH / "sample_asset.json") as f:
        return Asset(json.load(f))


@pytest.fixture
def scan_details():
    with open(SAMPLE_DATA_PATH / "sample_scan_details.json") as f:
        return ScanDetails(json.load(f))


@pytest.fixture
def finding_event():
    with open(SAMPLE_DATA_PATH / "sample_finding_event.json") as f:
        return json.load(f)


@pytest.fixture
def scan_event():
    with open(SAMPLE_DATA_PATH / "sample_scan_event.json") as f:
        return json.load(f)


def test_vulnerability_finding(vulnerability_details, asset, scan_details, finding_event):
    event_list: list[dict] = generate_event_from_vuln(
        "",
        "",
        "",
        vulnerability_details,
        {"ffabe5c2-b820-4d42-b5a5-244e1a033b03": asset},
        {"ea4e281a-015e-4848-81b3-80d16bafa20e": scan_details},
        {},
    )
    assert len(event_list) == 1

    event = event_list[0]
    del event["event.id"]
    del finding_event["event.id"]
    assert event == finding_event


def test_scan_finding(scan_details, asset, scan_event):
    event_list = generate_events_from_single_scan(
        scan_details, 1, {"ffabe5c2-b820-4d42-b5a5-244e1a033b03": asset}
    )

    assert len(event_list) == 1

    event = event_list[0]
    del event["event.id"]
    del scan_event["event.id"]
    assert event == scan_event
