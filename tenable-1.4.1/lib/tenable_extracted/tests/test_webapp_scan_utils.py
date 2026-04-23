import json
from pathlib import Path

import pytest

from appsec_tenable.models.webapp_scanning.findings import WebAppFinding
from appsec_tenable.models.webapp_scanning.scans import WAScan
from appsec_tenable.utils.webapp_scanning.findings import generate_event_from_webapp_finding
from appsec_tenable.utils.webapp_scanning.scans import generate_events_from_webapp_scan_details

SAMPLE_DATA_PATH = Path(__file__).parent / "sample_data" / "test_webapp_scan_utils"


# class TestGenerateEvent:
@pytest.fixture
def finding_details():
    with open(SAMPLE_DATA_PATH / "sample_finding.json") as f:
        return WebAppFinding(json.load(f))


@pytest.fixture
def scan_details():
    with open(SAMPLE_DATA_PATH / "sample_scan_details.json") as f:
        return {scan.get("scan_id"): WAScan(scan) for scan in json.load(f).get("items")}


@pytest.fixture
def finding_event():
    with open(SAMPLE_DATA_PATH / "sample_finding_event.json") as f:
        return json.load(f)


@pytest.fixture
def scan_event():
    with open(SAMPLE_DATA_PATH / "sample_scan_event.json") as f:
        return json.load(f)


def test_webapp_finding(finding_details, scan_details, finding_event):
    event_list: list[dict] = generate_event_from_webapp_finding(finding_details, scan_details, None, "")

    assert len(event_list) == 1

    event = event_list[0]
    del event["event.id"]
    del finding_event["event.id"]
    assert event == finding_event


def test_scan_finding(scan_details, scan_event):
    event_list = [generate_events_from_webapp_scan_details(list(scan_details.values())[0])]

    event = event_list[0]
    del event["event.id"]
    del scan_event["event.id"]
    assert event == scan_event
