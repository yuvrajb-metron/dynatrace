import logging
from typing import Dict, Any, Optional
from datetime import datetime
from .harbor_object import HarborObject
from .shared import datetime_from_harbor_timestamp

default_log = logging.getLogger(__name__)


class Scanner(HarborObject):
    def _create_from_raw_data(self, raw_element: Dict[str, Any]):
        self.name: str = raw_element.get("name")
        self.vendor: str = raw_element.get("vendor")
        self.version: str = raw_element.get("version")


class ScanOverview(HarborObject):
    def _create_from_raw_data(self, raw_element: Dict[str, Any]):
        self.complete_percent: int = raw_element.get("complete_percent")
        self.duration: int = raw_element.get("duration")
        self.report_id: str = raw_element.get("report_id")
        self.start_time: datetime = datetime_from_harbor_timestamp(
            raw_element.get("start_time")
        )
        self.end_time: datetime = (
            datetime_from_harbor_timestamp(raw_element.get("end_time"))
            if raw_element.get("end_time")
            else ""
        )
        self.scanner: Scanner = Scanner(raw_element=raw_element.get("scanner"))
        self.scan_status: str = raw_element.get("scan_status")


class Artifact(HarborObject):
    def _create_from_raw_data(self, raw_element: Dict[str, Any]):
        self.type: str = raw_element.get("type")
        self.artifact_type: str = raw_element.get("artifact_type")
        self.repository_name: str = raw_element.get("repository_name")
        self.digest: str = raw_element.get("digest")
        self.id: int = raw_element.get("id")
        self.project_id: str = raw_element.get("project_id")
        self.project_name: str = None  # must be set during execution
        self.repository_id: str = raw_element.get("repository_id")
        self.tags: Dict[str, Any] = (
            [tag["name"] for tag in raw_element.get("tags")]
            if raw_element.get("tags")
            else []
        )
        self.scan_overview: Optional[ScanOverview] = (
            ScanOverview(
                raw_element=raw_element.get("scan_overview")[
                    "application/vnd.security.vulnerability.report; version=1.1"
                ]
            )
            if raw_element.get("scan_overview")
            else None
        )
        self.original_content: dict = raw_element
