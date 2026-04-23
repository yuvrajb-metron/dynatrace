import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..github_object import GithubObject
from ..shared import datetime_from_github_timestamp, Repository, Location


class Scan(GithubObject):
    def _create_from_raw_data(self, raw_element):
        self.type: str = raw_element["type"]
        self.status: str = raw_element["status"]
        self.completed_at: datetime = (
            datetime_from_github_timestamp(raw_element.get("updated_at"))
            if raw_element.get("completed_at")
            else ""
        )
        self.started_at: datetime = (
            datetime_from_github_timestamp(raw_element.get("updated_at"))
            if raw_element.get("started_at")
            else ""
        )

class SecretScanningHistory(GithubObject):
    def _create_from_raw_data(self, raw_element):
        self.incremental_scans: List[Scan] = [Scan(raw_element=s) for s in raw_element.get("incremental_scans", [])]
        self.backfill_scans: List[Scan] = [Scan(raw_element=s) for s in raw_element.get("backfill_scans", [])]
        self.custom_pattern_backfill_scans: List[Scan] = [Scan(raw_element=s) for s in raw_element.get("custom_pattern_backfill_scans", [])]
        self.pattern_update_scans: List[Scan] = [Scan(raw_element=s) for s in raw_element.get("pattern_update_scans", [])]
        

class SecretScanningAlert(GithubObject):
    def _create_from_raw_data(self, raw_element: Dict[str, Any]):
        self.number: int = raw_element.get("number")
        self.created_at: datetime = (
            datetime_from_github_timestamp(raw_element.get("created_at"))
            if raw_element.get("created_at")
            else ""
        )
        self.updated_at: datetime = (
            datetime_from_github_timestamp(raw_element.get("updated_at"))
            if raw_element.get("updated_at")
            else ""
        )
        self.url: str = raw_element["url"]
        self.html_url: str = raw_element["html_url"]
        self.locations_url: str = raw_element["locations_url"]
        self.state: str = raw_element["state"]
        self.secret_type: str = raw_element["secret_type"]
        self.secret_type_display_name: str = raw_element["secret_type_display_name"]
        self.validity: str = "unknown"
        self.multi_repo: bool = raw_element["multi_repo"]
        self.is_base64_encoded: bool = raw_element["is_base64_encoded"]
        self.secret: str = raw_element.get("secret")
        self.first_location_detected: Location = Location(raw_element=raw_element["first_location_detected"])
        self.has_more_locations: bool = raw_element["has_more_locations"]
        self.publicly_leaked: bool = raw_element["publicly_leaked"]
        self.push_protection_bypassed: bool = raw_element["push_protection_bypassed"]
        self.push_protection_bypassed_by: Optional[str] = raw_element["push_protection_bypassed_by"]
        self.original_content: dict = raw_element


