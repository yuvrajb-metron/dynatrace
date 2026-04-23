import json
from typing import Any


class Schedule:
    def __init__(self, data: dict[str, Any]):
        self.timezone: str = data.get("timezone")
        self.starttime: str = data.get("starttime")
        self.rrule: str = data.get("rrule")
        self.enabled: bool = data.get("enabled")
        self.original_data: dict[str, Any] = data


class WAScanConfig:
    def __init__(self, data: dict[str, Any]):
        self.config_id: str = data.get("config_id")
        self.owner_id: str = data.get("owner_id")
        self.is_shared: bool = data.get("is_shared")
        self.user_permissions: str = data.get("user_permissions")
        self.name: str = data.get("name")
        self.target_count: int = data.get("target_count")
        self.description: str | None = data.get("description")
        self.created_at: str = data.get("created_at")
        self.updated_at: str = data.get("updated_at")
        self.schedule: Schedule = Schedule(data.get("schedule") if data.get("schedule") is not None else {})
        self.template_id: str = data.get("template_id")
        self.last_scan: Any | None = data.get("last_scan")
        self.user_template: Any | None = data.get("user_template")
        self.original_data: dict[str, Any] = data


class Metadata:
    def __init__(self, data: dict[str, Any]):
        self.found_urls: int = data.get("found_urls")
        self.queued_urls: int = data.get("queued_urls")
        self.scan_status: str = data.get("scan_status")
        self.audited_urls: int = data.get("audited_urls")
        self.queued_pages: int = data.get("queued_pages")
        self.audited_pages: int = data.get("audited_pages")
        self.request_count: int = data.get("request_count")
        self.response_time: int = data.get("response_time")
        self.original_data: dict[str, Any] = data


class Scanner:
    def __init__(self, data: dict[str, Any]):
        self.group_name: str = data.get("group_name")
        self.original_data: dict[str, Any] = data


class WAScan:
    def __init__(self, data: dict[str, Any]):
        self.scan_id: str = data.get("scan_id")
        self.user_id: str = data.get("user_id")
        self.config_id: str = data.get("config_id")
        self.asset_id: str = data.get("asset_id")
        self.target: str = data.get("target")
        self.created_at: str = data.get("created_at")
        self.updated_at: str = data.get("updated_at")
        self.started_at: str = data.get("started_at")
        self.finalized_at: str = data.get("finalized_at")
        self.requested_action: str = data.get("requested_action")
        self.status: str = data.get("status")
        self.metadata: Metadata = Metadata(data.get("metadata", {}))
        self.scanner: Scanner = Scanner(data.get("scanner", {}))
        self.template_name: str = data.get("template_name")
        self.original_data: str = json.dumps(data)
