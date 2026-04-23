from typing import Any


class AuditEvent:
    def __init__(self, data: dict[str, Any]):
        self.group_id: str = data.get("group_id")
        self.org_id: str = data.get("org_id")
        self.user_id: str = data.get("user_id")
        self.project_id: str = data.get("project_id")
        self.event: str = data.get("event")
        self.content: dict = data.get("content", {})
        self.created: str = data.get("created")
        self.original_data: dict[str, Any] = data


class AuditLogSearch:
    def __init__(self, data: dict[str, Any]):
        self.items: list[AuditEvent] = [AuditEvent(item) for item in data.get("items", [])]
        self.type: str = data.get("type")
        self.original_data: dict[str, Any] = data
