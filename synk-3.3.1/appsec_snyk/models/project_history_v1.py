from typing import Any


class CloudConfig:
    def __init__(self, data: dict[str, Any]):
        self.low: int = data.get("low")
        self.high: int = data.get("high")
        self.medium: int = data.get("medium")
        self.critical: int = data.get("critical")
        self.original_data: dict[str, Any] = data


class IssueCounts:
    def __init__(self, data: dict[str, Any]):
        self.cloudConfig: CloudConfig = CloudConfig(data.get("cloudConfig", {}))
        self.original_data: dict[str, Any] = data


class Snapshot:
    def __init__(self, data: dict[str, Any]):
        self.id: str = data.get("id")
        self.created: str = data.get("created")
        self.totalDependencies: int | None = data.get("totalDependencies")
        self.issueCounts: IssueCounts = IssueCounts(data.get("issueCounts", {}))
        self.method: str = data.get("method")
        self.original_data: dict[str, Any] = data


class SnapshotsData:
    def __init__(self, data: dict[str, Any]):
        self.snapshots: list[Snapshot] = [Snapshot(snapshot) for snapshot in data.get("snapshots", [])]
        self.total: int = data.get("total")
        self.original_data: dict[str, Any] = data
