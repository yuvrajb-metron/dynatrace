from typing import Any


class PrimaryRegion:
    def __init__(self, data: dict[str, Any]):
        self.endColumn: int = data.get("endColumn")
        self.endLine: int = data.get("endLine")
        self.startColumn: int = data.get("startColumn")
        self.startLine: int = data.get("startLine")
        self.original_data: dict[str, Any] = data


class Attributes:
    def __init__(self, data: dict[str, Any]):
        self.cwe: list[str] = data.get("cwe", [])
        self.ignored: bool = data.get("ignored")
        self.issueType: str = data.get("issueType")
        self.severity: str = data.get("severity")
        self.title: str = data.get("title")
        self.fingerprint: str = data.get("fingerprint")
        self.fingerprintVersion: str = data.get("fingerprintVersion")
        self.primaryFilePath: str = data.get("primaryFilePath")
        self.primaryRegion: PrimaryRegion = PrimaryRegion(data.get("primaryRegion", {}))
        self.priorityScore: int = data.get("priorityScore")
        self.priorityScoreFactors: list[str] = data.get("priorityScoreFactors", [])
        self.original_data: dict[str, Any] = data


class CodeIssue:
    def __init__(self, data: dict[str, Any]):
        self.attributes: Attributes = Attributes(data.get("attributes", {}))
        self.id: str = data.get("id")
        self.type: str = data.get("type")
        self.original_data: dict[str, Any] = data
