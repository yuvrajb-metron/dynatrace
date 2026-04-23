from typing import Any


class JsonApi:
    def __init__(self, data: dict[str, Any]):
        self.version: str = data.get("version")
        self.original_data: dict[str, Any] = data


class Links:
    def __init__(self, data: dict[str, Any]):
        self.first: str = data.get("first")
        self.last: str = data.get("last")
        self.next: str = data.get("next")
        self.original_data: dict[str, Any] = data
