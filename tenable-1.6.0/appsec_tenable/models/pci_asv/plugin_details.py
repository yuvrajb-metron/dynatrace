from typing import Any


class Attribute:
    def __init__(self, data: dict[str, Any]):
        self.attribute_name: str = data.get("attribute_name")
        self.attribute_value: str = data.get("attribute_value")
        self.original_data: dict[str, Any] = data


class Plugin:
    def __init__(self, data: dict[str, Any]):
        self.id: int = data.get("id")
        self.name: str = data.get("name")
        self.family_name: str = data.get("family_name")
        self.attributes: list[Attribute] = [Attribute(attr) for attr in data.get("attributes", [])]
        self.original_data: dict[str, Any] = data
