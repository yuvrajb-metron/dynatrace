from typing import Any


class Attributes:
    def __init__(self, data: dict[str, Any]):
        self.layers: list[str] = data.get("layers", [])
        self.names: list[str] = data.get("names", [])
        self.platform: str = data.get("platform")
        self.original_data: dict[str, Any] = data


class Links:
    def __init__(self, data: dict[str, Any]):
        self.self: str = data.get("self")
        self.original_data: dict[str, Any] = data


class ImageTargetRefs:
    def __init__(self, data: dict[str, Any]):
        self.links: Links = Links(data.get("links", {}))
        self.original_data: dict[str, Any] = data


class Relationships:
    def __init__(self, data: dict[str, Any]):
        self.image_target_refs: ImageTargetRefs = ImageTargetRefs(data.get("image_target_refs", {}))
        self.original_data: dict[str, Any] = data


class Data:
    def __init__(self, data: dict[str, Any]):
        self.attributes: Attributes = Attributes(data.get("attributes", {}))
        self.id: str = data.get("id")
        self.relationships: Relationships = Relationships(data.get("relationships", {}))
        self.type: str = data.get("type")
        self.original_data: dict[str, Any] = data


class JsonApi:
    def __init__(self, data: dict[str, Any]):
        self.version: str = data.get("version")
        self.original_data: dict[str, Any] = data


class ContainerImage:
    def __init__(self, data: dict[str, Any]):
        self.data: Data = Data(data.get("data", {}))
        self.jsonapi: JsonApi = JsonApi(data.get("jsonapi", {}))
        self.links: Links = Links(data.get("links", {}))
        self.original_data: dict[str, Any] = data
