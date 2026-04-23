from typing import Any

from .shared import JsonApi, Links


class MemberRoleDataAttributes:
    def __init__(self, data: dict[str, Any]):
        self.name: str = data.get("name")
        self.original_data: dict[str, Any] = data


class MemberRoleData:
    def __init__(self, data: dict[str, Any]):
        self.attributes: MemberRoleDataAttributes = MemberRoleDataAttributes(data.get("attributes", {}))
        self.id: str = data.get("id")
        self.type: str = data.get("type")
        self.original_data: dict[str, Any] = data


class RelationshipsMemberRole:
    def __init__(self, data: dict[str, Any]):
        self.data: MemberRoleData = MemberRoleData(data.get("data", {}))
        self.original_data: dict[str, Any] = data


class Attributes:
    def __init__(self, data: dict[str, Any]):
        self.access_requests_enabled: bool = data.get("access_requests_enabled")
        self.created_at: str = data.get("created_at")
        self.group_id: str = data.get("group_id")
        self.is_personal: bool = data.get("is_personal")
        self.name: str = data.get("name")
        self.slug: str = data.get("slug")
        self.updated_at: str = data.get("updated_at")
        self.original_data: dict[str, Any] = data


class Org:
    def __init__(self, data: dict[str, Any]):
        self.attributes: Attributes = Attributes(data.get("attributes", {}))
        self.id: str = data.get("id")
        self.relationships: RelationshipsMemberRole = RelationshipsMemberRole(data.get("relationships", {}))
        self.type: str = data.get("type")
        self.original_data: dict[str, Any] = data


class Orgs:
    def __init__(self, data: dict[str, Any]):
        self.data: list[Org] = [Org(item) for item in data.get("data", [])]
        self.jsonapi: JsonApi = JsonApi(data.get("jsonapi", {}))
        self.links: Links = Links(data.get("links", {}))
        self.original_data: dict[str, Any] = data
