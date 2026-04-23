from typing import Any

from .shared import JsonApi, Links


class ClassAttributes:
    def __init__(self, data: dict[str, Any]):
        self.id: str = data.get("id")
        self.source: str = data.get("source")
        self.type: str = data.get("type")
        self.original_data: dict[str, Any] = data


class RemedyMeta:
    def __init__(self, data: dict[str, Any]):
        self.schema_version: str = data.get("schema_version")
        self.original_data: dict[str, Any] = data


class Remedy:
    def __init__(self, data: dict[str, Any]):
        self.correlation_id: str = data.get("correlation_id")
        self.description: str = data.get("description")
        self.meta: RemedyMeta = RemedyMeta(data.get("meta", {}))
        self.type: str = data.get("type")
        self.original_data: dict[str, Any] = data


class Dependency:
    def __init__(self, data: dict[str, Any]):
        self.package_name: str = data.get("package_name")
        self.package_version: str = data.get("package_version")
        self.original_data: dict[str, Any] = data


class Line:
    def __init__(self, data: dict[str, Any]):
        self.column: int = data.get("column")
        self.line: int = data.get("line")


class Region:
    def __init__(self, data: dict[str, Any]):
        self.end: Line = Line(data.get("end", {}))
        self.start: Line = Line(data.get("start", {}))


class SourceLocation:
    def __init__(self, data: dict[str, Any]):
        self.commit_id: str = data.get("commit_id")
        self.file: str = data.get("file")
        self.region: Region = Region(data.get("region", {}))


class Representation:
    def __init__(self, data: dict[str, Any]):
        self.resourcePath: str = data.get("resourcePath")
        self.dependency: Dependency = Dependency(data.get("dependency", {}))
        self.sourceLocation: SourceLocation = SourceLocation(data.get("sourceLocation", {}))
        self.original_data: dict[str, Any] = data


class Coordinate:
    def __init__(self, data: dict[str, Any]):
        self.is_fixable_manually: bool = data.get("is_fixable_manually")
        self.is_fixable_snyk: bool = data.get("is_fixable_snyk")
        self.is_fixable_upstream: bool = data.get("is_fixable_upstream")
        self.is_patchable: bool = data.get("is_patchable")
        self.is_pinnable: bool = data.get("is_pinnable")
        self.is_upgradeable: bool = data.get("is_upgradeable")
        self.reachability: str = data.get("reachability")
        self.remedies: list[Remedy] = [Remedy(remedy) for remedy in data.get("remedies", [])]
        self.representations: list[Representation] = [
            Representation(rep) for rep in data.get("representations", [])
        ]
        self.original_data: dict[str, Any] = data


class Problem:
    def __init__(self, data: dict[str, Any]):
        self.id: str = data.get("id")
        self.source: str = data.get("source")
        self.type: str = data.get("type")
        self.original_data: dict[str, Any] = data


class Resolution:
    def __init__(self, data: dict[str, Any]):
        self.details: str = data.get("details")
        self.resolved_at: str = data.get("resolved_at")
        self.type: str = data.get("type")
        self.original_data: dict[str, Any] = data


class RiskFactor:
    def __init__(self, data: dict[str, Any]):
        self.name: str = data.get("name")
        self.updated_at: str = data.get("updated_at")
        self.value: bool = data.get("value")
        self.original_data: dict[str, Any] = data


class RiskScore:
    def __init__(self, data: dict[str, Any]):
        self.model: str = data.get("model")
        self.value: int = data.get("value")
        self.original_data: dict[str, Any] = data


class Risk:
    def __init__(self, data: dict[str, Any]):
        self.factors: list[RiskFactor] = [RiskFactor(factor) for factor in data.get("factors", [])]
        self.score: RiskScore = RiskScore(data.get("score", {}))
        self.original_data: dict[str, Any] = data


class Severity:
    def __init__(self, data: dict[str, Any]):
        self.level: str = data.get("level")
        self.modification_time: str = data.get("modification_time")
        self.score: float = data.get("score")
        self.source: str = data.get("source")
        self.vector: str = data.get("vector")
        self.version: str = data.get("version")
        self.original_data: dict[str, Any] = data


class Attributes:
    def __init__(self, data: dict[str, Any]):
        self.classes: list[ClassAttributes] = [ClassAttributes(cls) for cls in data.get("classes", [])]
        self.coordinates: list[Coordinate] = [Coordinate(coord) for coord in data.get("coordinates", [])]
        self.created_at: str = data.get("created_at")
        self.description: str = data.get("description")
        self.effective_severity_level: str = data.get("effective_severity_level")
        self.ignored: bool = data.get("ignored")
        self.key: str = data.get("key")
        self.problems: list[Problem] = [Problem(problem) for problem in data.get("problems", [])]
        self.resolution: Resolution = Resolution(data.get("resolution", {}))
        self.risk: Risk = Risk(data.get("risk", {}))
        self.severities: list[Severity] = [Severity(sev) for sev in data.get("severities", [])]
        self.status: str = data.get("status")
        self.title: str = data.get("title")
        self.tool: str = data.get("tool")
        self.type: str = data.get("type")
        self.updated_at: str = data.get("updated_at")
        self.original_data: dict[str, Any] = data


class RelationshipLinks:
    def __init__(self, data: dict[str, Any]):
        self.related: str = data.get("related")
        self.original_data: dict[str, Any] = data


class RelationshipsData:
    def __init__(self, data: dict[str, Any]):
        self.id: str = data.get("id")
        self.type: str = data.get("type")
        self.original_data: dict[str, Any] = data


class RelationshipsItem:
    def __init__(self, data: dict[str, Any]):
        self.data: RelationshipsData = RelationshipsData(data.get("data", {}))
        self.links: RelationshipLinks = RelationshipLinks(data.get("links", {}))
        self.original_data: dict[str, Any] = data


class Relationships:
    def __init__(self, data: dict[str, Any]):
        self.ignore: RelationshipsItem = RelationshipsItem(data.get("ignore", {}))
        self.organization: RelationshipsItem = RelationshipsItem(data.get("organization", {}))
        self.scan_item: RelationshipsItem = RelationshipsItem(data.get("scan_item", {}))
        self.original_data: dict[str, Any] = data


class Issue:
    def __init__(self, data: dict[str, Any]):
        self.attributes: Attributes = Attributes(data.get("attributes", {}))
        self.id: str = data.get("id")
        self.relationships: Relationships = Relationships(data.get("relationships", {}))
        self.type: str = data.get("type")
        self.original_data: dict[str, Any] = data


class Issues:
    def __init__(self, data: dict[str, Any]):
        self.data: list[Issue] = [Issue(item) for item in data.get("data", [])]
        self.jsonapi: JsonApi = JsonApi(data.get("jsonapi", {}))
        self.links: Links = Links(data.get("links", {}))
        self.original_data: dict[str, Any] = data
