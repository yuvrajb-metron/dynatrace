from typing import Any


class RecurringTests:
    def __init__(self, data: dict[str, Any]):
        self.frequency: str = data.get("frequency")
        self.original_data: dict[str, Any] = data


class PullRequests:
    def __init__(self, data: dict[str, Any]):
        self.fail_only_for_issues_with_fix: bool = data.get("fail_only_for_issues_with_fix")
        self.original_data: dict[str, Any] = data


class Settings:
    def __init__(self, data: dict[str, Any]):
        self.recurring_tests: RecurringTests = RecurringTests(data.get("recurring_tests", {}))
        self.pull_requests: PullRequests = PullRequests(data.get("pull_requests", {}))
        self.original_data: dict[str, Any] = data


class Attributes:
    def __init__(self, data: dict[str, Any]):
        self.name: str = data.get("name")
        self.type: str = data.get("type")
        self.target_file: str = data.get("target_file")
        self.target_reference: str = data.get("target_reference")
        self.origin: str = data.get("origin")
        self.created: str = data.get("created")
        self.status: str = data.get("status")
        self.business_criticality: list[Any] = data.get("business_criticality", [])
        self.environment: list[Any] = data.get("environment", [])
        self.lifecycle: list[Any] = data.get("lifecycle", [])
        self.tags: list[Any] = data.get("tags", [])
        self.read_only: bool = data.get("read_only")
        self.settings: Settings = Settings(data.get("settings", {}))
        self.original_data: dict[str, Any] = data


class OrganizationData:
    def __init__(self, data: dict[str, Any]):
        self.type: str = data.get("type")
        self.id: str = data.get("id")
        self.original_data: dict[str, Any] = data


class Organization:
    def __init__(self, data: dict[str, Any]):
        self.data: OrganizationData = OrganizationData(data.get("data", {}))
        self.links: dict[str, str] = data.get("links", {})
        self.original_data: dict[str, Any] = data


class TargetAttributes:
    def __init__(self, data: dict[str, Any]):
        self.display_name: str = data.get("display_name")
        self.url: str = data.get("url")
        self.original_data: dict[str, Any] = data


class IntegrationData:
    def __init__(self, data: dict[str, Any]):
        self.id: int = data.get("id")
        self.name: str = data.get("name")
        self.owner: str = data.get("owner")
        self.repo: str = data.get("repo")
        self.original_data: dict[str, Any] = data


class TargetMeta:
    def __init__(self, data: dict[str, Any]):
        self.integration_data: IntegrationData = IntegrationData(data.get("integration_data", {}))
        self.original_data: dict[str, Any] = data


class TargetData:
    def __init__(self, data: dict[str, Any]):
        self.id: str = data.get("id")
        self.type: str = data.get("type")
        self.attributes: TargetAttributes = TargetAttributes(data.get("attributes", {}))
        self.meta: TargetMeta = TargetMeta(data.get("meta", {}))
        self.original_data: dict[str, Any] = data


class Target:
    def __init__(self, data: dict[str, Any]):
        self.data: TargetData = TargetData(data.get("data", {}))
        self.links: dict[str, str] = data.get("links", {})
        self.original_data: dict[str, Any] = data


class ImporterData:
    def __init__(self, data: dict[str, Any]):
        self.type: str = data.get("type")
        self.id: str = data.get("id")
        self.original_data: dict[str, Any] = data


class Importer:
    def __init__(self, data: dict[str, Any]):
        self.data: ImporterData = ImporterData(data.get("data", {}))
        self.links: dict[str, str] = data.get("links", {})
        self.original_data: dict[str, Any] = data


class Relationships:
    def __init__(self, data: dict[str, Any]):
        self.organization: Organization = Organization(data.get("organization", {}))
        self.target: Target = Target(data.get("target", {}))
        self.importer: Importer = Importer(data.get("importer", {}))
        self.original_data: dict[str, Any] = data


class LatestIssueCounts:
    def __init__(self, data: dict[str, Any]):
        self.critical: int = data.get("critical")
        self.high: int = data.get("high")
        self.medium: int = data.get("medium")
        self.low: int = data.get("low")
        self.updated_at: str = data.get("updated_at")
        self.original_data: dict[str, Any] = data


class Meta:
    def __init__(self, data: dict[str, Any]):
        self.latest_issue_counts: LatestIssueCounts = LatestIssueCounts(data.get("latest_issue_counts", {}))
        self.original_data: dict[str, Any] = data


class ContainerData:
    def __init__(self, data: dict[str, Any]):
        self.image_id: str = data.get("imageId")
        self.image_tag: str = data.get("imageTag")
        self.image_platform: str = data.get("imagePlatform")
        self.image_base_image: str = data.get("imageBaseImage")
        self.image_digest: str = data.get("imageDigest")
        self.original_data: dict[str, Any] = data


class Project:
    def __init__(self, data: dict[str, Any]):
        self.type: str = data.get("type")
        self.id: str = data.get("id")
        self.meta: Meta = Meta(data.get("meta", {}))
        self.attributes: Attributes = Attributes(data.get("attributes", {}))
        self.container: ContainerData = ContainerData({})
        self.relationships: Relationships = Relationships(data.get("relationships", {}))
        self.original_data: dict[str, Any] = data
