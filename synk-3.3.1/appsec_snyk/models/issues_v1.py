from typing import Any


class Identifiers:
    def __init__(self, data: dict[str, Any]):
        self.CVE: list[str] = data.get("CVE", [])
        self.CWE: list[str] = data.get("CWE", [])
        self.GHSA: list[str] = data.get("GHSA", [])
        self.original_data: dict[str, Any] = data


class Semver:
    def __init__(self, data: dict[str, Any]):
        self.vulnerable: list[str] = data.get("vulnerable", [])
        self.original_data: dict[str, Any] = data


class CvssDetail:
    def __init__(self, data: dict[str, Any]):
        self.assigner: str = data.get("assigner")
        self.severity: str = data.get("severity")
        self.cvssV3Vector: str = data.get("cvssV3Vector")
        self.cvssV3BaseScore: float = data.get("cvssV3BaseScore")
        self.modificationTime: str = data.get("modificationTime")
        self.original_data: dict[str, Any] = data


class Severity:
    def __init__(self, data: dict[str, Any]):
        self.assigner: str = data.get("assigner")
        self.cvssVersion: str = data.get("cvssVersion")
        self.severity: str = data.get("severity")
        self.vector: str = data.get("vector")
        self.baseScore: float = data.get("baseScore")
        self.modificationTime: str = data.get("modificationTime")
        self.original_data: dict[str, Any] = data


class MaturityLevel:
    def __init__(self, data: dict[str, Any]):
        self.level: str = data.get("level")
        self.format: str = data.get("format")
        self.original_data: dict[str, Any] = data


class ExploitDetails:
    def __init__(self, data: dict[str, Any]):
        self.sources: list[Any] = data.get("sources", [])
        self.maturityLevels: list[MaturityLevel] = [
            MaturityLevel(level) for level in data.get("maturityLevels", [])
        ]
        self.original_data: dict[str, Any] = data


class FixInfo:
    def __init__(self, data: dict[str, Any]):
        self.isUpgradable: bool = data.get("isUpgradable")
        self.isPinnable: bool = data.get("isPinnable")
        self.isPatchable: bool = data.get("isPatchable")
        self.isFixable: bool = data.get("isFixable")
        self.isPartiallyFixable: bool = data.get("isPartiallyFixable")
        self.nearestFixedInVersion: str = data.get("nearestFixedInVersion")
        self.fixedIn: list[str] = data.get("fixedIn", [])
        self.original_data: dict[str, Any] = data


class PriorityFactor:
    def __init__(self, data: dict[str, Any]):
        self.name: str = data.get("name")
        self.description: str = data.get("description")
        self.original_data: dict[str, Any] = data


class Priority:
    def __init__(self, data: dict[str, Any]):
        self.score: int = data.get("score")
        self.factors: list[PriorityFactor] = [PriorityFactor(factor) for factor in data.get("factors", [])]
        self.original_data: dict[str, Any] = data


class Links:
    def __init__(self, data: dict[str, Any]):
        self.paths: str = data.get("paths")
        self.original_data: dict[str, Any] = data


class IssueData:
    def __init__(self, data: dict[str, Any]):
        self.id: str = data.get("id")
        self.title: str = data.get("title")
        self.severity: str = data.get("severity")
        self.originalSeverity: str = data.get("originalSeverity")
        self.url: str = data.get("url")
        self.description: str = data.get("description")
        self.identifiers: Identifiers = Identifiers(data.get("identifiers", {}))
        self.credit: list[str] = data.get("credit", [])
        self.exploitMaturity: str = data.get("exploitMaturity")
        self.semver: Semver = Semver(data.get("semver", {}))
        self.publicationTime: str = data.get("publicationTime")
        self.disclosureTime: str = data.get("disclosureTime")
        self.CVSSv3: str = data.get("CVSSv3")
        self.cvssScore: float = data.get("cvssScore")
        self.cvssDetails: list[CvssDetail] = [CvssDetail(detail) for detail in data.get("cvssDetails", [])]
        self.severities: list[Severity] = [Severity(severity) for severity in data.get("severities", [])]
        self.exploitDetails: ExploitDetails = ExploitDetails(data.get("exploitDetails", {}))
        self.language: str = data.get("language")
        self.patches: list[Any] = data.get("patches", [])
        self.nearestFixedInVersion: str = data.get("nearestFixedInVersion")
        self.isMaliciousPackage: bool = data.get("isMaliciousPackage")
        self.path: str = data.get("path")
        self.violatedPolicyPublicId: str = data.get("violatedPolicyPublicId")
        self.original_data: dict[str, Any] = data


class IssueV1:
    def __init__(self, data: dict[str, Any]):
        self.id: str = data.get("id")
        self.issueType: str = data.get("issueType")
        self.pkgName: str = data.get("pkgName")
        self.pkgVersions: list[str] = data.get("pkgVersions", [])
        self.issueData: IssueData = IssueData(data.get("issueData", {}))
        self.isPatched: bool = data.get("isPatched")
        self.isIgnored: bool = data.get("isIgnored")
        self.fixInfo: FixInfo = FixInfo(data.get("fixInfo", {}))
        self.priorityScore: int = data.get("priorityScore")
        self.priority: Priority = Priority(data.get("priority", {}))
        self.links: Links = Links(data.get("links", {}))
        self.original_data: dict[str, Any] = data
