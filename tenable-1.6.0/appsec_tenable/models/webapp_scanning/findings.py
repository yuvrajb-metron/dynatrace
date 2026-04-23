import json
from typing import Any


class VPR:
    def __init__(self, data: dict[str, Any]):
        self.score: float = data.get("score")
        self.original_data: dict[str, Any] = data


class Plugin:
    def __init__(self, data: dict[str, Any]):
        self.bid: list[str] = data.get("bid", [])
        self.id: int = data.get("id")
        self.risk_factor: str = data.get("risk_factor")
        self.original_risk_factor_num: int = data.get("original_risk_factor_num")
        self.locale: str = data.get("locale")
        self.type: str = data.get("type")
        self.intel_type: str = data.get("intel_type")
        self.name: str = data.get("name")
        self.publication_date: str = data.get("publication_date")
        self.modification_date: str = data.get("modification_date")
        self.see_also: list[str] = data.get("see_also", [])
        self.solution: str = data.get("solution")
        self.synopsis: str = data.get("synopsis")
        self.description: str = data.get("description")
        self.patch_publication_date: str = data.get("patch_publication_date")
        self.exploitability_ease: str = data.get("exploitability_ease")
        self.public_display: int = data.get("public_display")
        self.policy: list[Any] = data.get("policy", [])
        self.xrefs: list[dict[str, Any]] = data.get("xrefs", [])
        self.cpe: list[str] = data.get("cpe", [])
        self.cve: list[str] = data.get("cve", [])
        self.cwe: list[str] = data.get("cwe", [])
        self.wasc: list[str] = data.get("wasc", [])
        self.in_the_news: bool = data.get("in_the_news")
        self.exploited_by_malware: bool = data.get("exploited_by_malware")
        self.exploit_frameworks: list[dict[str, Any]] = data.get("exploit_frameworks", [])
        self.vpr: VPR = VPR(data.get("vpr", {}))
        self.cvss2_base_score: float = data.get("cvss2_base_score")
        self.cvss2_temporal_vector: dict[str, Any] = data.get("cvss2_temporal_vector", {})
        self.cvss2_vector: dict[str, Any] = data.get("cvss2_vector", {})
        self.cvss3_base_score: float = data.get("cvss3_base_score")
        self.cvss3_temporal_vector: dict[str, Any] = data.get("cvss3_temporal_vector", {})
        self.cvss3_vector: dict[str, Any] = data.get("cvss3_vector", {})
        self.owasp_2010: list[str] = data.get("owasp_2010", [])
        self.owasp_2013: list[str] = data.get("owasp_2013", [])
        self.owasp_2017: list[str] = data.get("owasp_2017", [])
        self.owasp_2021: list[str] = data.get("owasp_2021", [])
        self.owasp_api_2019: list[str] = data.get("owasp_api_2019", [])
        self.has_patch: bool = data.get("has_patch")
        self.exploit_available: bool = data.get("exploit_available")
        self.data: dict[str, Any] = data


class Asset:
    def __init__(self, data: dict[str, Any]):
        self.uuid: str = data.get("uuid")
        self.fqdn: str = data.get("fqdn")
        self.ipv4s: list[str] = data.get("ipv4s", [])
        self.ipv4: str = data.get("ipv4")
        self.data: dict[str, Any] = data


class Scan:
    def __init__(self, data: dict[str, Any]):
        self.completed_at: str = data.get("completed_at")
        self.uuid: str = data.get("uuid")
        self.data: dict[str, Any] = data


class WebAppFinding:
    def __init__(self, data: dict[str, Any]):
        self.finding_id: str = data.get("finding_id")
        self.url: str = data.get("url")
        self.input_type: str = data.get("input_type")
        self.input_name: str = data.get("input_name")
        self.http_method: str = data.get("http_method")
        self.proof: str = data.get("proof")
        self.payload: str = data.get("payload")
        self.output: str = data.get("output")
        self.state: str = data.get("state")
        self.severity: str = data.get("severity")
        self.severity_id: int = data.get("severity_id")
        self.severity_default_id: int = data.get("severity_default_id")
        self.severity_modification_type: str = data.get("severity_modification_type")
        self.first_found: str = data.get("first_found")
        self.last_found: str = data.get("last_found")
        self.last_fixed = data.get("last_fixed")
        self.indexed_at: str = data.get("indexed_at")
        self.plugin: Plugin = Plugin(data.get("plugin", {}))
        self.asset: Asset = Asset(data.get("asset", {}))
        self.scan: Scan = Scan(data.get("scan", {}))
        self.data: str = json.dumps(data)
