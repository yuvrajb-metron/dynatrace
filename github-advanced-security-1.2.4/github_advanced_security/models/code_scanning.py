import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..github_object import GithubObject
from ..shared import datetime_from_github_timestamp, Repository, Location


class Rule(GithubObject):
    def _create_from_raw_data(self, raw_element):
        self.id: str = raw_element["id"]
        self.name: str = raw_element["name"]
        self.severity: str = raw_element["severity"]
        self.security_severity_level: str = raw_element.get("security_severity_level")
        self.tags: list[str] = raw_element.get("tags", [])
        self.description: str = raw_element.get("description")
        self.full_description: str = raw_element.get("full_description")
        self.help: str = raw_element.get("help")


class Tool(GithubObject):
    def _create_from_raw_data(self, raw_element):
        self.name: str = raw_element["name"]
        self.guid: str = raw_element.get("guid")
        self.version: str = raw_element.get("version")


class Instance(GithubObject):
    def _create_from_raw_data(self, raw_element):
        self.ref: str = raw_element.get("ref")
        self.analysis_key: str = raw_element.get("analysis_key")
        self.category: str = raw_element.get("category")
        self.environment: str = raw_element.get("environment")
        self.state: str = raw_element.get("state")
        self.commit_sha: str = raw_element.get("commit_sha")
        self.message: str = raw_element.get("message")
        self.classifications: list[str] = raw_element.get("classifications", [])
        self.location: Location = Location(raw_element=raw_element["location"])

class CodeScanAnalysis(GithubObject):
    def _create_from_raw_data(self, raw_element):
        self.commit_sha: str = raw_element["commit_sha"]
        self.analysis_key: str = raw_element["analysis_key"]
        self.environment: str = raw_element["environment"]
        self.category: str = raw_element["category"]
        self.created_at: datetime = (
            datetime_from_github_timestamp(raw_element.get("created_at"))
            if raw_element.get("created_at")
            else ""
        )
        self.results_count: int = raw_element["results_count"]
        self.rules_count: int = raw_element["rules_count"]
        self.id: int = raw_element["id"]
        self.url: str = raw_element["url"]
        self.sarif_id: str = raw_element["sarif_id"]
        self.tool: Tool = Tool(raw_element=raw_element.get("tool"))
        self.error: str = raw_element["error"]
        self.warning: str = raw_element["warning"]
        self.deletable: bool = raw_element["deletable"]
        self.original_content: dict = raw_element

class CodeScanningAlert(GithubObject):
    def _create_from_raw_data(self, raw_element: Dict[str, Any]):
        self.number: int = raw_element.get("number")
        self.state: str = raw_element.get("state")
        self.created_at: datetime = (
            datetime_from_github_timestamp(raw_element.get("created_at"))
            if raw_element.get("created_at")
            else ""
        )
        self.updated_at: datetime = (
            datetime_from_github_timestamp(raw_element.get("updated_at"))
            if raw_element.get("updated_at")
            else ""
        )
        self.dismissed_at: datetime = (
            datetime_from_github_timestamp(raw_element.get("dismissed_at"))
            if raw_element.get("dismissed_at")
            else ""
        )
        self.fixed_at: datetime = (
            datetime_from_github_timestamp(raw_element.get("fixed_at"))
            if raw_element.get("fixed_at")
            else ""
        )
        self.dismissed_at: datetime = (
            datetime_from_github_timestamp(raw_element.get("dismissed_at"))
            if raw_element.get("dismissed_at")
            else ""
        )
        self.dismissed_by: str = raw_element.get("dismissed_by")
        self.dismissed_reason: str = raw_element.get("dismissed_reason")
        self.dismissed_comment: str = raw_element.get("dismissed_comment")
        self.url: str = raw_element["url"]
        self.html_url: str = raw_element["html_url"]
        self.rule: Rule = Rule(raw_element=raw_element.get("rule"))
        self.tool: Tool = Tool(raw_element=raw_element.get("tool"))
        self.most_recent_instance: Instance = Instance(
            raw_element=raw_element.get("most_recent_instance")
        )
        self.repository: Repository = (
            Repository(raw_element=raw_element.get("repository"))
            if raw_element.get("repository")
            else None
        )
        self.original_content: dict = raw_element
