"""
Lightweight wrappers around raw GitLab REST/GraphQL JSON blobs.

Responsibility:
    Provide attribute access and store ``.raw`` for ``event.original_content``.
"""

from __future__ import annotations

from ..utils.helpers import get_primary_identifier


class GitLabGroup:
    """
    Parsed GitLab group JSON.
    """

    def __init__(self, data: dict | None = None) -> None:
        """
        Args:
            data: Group object from the GitLab API, or empty dict.
        """
        data = data or {}
        self.id = data.get("id")
        self.name = data.get("name")
        self.full_path = data.get("full_path")
        self.web_url = data.get("web_url")
        self.raw = data


class GitLabProject:
    """
    Parsed GitLab project JSON.
    """

    def __init__(self, data: dict | None = None) -> None:
        """
        Args:
            data: Project object from the GitLab API, or empty dict.
        """
        data = data or {}
        self.id = data.get("id")
        self.name = data.get("name")
        self.path_with_namespace = data.get("path_with_namespace")
        self.web_url = data.get("web_url")
        self.default_branch = data.get("default_branch")
        self.raw = data


class GitLabJob:
    """
    Parsed GitLab CI job JSON.
    """

    def __init__(self, data: dict | None = None) -> None:
        """
        Args:
            data: Job object from the GitLab API, or empty dict.
        """
        data = data or {}
        self.id = data.get("id")
        self.name = data.get("name")
        self.status = data.get("status")
        self.stage = data.get("stage")
        self.web_url = data.get("web_url")
        self.created_at = data.get("created_at")
        self.started_at = data.get("started_at")
        self.finished_at = data.get("finished_at")
        self.raw = data


class GitLabPipeline:
    """
    Parsed GitLab pipeline JSON.
    """

    def __init__(self, data: dict | None = None) -> None:
        """
        Args:
            data: Pipeline object from the GitLab API, or empty dict.
        """
        data = data or {}
        self.id = data.get("id")
        self.iid = data.get("iid")
        self.status = data.get("status")
        self.web_url = data.get("web_url")
        self.ref = data.get("ref")
        self.sha = data.get("sha")
        self.created_at = data.get("created_at")
        self.updated_at = data.get("updated_at")
        self.raw = data


class GitLabFinding:
    """
    Parsed GitLab vulnerability / security finding node (GraphQL shape).

    Responsibility:
        Normalize mixed camelCase/snake_case fields and expose ``location``, ``identifiers``, etc.
    """

    def __init__(self, data: dict | None = None) -> None:
        """
        Args:
            data: Merged vulnerability dict from GitLab, or empty dict.
        """
        data = data or {}
        self.id = data.get("id") or data.get("gid")
        self.uuid = data.get("uuid")
        self.name = data.get("name")
        self.title = data.get("title")
        self.description = data.get("description")
        raw_severity = data.get("severity")
        if isinstance(raw_severity, str):
            self.severity = "NONE" if raw_severity == "UNKNOWN" else raw_severity.upper()
        elif raw_severity is None:
            self.severity = "NONE"
        else:
            severity_str = str(raw_severity)
            self.severity = "NONE" if severity_str == "UNKNOWN" else severity_str.upper()
        self.state = data.get("state")
        raw_report_type = data.get("reportType") or data.get("report_type")
        if isinstance(raw_report_type, str):
            normalized_report_type = raw_report_type.upper()
            self.report_type = normalized_report_type if normalized_report_type else None
        elif raw_report_type is None:
            self.report_type = None
        else:
            normalized_report_type = str(raw_report_type).upper()
            self.report_type = normalized_report_type if normalized_report_type else None
        self.solution = data.get("solution")
        if "falsePositive" in data:
            self.false_positive = data.get("falsePositive")
        else:
            self.false_positive = data.get("false_positive")
        self.scanner = data.get("scanner") or {}
        self.identifiers = data.get("identifiers") or []
        self.primary_identifier = get_primary_identifier(self.identifiers)
        self.location = data.get("location") or {}
        self.links = data.get("links") or []
        self.details = data.get("details") or {}
        self.project = data.get("project") or {}
        self.blob_path = data.get("blobPath") or data.get("blob_path") or self.location.get("blobPath")
        self.remediations = data.get("remediations") or []
        self.raw = data
