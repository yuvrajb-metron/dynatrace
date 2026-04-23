"""
Package / dependency fields extracted from a GitLab vulnerability ``location``.
"""

from __future__ import annotations

from .gitlab_objects import GitLabFinding


class DependencyDetails:
    """
    Normalized dependency package name, version, and lockfile path for event mapping.

    Responsibility:
        Read nested ``location.dependency`` and related fields from ``GitLabFinding``.
    """

    def __init__(self, finding: GitLabFinding) -> None:
        """
        Args:
            finding: Parsed GitLab vulnerability node.
        """
        self.dep_name = finding.location.get("dependency", {}).get("package", {}).get("name")
        self.current_version = finding.location.get("dependency", {}).get("version")
        self.package_file = finding.location.get("file") or finding.blob_path
