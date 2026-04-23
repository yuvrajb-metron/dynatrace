"""
Public domain models and wrappers (GitLab entities, scan/finding views, audit rows).

Import from here for type hints and tests; internal modules may import concretely.
"""

from .audit_log_details import AuditLogDetails
from .dependency_details import DependencyDetails
from .dynatrace_security_event import DynatraceSecurityEvent
from .gitlab_objects import (
    GitLabFinding,
    GitLabGroup,
    GitLabJob,
    GitLabPipeline,
    GitLabProject,
)
from .repository_scan import RepositoryScan
from .vulnerability_details import VulnerabilityDetails

__all__ = [
    "AuditLogDetails",
    "DependencyDetails",
    "DynatraceSecurityEvent",
    "GitLabFinding",
    "GitLabGroup",
    "GitLabJob",
    "GitLabPipeline",
    "GitLabProject",
    "RepositoryScan",
    "VulnerabilityDetails",
]
