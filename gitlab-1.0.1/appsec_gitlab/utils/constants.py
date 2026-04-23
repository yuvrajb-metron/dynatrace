"""
Central configuration keys, defaults, and static enums for the GitLab extension.

Responsibility:
    Single source for activation JSON field names, event type strings, risk mappings,
    HTTP status thresholds, and GitLab report-type constants. No runtime I/O.
"""

EXTENSION_MODULE_NAME = "appsec-gitlab"
DT_EXTENSION_NAME = "com.dynatrace.extension.gitlab"
GITLAB_FETCH_PAGE_SIZE = 100
GITLAB_GRAPHQL_PAGE_SIZE = 100
DEVELOPMENT_TASK_ID = "development_task_id"
DT_ENVIRONMENT_ID = "dt_environment_id"
DEFAULT_POLL_HOURS = 24
DEFAULT_FIRST_TIME_FETCH_WINDOW_DAYS = 7
DEFAULT_AUDIT_EVENT_FREQUENCY_MINUTES = 60
DEFAULT_DYNATRACE_CHUNK_MAX_BYTES = 9_500_000
ADVANCED_OPTIONS = "advanced_options"
DEBUG_LOGS = "debug_logs"
FEATURES = "features"
COLLECT_DEPENDENCY_SCANNING_ALERTS = "collect_dependency_scanning_alerts"
COLLECT_CONTAINER_SCANNING_ALERTS = "collect_container_scanning_alerts"
COLLECT_AUDIT_EVENTS = "collect_audit_events"
GITLAB = "gitlab"
GITLAB_URL = "url"
GITLAB_TOKEN = "token"
EVENT_PROVIDER = "GitLab"
ALL_GROUPS = "all_groups"
GROUPS = "groups"
ALL_PROJECTS = "all_projects"
PROJECTS = "projects"

DYNATRACE = "dynatrace"
DYNATRACE_TOKEN = "token"
DYNATRACE_SECURITY_INGEST_URL = "dynatrace_security_ingest_url"
USE_CUSTOM_SECURITY_INGEST_URL = "use_custom_security_ingest_url"
SECURITY_FINDINGS_FREQUENCY_HOURS = "security_findings_frequency_hours"
FIRST_TIME_FETCH_WINDOW_DAYS = "first_time_fetch_window_days"
AUDIT_EVENT_FREQUENCY_MINUTES = "audit_event_frequency_minutes"

DYNATRACE_SECURITY_INGEST_URL_PATH = "platform/ingest/v1/security.events"
DYNATRACE_LOCALHOST_URL = f"https://localhost:9999/e"



EVENT_TYPE_VULNERABILITY_SCAN = "VULNERABILITY_SCAN"
EVENT_TYPE_VULNERABILITY_FINDING = "VULNERABILITY_FINDING"
EVENT_TYPE_LOG = "LOG"
PRODUCT_VENDOR = "GitLab"
# Fallback ``product.name`` on VULNERABILITY_SCAN when job name hints and GraphQL scanner id are absent.
DEFAULT_SCAN_PRODUCT_NAME = "gitlab-security"
REMEDIATION_STATUS_AVAILABLE = "AVAILABLE"
REMEDIATION_STATUS_NOT_AVAILABLE = "NOT_AVAILABLE"


FULL_PATH = "fullPath"
CONTAINER_IMAGE = "CONTAINER_IMAGE"
CODE_ARTIFACT = "CODE_ARTIFACT"
CONTAINER_SCANNING = "CONTAINER_SCANNING"
DEPENDENCY_SCANNING = "DEPENDENCY_SCANNING"
CONTAINER_VULNERABILITY = "CONTAINER_VULNERABILITY"
DEPENDENCY_VULNERABILITY = "DEPENDENCY_VULNERABILITY"
# GitLab identifier externalType for CVE; only identifiers with this type are treated as CVE
CVE_EXTERNAL_TYPE = "cve"
PKG = "pkg"

REPORT_TYPE_BY_JOB_HINT = {
    "container_scanning": "CONTAINER_SCANNING",
    "dependency_scanning": "DEPENDENCY_SCANNING",
}

SCANNER_EXTERNAL_ID_BY_HINT = {
    "gemnasium-python": "gemnasium-python",
    "gemnasium-maven": "gemnasium-maven",
    "gemnasium": "gemnasium",
    "trivy": "trivy",
}

RISK_SCORES = {
    "CRITICAL": 10.0,
    "HIGH": 8.9,
    "MEDIUM": 6.9,
    "LOW": 3.9,
    "INFO": 0.0,
    "NONE": 0.0,
}

PACKAGE_TYPE_BY_FILE_NAME = {
    "requirements.txt": "pypi",
    "poetry.lock": "pypi",
    "pipfile.lock": "pypi",
    "pyproject.toml": "pypi",
    "yarn.lock": "npm",
    "package-lock.json": "npm",
    "pnpm-lock.yaml": "npm",
    "package.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "pom.xml": "maven",
    "build.gradle": "maven",
    "build.gradle.kts": "maven",
    "gradle.lockfile": "maven",
    "go.sum": "golang",
    "go.mod": "golang",
    "composer.lock": "composer",
    "composer.json": "composer",
}

UNAUTHORIZED = 401
FORBIDDEN = 403
NOT_FOUND = 404
TOO_MANY_REQUESTS = 429
SERVER_ERROR = 500
CLIENT_ERROR = 600
