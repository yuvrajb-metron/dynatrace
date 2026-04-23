"""Constants: extension defaults, Dynatrace ingest sizing, security event field values."""

# EF2 Python module / extension name (passed to ``Extension``).
EXTENSION_MODULE_NAME = "appsec_dockerscout"

# Default ``securityFindingsFrequencyHours`` when unset or invalid (< 1).
DEFAULT_POLL_HOURS = 24

# Max JSON payload size per security.events ingest POST (bytes).
INGEST_CHUNK_MAX_BYTES = 10_000_000

EVENT_PROVIDER = "Docker Scout"
EVENT_TYPE_VULNERABILITY_FINDING = "VULNERABILITY_FINDING"
EVENT_TYPE_VULNERABILITY_SCAN = "VULNERABILITY_SCAN"
PRODUCT_VENDOR = "Docker"
PRODUCT_NAME = "Docker Scout"
OBJECT_TYPE_CONTAINER_IMAGE = "CONTAINER_IMAGE"
FINDING_TYPE_DEPENDENCY_VULNERABILITY = "DEPENDENCY_VULNERABILITY"
REMEDIATION_STATUS_AVAILABLE = "AVAILABLE"
REMEDIATION_STATUS_NOT_AVAILABLE = "NOT_AVAILABLE"
SCAN_STATUS_COMPLETED = "Completed"
