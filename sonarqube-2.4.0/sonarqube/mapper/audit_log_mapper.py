from datetime import datetime, timezone

from sonarqube.clients.audit_client import AuditLog, AuditLogCloud


def audit_log_mapper(audit_log: AuditLog, monitoring_config_id: str, monitoring_config_name: str) -> dict:
    return {
        "level": "INFO",
        "log.source": "SonarQube",
        "content": audit_log.model_dump_json(exclude_none=True),
        "audit.identity": audit_log.user_login,
        "audit.action": audit_log.operation,
        "audit.time": audit_log.created_at,
        "dt.extension.name": "com.dynatrace.extension.sonarqube",
        "dt.extension.config.id": monitoring_config_id,
        "extension.config.name": monitoring_config_name,
    }


def audit_log_mapper_cloud(
    audit_log: AuditLogCloud, monitoring_config_id: str, monitoring_config_name: str
) -> dict:
    audit_log_time = (
        datetime.fromtimestamp(audit_log.timestamp / 1e3, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    )
    return {
        "level": "INFO",
        "log.source": "SonarQube",
        "content": audit_log.model_dump_json(exclude_none=True),
        "audit.identity": audit_log.principal_id,
        "audit.action": audit_log.event_type,
        "audit.time": audit_log_time,
        "dt.extension.name": "com.dynatrace.extension.sonarqube",
        "dt.extension.config.id": monitoring_config_id,
        "extension.config.name": monitoring_config_name,
    }
