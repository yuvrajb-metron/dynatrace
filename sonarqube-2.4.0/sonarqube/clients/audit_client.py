import requests

from sonarqube.clients.base_schema import BaseSchema
from sonarqube.config.sonarqube_config import SonarQubeConfig


class AuditLogCloud(BaseSchema):
    timestamp: int
    event_type: str
    principal_id: str | None = None
    principal_type: str | None = None
    outcome: str | None = None
    description: str | None = None
    event_information: dict | None = None
    enterprise_id: str | None = None
    enterprise_name: str | None = None


class AuditLog(BaseSchema):
    user_login: str
    new_value: dict | None = None
    created_at: str | None = None
    user_uuid: str | None = None
    user_triggered: bool | None = None
    category: str | None = None
    operation: str | None = None
    previous_value: dict | None = None


class NotFoundError(Exception):
    pass


class AuditLogClient:
    def __init__(self, config: SonarQubeConfig, logger):
        self.config = config
        self.logger = logger

    def get_audit_logs(self, from_timestamp: str, to_timestamp: str, cloud: bool) -> AuditLog | AuditLogCloud:
        request_from_timestamp = from_timestamp.split("T")[0]
        request_to_timestamp = to_timestamp.split("T")[0]
        response = requests.get(
            self.config.get_audit_log_endpoint(request_from_timestamp, request_to_timestamp),
            headers=self.config.get_headers(),
            verify=self.config.verify,
            proxies=self.config.get_proxies(),
        )

        if response.status_code == 404:
            raise NotFoundError
        response.raise_for_status()
        self.logger.debug("Successfully got audit logs.")
        if cloud:
            return [AuditLogCloud(**log) for log in response.json().get("auditLogs")]
        return [AuditLog(**log) for log in response.json().get("audit_logs")]
