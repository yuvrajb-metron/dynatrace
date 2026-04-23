from datetime import datetime, timedelta

from dynatrace_extension import Extension, StatusValue
from dynatrace_extension.sdk.status import MultiStatus

from sonarqube.clients.audit_client import AuditLogClient, NotFoundError
from sonarqube.config.sonarqube_config import SonarQubeConfig
from sonarqube.mapper.audit_log_mapper import audit_log_mapper, audit_log_mapper_cloud


class SonarQubeAuditLogsService:
    def __init__(
        self,
        extension: Extension,
        sonarqube_url: str,
        sonarqube_token: str,
        sonarqube_verify: str | bool,
        sonarqube_cloud: bool,
        sonarqube_org: str,
        sonarqube_proxy: str | None,
        first_ingest_window_hours=1.0,
        sync_interval=1.0,
    ):
        self.logger = extension.logger
        self.extension = extension
        self.sonar_config = SonarQubeConfig(
            sonarqube_url,
            sonarqube_token,
            sonarqube_verify,
            sonarqube_cloud,
            sonarqube_org,
            sonarqube_proxy,
        )
        self.audit_client = AuditLogClient(self.sonar_config, self.logger)

        self.sync_from = datetime.now() - timedelta(hours=first_ingest_window_hours)
        self.sync_interval = sync_interval
        self.first_sync = True

    def ingest(self) -> MultiStatus:
        self.multi_status = MultiStatus()

        if not self.first_sync:
            self.sync_from = datetime.now() - timedelta(hours=self.sync_interval)

        try:
            self.ingest_audit_logs()

        except NotFoundError:
            self.logger.warning(
                "Unable to find audit logs endpoint for this tenant. "
                "Disabling audit logs ingest for the rest of the execution."
            )
            self.multi_status.add_status(
                StatusValue.WARNING,
                "Unable to find audit logs endpoint for this tenant. "
                "Disabling audit logs ingest for the rest of the execution.",
            )
            self.extension.ingest_audit_logs = False
        except Exception as e:
            self.logger.warning(
                f"Unable to fetch audit logs for tenant {self.sonar_config.url}\nException {e}"
            )
            self.multi_status.add_status(
                StatusValue.WARNING,
                f"Unable to fetch audit logs for tenant {self.sonar_config.url}\n"
                f"Exception {type(e).__name__}",
            )
            raise

        return self.multi_status

    def ingest_audit_logs(self) -> MultiStatus:
        from_timestamp = self.sync_from.astimezone().isoformat()
        to_timestamp = datetime.now().astimezone().isoformat()
        audit_logs = self.audit_client.get_audit_logs(
            from_timestamp, to_timestamp, self.extension.sonarqube_cloud
        )

        if self.extension.sonarqube_cloud:
            logs_to_ingest = [
                audit_log_mapper_cloud(
                    log, self.extension.monitoring_config_id, self.extension.monitoring_config_name
                )
                for log in audit_logs
                if log.timestamp >= self.sync_from.timestamp() * 1e3
            ]
        else:
            logs_to_ingest = [
                audit_log_mapper(
                    log, self.extension.monitoring_config_id, self.extension.monitoring_config_name
                )
                for log in audit_logs
            ]
        self.extension.report_log_event(logs_to_ingest)

        self.logger.info(
            f"Attempted ingest of {len(logs_to_ingest)} audit events for tenant {self.sonar_config.url}."
        )
        self.multi_status.add_status(
            StatusValue.OK,
            f"Generated {len(logs_to_ingest)} audit events for tenant {self.sonar_config.url}.",
        )
