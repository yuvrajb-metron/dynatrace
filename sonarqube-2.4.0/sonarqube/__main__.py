from datetime import timedelta
from urllib.parse import quote_plus

from dynatrace_extension import Extension, Status, StatusValue
from dynatrace_extension.sdk.status import MultiStatus

from sonarqube.services.sonarqube_audit_logs_service import SonarQubeAuditLogsService
from sonarqube.services.sonarqube_service import SonarQubeService
from sonarqube.utils.environment import DynatraceEnvironmentUtils


class ExtensionImpl(Extension):
    def initialize(self):
        self.dev_mode = self.task_id == "development_task_id"

        if self.activation_config["advancedOptions"]["debugLogs"]:
            self.logger.setLevel("DEBUG")
        else:
            self.logger.setLevel("INFO")

        # Sonarqube tenant details
        self.sonarqube_url: str = self.activation_config["sonarqube"].get("sonarQubeUrl")
        self.sonarqube_token: str = self.activation_config["sonarqube"].get("sonarQubeApiToken")
        self.sonarqube_cloud: bool = self.activation_config["sonarqube"].get("sonarqubeCloud")
        self.sonarqube_org: str = self.activation_config["sonarqube"].get("sonarqubeOrganization")

        self.sonarqube_verify = self.activation_config["sonarqube"].get("verify_certificate", True)
        ca_location = self.activation_config["sonarqube"].get("ca_location") or None
        if self.sonarqube_verify and ca_location:
            self.logger.info(f"Using custom CA location: {ca_location}")
            self.sonarqube_verify = ca_location

        self.sonarqube_proxy = None
        if self.activation_config["advancedOptions"].get("sonarqubeProxy") is not None:
            proxy_address = self.activation_config["advancedOptions"].get("sonarqubeProxy").get("address")
            proxy_username = self.activation_config["advancedOptions"].get("sonarqubeProxy").get("username")
            proxy_password = self.activation_config["advancedOptions"].get("sonarqubeProxy").get("password")

            if proxy_address:
                if proxy_username and proxy_password:
                    user = quote_plus(proxy_username)
                    password = quote_plus(proxy_password)
                    protocol, address = proxy_address.split("://")
                    self.sonarqube_proxy = f"{protocol}://{user}:{password}@{address}"
                else:
                    self.sonarqube_proxy = proxy_address

        # Dynatrace tenant details
        dt_env_utils = DynatraceEnvironmentUtils(log=self.logger)
        tenant_api_url = (
            dt_env_utils.get_api_url() if not self.dev_mode else self.activation_config.get("envApiUrl")
        )

        if not self.activation_config["dynatrace"].get("use_custom_security_ingest_url"):
            self.dynatrace_security_events_endpoint = f"{tenant_api_url}/platform/ingest/v1/security.events"
        else:
            self.dynatrace_security_events_endpoint = self.activation_config["dynatrace"].get(
                "dynatrace_security_ingest_url"
            )
        if not self.activation_config["dynatrace"].get("use_custom_sdlc_ingest_url"):
            self.dynatrace_sdlc_events_endpoint = f"{tenant_api_url}/platform/ingest/v1/events.sdlc"
        else:
            self.dynatrace_sdlc_events_endpoint = self.activation_config["dynatrace"].get(
                "dynatrace_sdlc_ingest_url"
            )

        self.dynatrace_ingest_token: str = self.activation_config["dynatrace"].get("token")

        # Products
        self.ingest_security_events: bool = self.activation_config["products"].get("fetchEvents")
        self.ingest_sdlc: bool = self.activation_config["products"].get("fetchSDLC")
        self.ingest_metrics: bool = self.activation_config["products"].get("fetchMetrics")
        self.ingest_audit_logs: bool = self.activation_config["products"].get("fetchAuditLogs")

        # Advanced options
        self.issue_severities = (
            "INFO,LOW,MEDIUM,HIGH,BLOCKER"
            if self.activation_config["advancedOptions"].get("fetchInfoVulnerabilities")
            else "LOW,MEDIUM,HIGH,BLOCKER"
        )
        self.events_fetch_frequency: float = self.activation_config["advancedOptions"].get(
            "eventFetchFrequency"
        )
        self.metrics_fetch_frequency: float = self.activation_config["advancedOptions"].get(
            "metricFetchFrequency"
        )
        self.audit_logs_fetch_frequency: float = self.activation_config["advancedOptions"].get(
            "auditFetchFrequency"
        )
        self.first_ingest_window_hours: float = self.activation_config["advancedOptions"].get(
            "firstTimeFetchWindow"
        )

        # Enrichment attributes
        self.enrichment_attributes = self.activation_config._activation_context_json.get("dtAttributes", {})

        if self.ingest_security_events or self.ingest_sdlc or self.ingest_metrics:
            if timedelta(hours=self.events_fetch_frequency) == timedelta(
                minutes=self.metrics_fetch_frequency
            ):
                self.schedule(
                    self.events_and_metrics_ingest,
                    interval=timedelta(hours=self.events_fetch_frequency),
                    args=(self.ingest_security_events or self.ingest_sdlc, self.ingest_metrics),
                )
            else:
                if self.ingest_security_events or self.ingest_sdlc:
                    self.schedule(
                        self.events_and_metrics_ingest,
                        interval=timedelta(hours=self.events_fetch_frequency),
                        args=(True, False),
                    )
                if self.ingest_metrics:
                    self.schedule(
                        self.events_and_metrics_ingest,
                        interval=timedelta(minutes=self.metrics_fetch_frequency),
                        args=(False, True),
                    )

        if self.ingest_audit_logs:
            self.schedule(self.audit_logs_ingest, interval=timedelta(minutes=self.audit_logs_fetch_frequency))

    def events_and_metrics_ingest(self, ingest_events: bool, ingest_metrics: bool) -> MultiStatus:
        sonar_qube_service = SonarQubeService(
            self,
            self.sonarqube_url,
            self.sonarqube_token,
            self.sonarqube_verify,
            self.sonarqube_cloud,
            self.sonarqube_org,
            self.sonarqube_proxy,
            self.dynatrace_security_events_endpoint,
            self.dynatrace_sdlc_events_endpoint,
            ingest_events,
            ingest_metrics,
            self.dynatrace_ingest_token,
            self.first_ingest_window_hours,
            self.events_fetch_frequency,
        )

        return sonar_qube_service.sync()

    def audit_logs_ingest(self) -> None | MultiStatus:
        if self.ingest_audit_logs:
            audit_logs_service = SonarQubeAuditLogsService(
                self,
                self.sonarqube_url,
                self.sonarqube_token,
                self.sonarqube_verify,
                self.sonarqube_cloud,
                self.sonarqube_org,
                self.sonarqube_proxy,
                self.first_ingest_window_hours,
                self.audit_logs_fetch_frequency,
            )

            return audit_logs_service.ingest()

        return None

    def fastcheck(self) -> Status:
        """
        Use to check if the extension can run.
        If this Activegate cannot run this extension, you can
        raise an Exception or return StatusValue.ERROR.
        This does not run for OneAgent extensions.
        """
        return Status(StatusValue.OK)


def main():
    ExtensionImpl(name="sonarqube").run()


if __name__ == "__main__":
    main()
