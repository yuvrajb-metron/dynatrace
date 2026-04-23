"""
Dynatrace EF2 extension implementation.

Implements the Extension base class from dt-extensions-sdk. The extension polls
Renovate CE for job logs, parses vulnerability findings, enriches with OSV,
and ingests security events into Dynatrace.
"""

from datetime import timedelta
import logging
import time

from dynatrace_extension import Extension, Status, StatusValue

from .clients import get_orgs_and_repos_to_poll
from .clients import RestApiHandler
from .core.polling import poll_and_ingest_org_repos
from .environment import DynatraceEnvironmentUtils

EXTENSION_MODULE_NAME = "renovate"
DEFAULT_POLL_HOURS = 24
DEFAULT_FIRST_TIME_FETCH_WINDOW = 7

_dt_env_utils = DynatraceEnvironmentUtils()


class ExtensionImpl(Extension):
    """
    Extension implementation: schedule report_vulnerabilities and use
    self.logger for all logging.
    """

    def initialize(self):
        """
        Called once after extension start and activation config is received.
        Configures connection, Dynatrace ingest, and schedules the main callback.
        """
        self.logger.info("initialize method started for %s.", EXTENSION_MODULE_NAME)

        self.advanced = self.activation_config.get("advancedOptions") or {}
        if self.advanced.get("debugLogs", False):
            self.logger.setLevel(logging.DEBUG)
            self.logger.debug("Debug logs enabled via activation config (advancedOptions.debugLogs).")

        features = self.activation_config.get("features") or {}
        if not features.get("collectRenovateCESecurityEvents", True):
            self.logger.error("Collect Renovate CE Security Events is disabled; skipping.")
            return

        self.connection = self.activation_config.get("connection") or {}
        self.base_url = (self.connection.get("renovateBaseUrl") or "").strip()
        self.api_secret = self.connection.get("renovateApiSecret") or ""

        if not self.base_url or not self.api_secret:
            self.logger.error("Renovate CE base URL or API secret not configured; skipping.")
            return

        self.dynatrace_cfg = self.activation_config.get("dynatrace") or {}
        self.dynatrace_token = (self.dynatrace_cfg.get("token", "").strip())
        custom_ingest_url = (self.dynatrace_cfg.get("dynatraceSecurityIngestUrl") or "").strip()
        self.dev_mode = self.task_id == "development_task_id"
        if self.dynatrace_cfg.get("useCustomSecurityIngestUrl") and custom_ingest_url:
            self.dynatrace_url = custom_ingest_url
        elif self.dev_mode:
            _env_id = self.dynatrace_cfg.get("dt_environment_id", "")
            self.dynatrace_url = (
                f"https://localhost:9999/e/{_env_id}/platform/ingest/v1/security.events"
            )
        else:
            self.dynatrace_url = f"{_dt_env_utils.get_api_url()}/platform/ingest/v1/security.events"
        self.security_events_interface = None
        if self.dynatrace_url and self.dynatrace_token:
            self.security_events_interface = RestApiHandler(
                auth_header=f"Api-Token {self.dynatrace_token}",
            )
        self.vulns_frequency = int(self.advanced.get("securityFindingsFrequencyHours") or DEFAULT_POLL_HOURS)
        if self.vulns_frequency < 1:
            self.vulns_frequency = DEFAULT_POLL_HOURS
        self.firstTimeFetchWindow = int(self.advanced.get("firstTimeFetchWindow", DEFAULT_FIRST_TIME_FETCH_WINDOW))
        self.schedule(
            self.report_vulnerabilities,
            interval=timedelta(hours=self.vulns_frequency),
        )
        self.logger.info(f"initialize method ended for {EXTENSION_MODULE_NAME} with poll frequency {self.vulns_frequency} hours and first time fetch window {self.firstTimeFetchWindow} days")

    def report_vulnerabilities(self):
        """Scheduled callback: poll repos, parse job logs, build events, push to Dynatrace."""
        org_to_repo_list = get_orgs_and_repos_to_poll(
            self.activation_config,
            self.base_url,
            self.api_secret,
        )
        self.logger.info(f"Found orgs/repos: {org_to_repo_list}")
        for org, repos in org_to_repo_list.items():
            poll_and_ingest_org_repos(
                org,
                repos,
                base_url=self.base_url,
                api_secret=self.api_secret,
                dynatrace_url=self.dynatrace_url,
                security_events_interface=self.security_events_interface,
                firstTimeFetchWindow=self.firstTimeFetchWindow,
            )
        if not org_to_repo_list:
            self.logger.info("No orgs/repos to poll; skipping job fetch.")

        if not self.dynatrace_url or not self.dynatrace_token:
            self.logger.debug(
                "Dynatrace URL or token not configured; skipping event push."
            )

    def fastcheck(self) -> Status:
        """
        Called when extension is run in fastcheck mode (remote/ActiveGate only).

        Return StatusValue.OK if the extension can run on this agent, or
        StatusValue.ERROR / raise an Exception otherwise. Not invoked for OneAgent.
        """
        return Status(StatusValue.OK)

    def on_shutdown(self):
        """
        Called when the extension receives a shutdown signal from the EEC.
        Use for cleanup; metrics are flushed after this runs.
        """
        self.logger.info("Shutdown signal received for %s.", EXTENSION_MODULE_NAME)


def main():
    """Entrypoint: run the extension (dt-sdk run or EEC)."""
    ExtensionImpl(name=EXTENSION_MODULE_NAME).run()


if __name__ == "__main__":
    main()