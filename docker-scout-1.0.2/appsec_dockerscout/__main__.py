"""
Dynatrace EF2 extension implementation.

Discovers container images via Docker Hub, runs Docker Scout CVES/SBOM per image,
and ingests vulnerability findings and scan events into Dynatrace security.events.
"""

import logging
from datetime import timedelta
from typing import List

from dynatrace_extension import Extension, Status, StatusValue
from dynatrace_extension.sdk.status import MultiStatus

from appsec_dockerscout.clients import RestApiHandler
from appsec_dockerscout.core import run_discovery_and_ingest
from appsec_dockerscout.environment import DynatraceEnvironmentUtils
from appsec_dockerscout.utils.constants import DEFAULT_POLL_HOURS, EXTENSION_MODULE_NAME

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
        self.logger.info(f"initialize method started for {EXTENSION_MODULE_NAME}.")

        self.advanced = self.activation_config.get("advancedOptions") or {}
        if self.advanced.get("debugLogs", False):
            self.logger.setLevel(logging.DEBUG)
            self.logger.debug(
                "Debug logs enabled via activation config (advancedOptions.debugLogs)."
            )

        features = self.activation_config.get("features") or {}
        if not features.get("collectDockerScoutSecurityEvents", True):
            self.logger.error(
                "Collect Docker Scout security events is disabled; skipping."
            )
            return

        self.connection = self.activation_config.get("connection") or {}
        self.username = (self.connection.get("dockerHubUsername") or "").strip()
        self.password = self.connection.get("dockerHubApiSecret") or ""

        if not self.username or not self.password:
            self.logger.error(
                "Docker Hub username or API secret not configured; skipping."
            )
            return

        self.dynatrace_cfg = self.activation_config.get("dynatrace") or {}
        self.dynatrace_token = (self.dynatrace_cfg.get("token") or "").strip()
        custom_ingest_url = (
            self.dynatrace_cfg.get("dynatraceSecurityIngestUrl") or ""
        ).strip()
        self.dev_mode = getattr(self, "task_id", None) == "development_task_id"
        if self.dynatrace_cfg.get("useCustomSecurityIngestUrl") and custom_ingest_url:
            self.dynatrace_url = custom_ingest_url
        elif self.dev_mode:
            _env_id = self.dynatrace_cfg.get("dt_environment_id", "")
            self.dynatrace_url = (
                f"https://localhost:9999/e/{_env_id}/platform/ingest/v1/security.events"
            )
        else:
            try:
                self.dynatrace_url = (
                    f"{_dt_env_utils.get_api_url()}/platform/ingest/v1/security.events"
                )
            except Exception as e:
                self.logger.warning(
                    f"Could not get default Dynatrace API URL from environment: {e}"
                )
                self.dynatrace_url = None
        self.security_events_interface = None
        if self.dynatrace_url and self.dynatrace_token:
            self.security_events_interface = RestApiHandler(
                auth_header=f"Api-Token {self.dynatrace_token}",
            )
        # Same value drives schedule cadence and Hub discovery lookback (see run_discovery_and_ingest).
        self.security_findings_interval_hours = int(
            self.advanced.get("securityFindingsFrequencyHours") or DEFAULT_POLL_HOURS
        )
        if self.security_findings_interval_hours < 1:
            self.security_findings_interval_hours = DEFAULT_POLL_HOURS
        self.schedule(
            self.report_vulnerabilities,
            interval=timedelta(hours=self.security_findings_interval_hours),
        )
        self.logger.info(
            f"initialize method ended for {EXTENSION_MODULE_NAME} with poll frequency "
            f"{self.security_findings_interval_hours} hours"
        )

    def report_vulnerabilities(self) -> MultiStatus:
        """
        Periodic job registered in ``initialize``: Docker Hub image discovery and Scout ingest.

        Reads ``connection.repositories`` (orgs, repo allow list) from activation config, then
        calls ``run_discovery_and_ingest`` (see ``appsec_dockerscout.core``) to log into Hub,
        list active repositories and tags, run ``docker scout`` per image, map SARIF/SBOM
        to security events, and POST them to Dynatrace ``security.events``.

        If the Dynatrace ingest URL or API token is missing, returns immediately with an
        error status (no Hub/Scout work). Otherwise ``MultiStatus`` is filled inside the
        core layer (e.g. Hub errors, docker login, per-image scan failures, completion).

        Returns:
            ``MultiStatus`` aggregated for the extension UI and operator visibility.
        """
        multi_status = MultiStatus()
        repos_cfg = self.connection.get("repositories") or {}
        all_orgs = repos_cfg.get("allOrgsAndRepos", True)
        org_list = repos_cfg.get("orgList") or []
        all_repos_in_orgs = repos_cfg.get("allReposInSelectedOrgs", True)
        repo_list: List[str] = repos_cfg.get("repoList") or []
        org_filter = (
            None if all_orgs else (org_list if isinstance(org_list, list) else [])
        )
        if not self.security_events_interface:
            skip_msg = (
                "Dynatrace URL or token not configured; skipping event push."
            )
            self.logger.debug(skip_msg)
            multi_status.add_status(StatusValue.GENERIC_ERROR, skip_msg)
            return multi_status
        try:
            run_discovery_and_ingest(
                username=self.username,
                password=self.password,
                dynatrace_url=getattr(self, "dynatrace_url", None),
                security_events_interface=getattr(
                    self, "security_events_interface", None
                ),
                org_filter=org_filter,
                all_repos_in_orgs=all_repos_in_orgs,
                repo_list=repo_list if isinstance(repo_list, list) else [],
                multi_status=multi_status,
                hub_activity_lookback_hours=self.security_findings_interval_hours,
            )
        except Exception as e:
            self.logger.exception(f"Discovery/ingest failed: {e}")
            multi_status.add_status(
                StatusValue.GENERIC_ERROR,
                f"Docker Scout discovery/ingest failed: {e}",
            )
        return multi_status

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
        self.logger.info(f"Shutdown signal received for {EXTENSION_MODULE_NAME}.")


def main():
    """Entrypoint: run the extension (dt-sdk run or EEC)."""
    ExtensionImpl(name=EXTENSION_MODULE_NAME).run()


if __name__ == "__main__":
    main()
