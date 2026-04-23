"""
Dynatrace Extensions 2.0 entry point for the GitLab Advanced Security integration.

Responsibilities:
    - Read activation configuration (GitLab URL/token, feature toggles, Dynatrace token).
    - Schedule periodic collection of vulnerability scan/finding data and optional audit logs.
    - Send security events to Dynatrace via the security events ingest HTTP API.
    - Send audit records via the extension SDK (``report_log_event``).

Security findings use ``POST`` to ``platform/ingest/v1/security.events``. Audit logs
use only ``Extension.report_log_event`` (no separate log ingest URL).
"""

from datetime import datetime, timedelta, timezone
import logging

from dynatrace_extension import Extension, Status, StatusValue
from dynatrace_extension.sdk.extension import extension_logger
from dynatrace_extension.sdk.status import MultiStatus

from .clients.http_client import RestApiHandler
from .core.gitlab_processor import GitLabProcessor
from .core.polling import collect_audit_log_events, poll_groups_and_ingest_security_events
from .utils import constants as c
from .utils.environment import DynatraceEnvironmentUtils
from .utils.helpers import _get_positive_int, build_enabled_report_types
from .utils.urlutil import join_urls

_dt_env_utils = DynatraceEnvironmentUtils()


class ExtensionImpl(Extension):
    """
    GitLab → Dynatrace extension implementation.

    Responsibility:
        Wire Dynatrace scheduler callbacks to GitLab polling and ingest. Holds
        connection settings and feature flags on ``self`` after ``initialize()``.
    """

    def initialize(self) -> None:
        """
        Load activation config, validate required settings, and register scheduled tasks.

        Reads:
            ``activation_config`` keys under ``advanced_options``, ``features``,
            ``gitlab``, and ``dynatrace`` (see ``utils.constants``).

        Side effects:
            Sets instance attributes (URLs, tokens, poll intervals) and calls
            ``self.schedule`` for enabled features. Returns early without scheduling
            if configuration is invalid or all features are disabled.
        """
        self.logger.info(f"Initialization started for {c.EXTENSION_MODULE_NAME}.")
        self.advanced_options = self.activation_config.get(c.ADVANCED_OPTIONS) or {}
        debug_on = bool(self.advanced_options.get(c.DEBUG_LOGS, False))
        log_level = logging.DEBUG if debug_on else logging.INFO
        extension_logger.setLevel(log_level)
        self.logger.setLevel(log_level)
        if debug_on:
            self.logger.debug(f"Debug logging enabled via activation config (extension + SDK logger).")
        features = self.activation_config.get(c.FEATURES) or {}
        self.collect_dependency_scanning_alerts = features.get(c.COLLECT_DEPENDENCY_SCANNING_ALERTS, False)
        self.collect_container_scanning_alerts = features.get(c.COLLECT_CONTAINER_SCANNING_ALERTS, False)

        self.gitlab_config = self.activation_config.get(c.GITLAB) or {}
        self.collect_audit_events = features.get(c.COLLECT_AUDIT_EVENTS, False)
        if not any([self.collect_dependency_scanning_alerts, self.collect_container_scanning_alerts, self.collect_audit_events]):
            self.logger.error(f"No GitLab events will be collected because all collection toggles are disabled.")
            return

        self.gitlab_url = self.gitlab_config.get(c.GITLAB_URL)
        self.gitlab_token = self.gitlab_config.get(c.GITLAB_TOKEN)
        if not self.gitlab_url or not self.gitlab_token:
            self.logger.error(f"GitLab URL and token must be configured in gitlab.url and gitlab.token.")
            return

        self.gitlab_interface = RestApiHandler(private_token=self.gitlab_token)
        self.all_groups = bool(self.gitlab_config.get(c.ALL_GROUPS, True))
        self.groups = self.gitlab_config.get(c.GROUPS) or []
        self.all_projects = bool(self.gitlab_config.get(c.ALL_PROJECTS, True))
        self.projects = self.gitlab_config.get(c.PROJECTS) or []

        self.dynatrace_config = self.activation_config.get(c.DYNATRACE) or {}
        self.dynatrace_token = (self.dynatrace_config.get(c.DYNATRACE_TOKEN) or "").strip()
        custom_ingest_url = (self.dynatrace_config.get(c.DYNATRACE_SECURITY_INGEST_URL) or "").strip()
        ingest_path_parts = tuple(p for p in c.DYNATRACE_SECURITY_INGEST_URL_PATH.split("/") if p)
        if self.dynatrace_config.get(c.USE_CUSTOM_SECURITY_INGEST_URL) and custom_ingest_url:
            self.dynatrace_url = custom_ingest_url
        elif self.task_id == c.DEVELOPMENT_TASK_ID:
            environment_id = self.dynatrace_config.get(c.DT_ENVIRONMENT_ID, "")
            self.dynatrace_url = join_urls(c.DYNATRACE_LOCALHOST_URL, environment_id, *ingest_path_parts)
        else:
            self.dynatrace_url = join_urls(_dt_env_utils.get_api_url(), *ingest_path_parts)
        self.logger.info(f"Using Dynatrace ingest URL: {self.dynatrace_url}")
        self.security_events_interface = RestApiHandler(auth_header=f"Api-Token {self.dynatrace_token}") if self.dynatrace_url and self.dynatrace_token else None

        self.findings_frequency_hours = _get_positive_int(
            self.advanced_options,
            c.SECURITY_FINDINGS_FREQUENCY_HOURS,
            c.DEFAULT_POLL_HOURS,
        )
        self.first_time_fetch_window_days = _get_positive_int(
            self.advanced_options,
            c.FIRST_TIME_FETCH_WINDOW_DAYS,
            c.DEFAULT_FIRST_TIME_FETCH_WINDOW_DAYS,
        )
        self.audit_event_frequency_minutes = _get_positive_int(
            self.advanced_options,
            c.AUDIT_EVENT_FREQUENCY_MINUTES,
            c.DEFAULT_AUDIT_EVENT_FREQUENCY_MINUTES,
        )
        self.dynatrace_chunk_max_bytes = c.DEFAULT_DYNATRACE_CHUNK_MAX_BYTES
        # Audit log fetch lower bound for incremental polls (Harbor-style); reset on process restart.
        self.last_log_time: datetime | None = None

        if self.collect_dependency_scanning_alerts or self.collect_container_scanning_alerts:
            self.schedule(self.report_vulnerabilities, interval=timedelta(hours=max(1, self.findings_frequency_hours)))
        if self.collect_audit_events:
            self.schedule(self.report_audit_logs, interval=timedelta(minutes=max(1, self.audit_event_frequency_minutes)))
        self.logger.info(f"Initialization completed for {c.EXTENSION_MODULE_NAME}.")

    def report_vulnerabilities(self) -> MultiStatus:
        """
        Scheduled callback: collect new security jobs, build scan/finding events, POST to Dynatrace.

        Responsibility:
            Orchestrate ``poll_groups_and_ingest_security_events``. New jobs are tracked
            in SQLite via ``JobDatabase`` inside the polling layer so jobs are not
            re-ingested.

        Returns:
            ``MultiStatus`` with one or more entries (per GitLab group, plus errors
            for missing Dynatrace client or unexpected failures).
        """
        multi_status = MultiStatus()
        self.logger.info(f"Starting vulnerability reporting for {c.EXTENSION_MODULE_NAME}.")
        if not self.security_events_interface:
            multi_status.add_status(
                StatusValue.GENERIC_ERROR,
                "Dynatrace token or security ingest URL missing; cannot push scan/finding events.",
            )
            return multi_status
        try:
            poll_groups_and_ingest_security_events(
                base_url=self.gitlab_url,
                gitlab_interface=self.gitlab_interface,
                all_groups=self.all_groups,
                group_ids=self.groups,
                all_projects=self.all_projects,
                selected_projects=self.projects,
                enabled_report_types=set(
                    build_enabled_report_types(
                        self.collect_dependency_scanning_alerts,
                        self.collect_container_scanning_alerts,
                    )
                ),
                dynatrace_url=self.dynatrace_url,
                security_events_interface=self.security_events_interface,
                first_time_fetch_window_days=self.first_time_fetch_window_days,
                dynatrace_chunk_max_bytes=self.dynatrace_chunk_max_bytes,
                multi_status=multi_status,
            )
        except Exception as error:
            self.logger.exception(f"Vulnerability reporting failed: {error}")
            multi_status.add_status(
                StatusValue.GENERIC_ERROR,
                f"GitLab scan/finding reporting failed: {error}",
            )
        return multi_status

    def report_audit_logs(self) -> MultiStatus:
        """
        Scheduled callback: fetch GitLab audit events and report each as a log event.

        Responsibility:
            Build log-shaped payloads (``events/audit_log.py``) and call
            ``self.report_log_event`` for each. Does not use the security ingest URL.
            Uses ``last_log_time`` each run requests events after the
            previous run's end time; the first run uses ``first_time_fetch_window_days``.

        Returns:
            ``MultiStatus`` describing success, empty window, or failure.
        """
        multi_status = MultiStatus()
        self.logger.info(f"Starting audit log reporting for {c.EXTENSION_MODULE_NAME}.")
        try:
            now_utc = datetime.now(timezone.utc)
            if self.last_log_time is not None:
                created_after = self.last_log_time.isoformat()
            else:
                created_after = (
                    now_utc - timedelta(days=self.first_time_fetch_window_days)
                ).isoformat()
            self.last_log_time = now_utc
            self.logger.info(
                f"GitLab audit collection window: created_after={created_after}, until={now_utc.isoformat()}."
            )

            gitlab_processor = GitLabProcessor(self.gitlab_url, self.gitlab_interface)
            target_groups = gitlab_processor.fetch_target_groups(self.all_groups, self.groups)
            audit_log_events = collect_audit_log_events(
                base_url=self.gitlab_url,
                gitlab_interface=self.gitlab_interface,
                target_groups=target_groups,
                all_projects=self.all_projects,
                selected_projects=self.projects,
                created_after=created_after,
            )
            if audit_log_events:
                for log_entry in audit_log_events:
                    # send_immediately=True avoids EEC batching delays/drops for low-volume audit lines
                    self.report_log_event(log_entry, send_immediately=True)
                self.logger.info(
                    f"Reported {len(audit_log_events)} audit log event(s) via Extension.report_log_event."
                )
                multi_status.add_status(
                    StatusValue.OK,
                    f"Ingested {len(audit_log_events)} GitLab audit log event(s) via SDK.",
                )
            else:
                multi_status.add_status(
                    StatusValue.OK,
                    "No GitLab audit log events in the current collection window.",
                )
        except Exception as error:
            self.logger.exception(f"Audit log collection or report_log_event failed: {error}")
            multi_status.add_status(
                StatusValue.GENERIC_ERROR,
                f"GitLab audit log ingest failed: {error}",
            )
        return multi_status

    def fastcheck(self) -> Status:
        """
        Lightweight health check invoked by the extension runtime.

        Returns:
            ``Status(StatusValue.OK)`` (GitLab connectivity is not probed here).
        """
        return Status(StatusValue.OK)

    def on_shutdown(self) -> None:
        """Log shutdown; persist any state via context managers in polling/ingest as needed."""
        self.logger.info(f"Shutdown signal received for {c.EXTENSION_MODULE_NAME}.")


def main() -> None:
    """
    Start the extension process.

    Returns:
        None (blocks inside ``Extension.run()`` until shutdown).
    """
    ExtensionImpl(name=c.EXTENSION_MODULE_NAME).run()


if __name__ == "__main__":
    main()
