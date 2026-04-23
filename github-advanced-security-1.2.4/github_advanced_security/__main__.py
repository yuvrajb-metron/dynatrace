from dynatrace_extension import Extension, Status, StatusValue
from dynatrace_extension.sdk.status import MultiStatus

from typing import List, Dict, Optional
from datetime import datetime, timezone, timedelta
from itertools import chain
import re
import json

import requests
from requests.exceptions import RequestException

from .shared import split_by_size
from .github import Github
from .environment import DynatraceEnvironmentUtils

dt_env_utils = DynatraceEnvironmentUtils()


class ExtensionImpl(Extension):
    def initialize(self):
        self.dev_mode = True if self.task_id == "development_task_id" else False
        self.extension_name: str = self.activation_config.get("log_level", "INFO")
        self.logger.setLevel(
            "DEBUG"
            if self.activation_config.get("advanced_options", {}).get(
                "debug_logs", False
            )
            else "INFO"
        )

        github: Dict = self.activation_config["github"]
        self.authentication_method: str = github.get("authentication_method")
        self.github_url: str = github.get("url")
        if self.authentication_method == "APP":
            self.client_id: str = github.get("client_id")
            self.account: str = github.get("account")
            key_config = github["private_key"]
            if key_config["method"] == "PATH":
                self.logger.info(f"Using key path for private key.")
                private_key_path: str = key_config.get("path")
                f = open(private_key_path, "r")
                self.private_key: str = f.read()
            else:
                self.logger.info(f"Using key contents for private key.")
                self.private_key = self.create_valid_key_from_text(
                    key_config["contents"]
                )
        else:
            self.token = github["token"]

        self.all_organization_logs: bool = github.get("all_organization_logs", True)
        if not self.all_organization_logs:
            self.organization_logs: List[str] = github.get("organizations")

        self.all_repositories: bool = github.get("all_repositories", True)
        if not self.all_repositories:
            self.repositories: List[str] = github.get("repositories", [])

        self.github = Github(
            self.github_url,
            token=self.token if self.authentication_method == "PAT" else None,
            client_id=self.client_id if self.authentication_method == "APP" else None,
            account=self.account if self.authentication_method == "APP" else None,
            private_key=(
                self.private_key if self.authentication_method == "APP" else None
            ),
            proxies={
                "https": self.build_proxy_url(
                    self.activation_config.get("github", {}).get("proxy", {})
                )
            },
            verify=not self.activation_config.get("advanced_options", {}).get(
                "disable_cert_validation", False
            ),
            repository_filters=None if self.all_repositories else self.repositories,
            organization_logs=(
                None if self.all_organization_logs else self.organization_logs
            ),
            log=self.logger,
        )

        self.dt_token = self.activation_config["dynatrace"]["token"]
        if self.dev_mode:
            self.security_events_ingest_url = (
                f"https://localhost:9999/e/{self.activation_config.get('dt_environment_id')}/platform/ingest/v1/security.events"
                if not self.activation_config["dynatrace"].get(
                    "dynatrace_security_ingest_url"
                )
                else self.activation_config["dynatrace"].get(
                    "dynatrace_security_ingest_url"
                )
            )
        else:
            self.security_events_ingest_url = (
                self.activation_config["dynatrace"].get("dynatrace_security_ingest_url")
                if self.activation_config["dynatrace"].get(
                    "dynatrace_security_ingest_url"
                )
                else f"{dt_env_utils.get_api_url()}/platform/ingest/v1/security.events"
            )

        if self.authentication_method == "APP":
            self.github.update_app_installations()
            self.schedule(self.github.update_app_installations, timedelta(minutes=9))

        if self.activation_config["features"].get("collect_dependabot_alerts", False):
            self.schedule(
                self.report_dependabot_alerts,
                timedelta(
                    hours=self.activation_config.get("advanced_options", {}).get(
                        "security_findings_frequency_hours", 1
                    )
                ),
            )

        if self.activation_config["features"].get("collect_secret_alerts", False):
            severity_level = self.activation_config.get("advanced_options", {}).get(
                "exposed_secret_severity_level"
            )
            self.schedule(
                self.report_secret_alerts,
                timedelta(
                    hours=self.activation_config.get("advanced_options", {}).get(
                        "security_findings_frequency_hours", 1
                    )
                ),
                (severity_level or "HIGH",),
            )

        if self.activation_config["features"].get(
            "collect_code_scanning_alerts", False
        ):
            self.schedule(
                self.report_code_scanning_alerts,
                timedelta(
                    hours=self.activation_config.get("advanced_options", {}).get(
                        "security_findings_frequency_hours", 1
                    )
                ),
            )

        if self.activation_config["github"].get("collect_audit_logs", False):
            self.last_log_time: Optional[datetime] = None
            self.schedule(
                self.report_audit_logs,
                timedelta(
                    minutes=self.activation_config.get("advanced_options", {}).get(
                        "audit_log_frequency_minutes", 5
                    )
                ),
            )

    def report_audit_logs(self):

        to_time = (datetime.now(tz=timezone.utc) - timedelta(minutes=1)).replace(
            second=0, microsecond=0
        )
        if self.last_log_time:
            from_time = self.last_log_time.replace(second=0, microsecond=0)
        else:
            from_time = to_time - timedelta(minutes=1)
        self.last_log_time = to_time

        multi_status: MultiStatus = MultiStatus()

        self.logger.info(
            f"Collecting audit logs from {from_time.isoformat()} to {to_time.isoformat()}..."
        )

        if self.authentication_method == "APP":
            entries = self.github.prepare_audit_log_entries(
                from_time=from_time, to_time=to_time
            )
        elif self.activation_config["github"].get("audit_log_enterprise"):
            entries = self.github.prepare_audit_log_entries(
                from_time=from_time,
                to_time=to_time,
                enterprise=self.activation_config["github"].get("audit_log_enterprise"),
            )

        for entry in entries:
            self.report_log_event(entry)

        multi_status.add_status(
            StatusValue.OK, f"Generated {len(entries)} audit log events."
        )
        return multi_status

    def report_secret_alerts(self, severity_level: str = "HIGH"):
        if not self.github.last_secret_scanning_query_time:
            oldest_acceptable_alert_time: datetime = datetime.now(
                tz=timezone.utc
            ) - timedelta(
                self.activation_config.get("advanced_options", {}).get(
                    "inclusion_time_window_days", 90
                )
            )
        else:
            oldest_acceptable_alert_time = self.github.last_secret_scanning_query_time

        multi_status: MultiStatus = MultiStatus()

        if self.authentication_method == "APP":
            for installation in self.github.app_installations:
                installation.set_repositories()

        security_events_to_report = self.github.get_secret_alerts(
            oldest_acceptable_alert_time, severity_level=severity_level
        )

        self.github.last_secret_scanning_query_time = datetime.now(tz=timezone.utc)

        multi_status.add_status(
            StatusValue.OK,
            f"Generated {len(security_events_to_report)} secret alert findings.",
        )

        self.ingest_security_event_chunks(security_events_to_report, [])

        return multi_status

    def report_code_scanning_alerts(self):
        if not self.github.last_code_scanning_query_time:
            oldest_acceptable_alert_time: datetime = datetime.now(
                tz=timezone.utc
            ) - timedelta(
                self.activation_config.get("advanced_options", {}).get(
                    "inclusion_time_window_days", 90
                )
            )
        else:
            oldest_acceptable_alert_time = self.github.last_code_scanning_query_time

        multi_status: MultiStatus = MultiStatus()

        if self.authentication_method == "APP":
            for installation in self.github.app_installations:
                installation.set_repositories()

        security_events_to_report = self.github.get_code_scanning_alerts(
            oldest_acceptable_alert_time
        )

        self.github.last_code_scanning_query_time = datetime.now(tz=timezone.utc)

        multi_status.add_status(
            StatusValue.OK,
            f"Generated {len(security_events_to_report)} code scanning security findings.",
        )

        self.ingest_security_event_chunks(security_events_to_report, [])

        return multi_status

    def report_dependabot_alerts(self):
        if not self.github.last_dependabot_query_time:
            oldest_acceptable_alert_time: datetime = datetime.now(
                tz=timezone.utc
            ) - timedelta(
                days=self.activation_config.get("advanced_options", {}).get(
                    "inclusion_time_window_days", 90
                )
            )
        else:
            oldest_acceptable_alert_time = self.github.last_dependabot_query_time

        multi_status: MultiStatus = MultiStatus()

        if self.authentication_method == "APP":
            for installation in self.github.app_installations:
                installation.set_repositories()

        security_events_to_report = self.github.get_dependabot_alerts(
            oldest_acceptable_alert_time
        )

        self.github.last_dependabot_query_time = datetime.now(tz=timezone.utc)

        multi_status.add_status(
            StatusValue.OK,
            f"Generated {len(security_events_to_report)} Dependabot security findings.",
        )

        self.ingest_security_event_chunks(security_events_to_report, [])

        return multi_status

    @staticmethod
    def create_valid_key_from_text(key_text: str):
        try:
            match = re.match(
                r"^(-----[A-Z\s]+-----)(.*)(-----[A-Z\s]+-----)$", key_text
            )
            header = match.group(1)
            key = match.group(2).lstrip()
            footer = match.group(3)

            if key.startswith("Proc-Type"):
                encryption_section, key = re.split("\s\s", key)
                key = "\n".join(re.split("\s+", key))
                proc_type_line, dek_line = encryption_section.split("DEK-Info")
                dek_line = f"DEK-Info{dek_line}"
                processed_key = (
                    f"{header}\n{proc_type_line}\n{dek_line}\n\n{key}{footer}"
                )
            else:
                key = "\n".join(re.split("\s+", key))
                processed_key = f"{header}\n{key}{footer}"
        except Exception as e:
            raise Exception(
                f"Key components could not be extracted using regex '^(-----[A-Z\s]+-----)(.*)(-----[A-Z\s]+-----)$'. Please check key: {e}"
            )
        return processed_key

    def fastcheck(self) -> Status:
        """
        Use to check if the extension can run.
        If this Activegate cannot run this extension, you can
        raise an Exception or return StatusValue.ERROR.
        This does not run for OneAgent extensions.
        """
        try:
            url = self.activation_config["github"]["url"]
            self.logger.info(f"Attempting  to connect to '{url}'")
            proxies = {
                "https": self.build_proxy_url(
                    self.activation_config.get("github", {}).get("proxy", {})
                )
            }
            verify = not self.activation_config.get("advanced_options", {}).get(
                "disable_cert_validation", False
            )
            response = requests.get(url=url, proxies=proxies, verify=verify, timeout=10)
            self.logger.info(f"{url} response: {response.status_code}")
            response.raise_for_status()
            return Status(StatusValue.OK)
        except Exception as e:
            self.logger.error(f"Unable to reach configured API base: {e}")
            return Status(
                StatusValue.GENERIC_ERROR, f"Unable to reach configured API base: {e}"
            )

    def ingest_security_event_chunks(self, chunk_events, failed_chunks_list):
        self.logger.info(
            f"Sending {len(chunk_events)} events to {self.security_events_ingest_url}..."
        )
        resized_chunks = split_by_size(
            chunk_events, 10000000
        )  # ensure we don't send payloads larger than 10MBs to OpenPipeline
        failed_chunks = []
        for chunk in chain(resized_chunks, failed_chunks_list):
            try:
                resp = requests.post(
                    (self.security_events_ingest_url),
                    headers={"Authorization": f"Api-Token {self.dt_token}"},
                    json=chunk,
                    verify=(
                        False
                        if (
                            self.security_events_ingest_url.startswith(
                                "https://localhost"
                            )
                            or self.security_events_ingest_url.startswith(
                                "https://127.0.0.1"
                            )
                        )
                        else True
                    ),
                )
                self.logger.debug(f"Event ingestion result: {resp.status_code}")
                resp.raise_for_status()
            except RequestException as e:
                failed_chunks.append(chunk)
                self.logger.exception(
                    f"Failed POSTing security events to Dynatrace with exception {e}"
                )
                self.logger.debug(f"Failed chunk: {json.dumps(chunk)}")

        if failed_chunks != []:
            self.logger.error(
                f"Failed ingest for {len(failed_chunks)} chunks of events. Will attempt re-ingest on the next run"
            )
            failed_chunks_list = failed_chunks

    @staticmethod
    def build_proxy_url(proxy_config: dict) -> str:
        proxy_address = proxy_config.get("address")
        proxy_username = proxy_config.get("username")
        proxy_password = proxy_config.get("password")

        if proxy_address:
            protocol, address = proxy_address.split("://")
            proxy_url = f"{protocol}://"
            if proxy_username:
                proxy_url += proxy_username
            if proxy_password:
                proxy_url += f":{proxy_password}"
            proxy_url += f"@{address}"
            return proxy_url

        return ""

    def repo_is_included(self, repo: str) -> bool:
        for repo_filter in self.repositories:
            if re.search(repo_filter, repo):
                return True
        return False


def main():
    ExtensionImpl(name="github_advanced_security").run()


if __name__ == "__main__":
    main()
