from dynatrace_extension import Extension, Status, StatusValue
from dynatrace_extension.sdk.status import MultiStatus
from typing import Dict, List, Optional
from datetime import datetime, timedelta, timezone
import uuid
from itertools import chain
import requests
import json
from functools import lru_cache
import urllib3

from requests.exceptions import RequestException

from .harbor import Harbor
from .artifact import Artifact
from .vulnerability import Vulnerability
from .shared import split_by_size, size_of_record
from .environment import DynatraceEnvironmentUtils

dt_env_utils = DynatraceEnvironmentUtils()

SCHEMA_VERSION = "1.306"

urllib3.disable_warnings()


class ExtensionImpl(Extension):

    def initialize(self):
        self.dev_mode = True if self.task_id == "development_task_id" else False
        self.extension_name = "harbor"
        self.logger.setLevel(
            "DEBUG"
            if self.activation_config.get("advanced_options", {}).get(
                "debug_logs", False
            )
            else "INFO"
        )
        self.last_query_time: Optional[datetime] = None
        self.last_log_time: Optional[datetime] = None
        harbor = self.activation_config["harbor"]

        self.harbor = Harbor(
            harbor["host"],
            harbor["username"],
            harbor["password"],
            proxies={
                "https": self.build_proxy_url(self.activation_config.get("proxy", {}))
            },
            verify=not self.activation_config.get("advanced_options", {}).get(
                "disable_cert_validation", False
            ),
            log=self.logger,
        )
        self.dt_token = self.activation_config["dynatrace"]["dt_token"]
        if self.dev_mode:
            self.security_events_ingest_url = f"https://localhost:9999/e/{self.activation_config.get('dt_environment_id')}/platform/ingest/v1/security.events"
        else:
            self.security_events_ingest_url = (
                self.activation_config["dynatrace"].get("dynatrace_security_ingest_url")
                if self.activation_config["dynatrace"].get("dynatrace_security_ingest_url")
                else f"{dt_env_utils.get_api_url()}/platform/ingest/v1/security.events"
            )

        self.schedule(
            self.report_audit_logs,
            timedelta(
                minutes=self.activation_config.get("advanced_options", {}).get(
                    "audit_fetch_frequency", 1
                )
            ),
        )

        self.schedule(
            self.report_vulnerability_scans,
            timedelta(
                hours=self.activation_config.get("advanced_options", {}).get(
                    "vulns_fetch_frequency", 1
                )
            ),
        )

    def report_audit_logs(self):
        multi_status: MultiStatus = MultiStatus()
        self.harbor.initialize()
        now = datetime.now(tz=timezone.utc)
        if self.last_log_time:
            from_time = self.last_log_time
        else:
            from_time = now - timedelta(minutes=1)
        self.last_log_time = now
        logs = self.harbor.get_audit_logs(from_time, now)
        for log in logs:
            log_event = {
                "level": "INFO",
                "log.source": "Harbor",
                "content": json.dumps(log.original_content),
                "audit.identity": log.username,
                "audit.action": f"{log.operation} {log.resource_type} {log.resource}",
                "audit.time": log.op_time.isoformat(),
                "audit.result": "Succeeded",
                "id": log.id,
            }
            self.logger.debug(f"Reporting audit log: {log_event}")
            self.report_log_event(log_event)
        multi_status.add_status(StatusValue.OK, f"Reported {len(logs)} audit logs.")
        return multi_status

    def determine_filtered_artifacts(self):
        filtered_artifacts: List[Artifact] = []
        if self.activation_config["harbor"].get("projects", None):
            # user specified projects
            for project in self.activation_config["harbor"].get("projects", []):
                self.logger.info(f"Reporting project {project['name']}")
                project_name = project["name"]
                repositories = project.get("repositories", [])
                if repositories:
                    # user specified repositories within project
                    for repo_name in repositories:
                        try:
                            self.logger.info(
                                f"Reporting repository {repo_name} in {project['name']}"
                            )
                            for artifact in self.harbor.get_artifacts(
                                project_name, repo_name
                            ):
                                artifact.project_name = project_name
                                filtered_artifacts.append(artifact)
                        except Exception as e:
                            self.logger.error(f"DEC:197 Unable to collect artifacts for respository {repo_name} in project {project_name}: {e}")
                else:
                    # all repositories in project included
                    self.logger.info(f"Reporting all repos in {project['name']}")
                    repositories = self.harbor.get_repositories(project["name"])
                    for repo in repositories:
                        try:
                            for artifact in self.harbor.get_artifacts(
                                project["name"], repo.name
                            ):
                                artifact.project_name = project["name"]
                                filtered_artifacts.append(artifact)
                        except Exception as e:
                            self.logger.error(f"DEC:197 Unable to collect artifacts for respository {repo.name} in project {project['name']}: {e}")
        else:
            # all projects in registry included (based on permissions of user)
            self.logger.info(f"Reporting all projects and repositories.")
            try:
                for project in self.harbor.get_projects():
                    self.logger.debug(f"Project: {project.name}")
                    for repo in self.harbor.get_repositories(project.name):
                        try:
                            for artifact in self.harbor.get_artifacts(project.name, repo.name):
                                self.logger.debug(f"Artifact: {artifact.id}")
                                artifact.project_name = project.name
                                filtered_artifacts.append(artifact)
                        except Exception as e:
                            self.logger.error(f"DEC:197 Unable to collect artifacts for project {project.name}: {e}")
            except Exception as e:
                self.logger.error(f"DEC:197 Unable to collect artifacts for all projects: {e}")

        self.logger.info(
            f"Number of filtered artifacts to analyze: {len(filtered_artifacts)}"
        )

        return filtered_artifacts

    def report_scans(self, artifacts: List[Artifact]):
        scans_to_report = []
        for artifact in artifacts:
            scan_payload = {
                "event.kind": "SECURITY_EVENT",
                "event.provider": "Harbor",
                "event.original_content": artifact.original_content,
                "event.id": str(uuid.uuid4()),
                "event.version": SCHEMA_VERSION,
                "event.type": "VULNERABILITY_SCAN",
                "event.category": "VULNERABILITY_MANAGEMENT",
                "event.name": "Vulnerability scan event",
                "event.description": f"Vulnerability scan completed on container image {artifact.repository_name}",
                "product.vendor": artifact.scan_overview.scanner.vendor,
                "product.name": artifact.scan_overview.scanner.name,
                "object.id": f"{self.harbor.registry_url}/{artifact.repository_name}/{artifact.digest}",
                "object.type": "CONTAINER_IMAGE",
                "object.name": artifact.repository_name,
                "container_image.registry": self.harbor.registry_url,
                "container_image.repository": artifact.repository_name,
                "container_image.tags": artifact.tags,
                "container_image.digest": artifact.digest,
                "scan.id": artifact.scan_overview.report_id,
                "scan.name": artifact.scan_overview.report_id,
                "scan.time.started": artifact.scan_overview.start_time.isoformat(),
                "scan.time.completed": artifact.scan_overview.end_time.isoformat(),
                "harbor.project.name": artifact.project_name,
                "harbor.project.id": artifact.project_id,
            }
            self.logger.debug(f"Reporting scan event {scan_payload}")
            scans_to_report.append(scan_payload)
        self.ingest_security_event_chunks(scans_to_report, [])

    @staticmethod
    @lru_cache
    def determine_risk_level_and_score(vulnerability: Vulnerability):
        risk_level = vulnerability.severity.upper()
        if risk_level == "UNKNOWN":
            risk_level = "NONE"

        risk_score = 0
        if risk_level == "CRITICAL":
            risk_score = 10
        elif risk_level == "HIGH":
            risk_score = 8.9
        elif risk_level == "MEDIUM":
            risk_score = 6.9
        elif risk_level == "LOW":
            risk_score = 3.9

        return risk_level, risk_score

    def report_vulnerabilities(self, artifacts: List[Artifact]):
        artifact_map: Dict[str, Artifact] = {}
        for artifact in artifacts:
            artifact_map.update({artifact.digest: artifact})

        vuln_events_to_report = []
        vulnerabilites = self.harbor.get_vulnerabilities(list(artifact_map.keys()))
        for vuln in vulnerabilites:
            artifact: Artifact = artifact_map[vuln.digest]
            risk_level, risk_score = self.determine_risk_level_and_score(vuln)
            vuln_payload = {
                "event.kind": "SECURITY_EVENT",
                "event.original_content": vuln.original_content,
                "event.id": str(uuid.uuid4()),
                "event.version": SCHEMA_VERSION,
                "event.provider": "Harbor",
                "event.type": "VULNERABILITY_FINDING",
                "event.category": "VULNERABILITY_MANAGEMENT",
                "event.name": "Vulnerability finding event",
                "event.description": f"Vulnerability {vuln.cve_id} was found in container image ({artifact.repository_name}) in {vuln.package} ({vuln.version})",
                "object.id": f"{self.harbor.registry_url}/{artifact.repository_name}/{artifact.digest}",
                "object.name": artifact.repository_name,
                "object.type": "CONTAINER_IMAGE",
                "container_image.registry": self.harbor.registry_url,
                "container_image.repository": artifact.repository_name,
                "container_image.tags": artifact.tags,
                "container_image.digest": artifact.digest,
                "vulnerability.id": vuln.cve_id,
                "vulnerability.title": vuln.cve_id,
                "vulnerability.description": vuln.desc,
                "vulnerability.references.cve": [vuln.cve_id],
                "vulnerability.remediation.fix_versions": [vuln.fixed_version],
                "vulnerability.remediation.status": (
                    "AVAILABLE" if vuln.fixed_version else "NOT_AVAILABLE"
                ),
                "vulnerability.remediation.description": (
                    f"Upgrade to {vuln.package} {vuln.fixed_version} or later."
                    if vuln.fixed_version
                    else None
                ),
                "dt.security.risk.level": risk_level,
                "dt.security.risk.score": risk_score,
                "component.name": vuln.package,
                "component.version": vuln.version,
                "finding.id": f"{artifact.digest}/{artifact.scan_overview.report_id}",
                "finding.title": f"{vuln.cve_id} on {artifact.repository_name}",
                "finding.time.created": artifact.scan_overview.end_time.isoformat(),
                "finding.severity": vuln.severity,
                "finding.score": vuln.cvss_v3_score,
                "product.name": artifact.scan_overview.scanner.name,
                "product.vendor": artifact.scan_overview.scanner.vendor,
                "scan.id": artifact.scan_overview.report_id,
                "scan.name": artifact.scan_overview.report_id,
                "scan.time.completed": artifact.scan_overview.end_time.isoformat(),
                "harbor.project.name": artifact.project_name,
                "harbor.project.id": artifact.project_id,
            }

            vuln_events_to_report.append(vuln_payload)

        self.logger.info(
            f"Reporting {len(vuln_events_to_report)} vulnerability findings for artifact {self.harbor.registry_url}/{artifact.repository_name}/{artifact.digest}"
        )

        self.ingest_security_event_chunks(vuln_events_to_report, [])

    def report_vulnerability_scans(self):
        multi_status: MultiStatus = MultiStatus()
        self.harbor.initialize()
        artifacts_with_recent_scans: Optional[List[Artifact]] = []
        now = datetime.now(tz=timezone.utc)
        if self.last_query_time:
            from_time = self.last_query_time
        else:
            from_time = now - timedelta(
                hours=self.activation_config.get("advanced_options", {}).get(
                    "first_time_fetch_window", 1
                )
            )
        self.last_query_time = now
        artifacts_to_check = self.determine_filtered_artifacts()
        self.logger.debug(
            f"Vulns reported in scan end time between {from_time} and {now}"
        )

        for artifact in artifacts_to_check:
            if artifact.type == "IMAGE":
                if not artifact.scan_overview:
                    self.logger.info(
                        f"No scan overview available for artifact {artifact.id}, skipping"
                    )
                    continue
                if now > artifact.scan_overview.end_time > from_time:
                    self.logger.info(
                        f"{artifact.scan_overview.scanner.name} scanned artifact with end time of {artifact.scan_overview.end_time} will be reported"
                    )
                    artifacts_with_recent_scans.append(artifact)
                else:
                    self.logger.debug(
                        f"{artifact.scan_overview.scanner.name} scanned artifact with end time of {artifact.scan_overview.end_time} will NOT be reported"
                    )
            else:
                # charts don't have scans
                # CNABs not considered for now
                continue
        if artifacts_with_recent_scans:
            try:
                self.report_scans(artifacts_with_recent_scans)
                self.report_vulnerabilities(artifacts_with_recent_scans)
                multi_status.add_status(StatusValue.OK, f"Reported scans and vulns for {len(artifacts_with_recent_scans)} artifacts.")
            except Exception as e:
                self.logger.exception(f"DEC:197 Unable to report scans and vulns: {e}")
        else:
            self.logger.info(
                f"No available artifacts with recent scans, nothing to report."
            )
        return multi_status

    def ingest_security_event_chunks(
        self, chunk_events, failed_chunks_list
    ) -> tuple[StatusValue, str]:
        status_value: StatusValue = None
        status_message: str = None
        successful_events_count = 0
        # Add attributes to events
        attributes = self.activation_config._activation_context_json.get('dtAttributes', {})
        security_context = attributes.get("dt.security_context")
        cost_center = attributes.get("dt.cost.costcenter")
        product = attributes.get("dt.cost.product")
        for event in chunk_events:
            if security_context:
                event["dt.security_context"] = security_context
            if cost_center:
                event["dt.cost.costcenter"] = cost_center
            if product:
                event["dt.cost.product"] = product
            
            # if self.dev_mode:
            #     print(json.dumps(event))
            #     print("----")
            
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
                successful_events_count += len(chunk)
            except RequestException as e:
                reason = e
                try:
                    error = resp.json()
                    if error.get("error", {}).get("message"):
                        reason = error["error"]["message"]
                except Exception as e:
                    pass
                failed_chunks.append(chunk)
                self.logger.error(
                    f"DEC:C6 Failed POSTing security events to Dynatrace with exception: {reason}"
                )
                self.logger.debug(f"Failed chunk: {json.dumps(chunk)}")

        if failed_chunks != []:
            self.logger.error(
                f"DEC:C6 Failed ingest for {len(failed_chunks)} chunks of events."
            )
            failed_chunks_list = failed_chunks
            status_value = StatusValue.GENERIC_ERROR
            status_message = (
                f"DEC:C6 Failed ingest for {len(failed_chunks)} chunks of events."
            )
        if successful_events_count > 0:
            status_value = StatusValue.OK
            status_message = (
                f"Successfully ingested {successful_events_count} security events."
            )

        return status_value, status_message

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

    def fastcheck(self) -> Status:
        self.initialize()
        # fastcheck needs to finish in 15 seconds
        self.harbor.http_client.timeout_seconds = 10
        self.harbor.ping()
        return Status(StatusValue.OK)


def main():
    ExtensionImpl(name="harbor_extension").run()


if __name__ == "__main__":
    main()
