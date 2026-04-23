import json
from datetime import datetime, timedelta, timezone
from itertools import chain
from urllib.parse import urljoin

from dynatrace_extension import Extension, Status, StatusValue
from dynatrace_extension.sdk.status import MultiStatus
from requests.exceptions import RequestException
from requests.models import Response
from snyk import SnykClient

from .models.audit_events import AuditEvent
from .models.issues import Issue
from .models.issues_v1 import IssueV1
from .models.orgs import Org
from .models.project_history_v1 import SnapshotsData
from .models.projects import Project
from .rest_interface import Auth, Header, Proxy, RestApiHandler
from .utils.audit import get_audit_paged
from .utils.issues import generate_finding_from_issue
from .utils.projects import enrich_project_with_container_details
from .utils.scans import generate_scan_from_project_history
from .utils.shared import split_by_size
from .utils.snyk_pagination import PaginatedList, PaginationError


class ExtensionImpl(Extension):
    def initialize(self):
        if self.activation_config["advancedOptions"]["debugLogs"]:
            self.logger.setLevel("DEBUG")
        else:
            self.logger.setLevel("INFO")

        # Dynatrace API
        self.dynatrace_url: str = self.activation_config["connection"]["dynatraceUrl"]
        self.dynatrace_access_token: str = self.activation_config["connection"]["dynatraceAccessToken"]

        self.dynatrace_auth: Auth = Auth(
            type="Header", header_key="Authorization", header_value=f"Api-Token {self.dynatrace_access_token}"
        )

        if self.activation_config["advancedOptions"].get("dynatraceProxy") is not None:
            proxy_address = self.activation_config["advancedOptions"].get("dynatraceProxy").get("address")
            if proxy_address is not None:
                proxy_username = (
                    self.activation_config["advancedOptions"].get("dynatraceProxy").get("username")
                )
                proxy_password = (
                    self.activation_config["advancedOptions"].get("dynatraceProxy").get("password")
                )
                protocol, address = proxy_address.split("://")
                proxy_url = f"{protocol}://"
                if proxy_username is not None and proxy_password is not None:
                    proxy_url += f"{proxy_username}:{proxy_password}@"
                proxy_url += f"{address}"
                self.proxies = [Proxy("https", proxy_url)]
        else:
            self.proxies = None

        self.security_events_interface = RestApiHandler(
            url=self.dynatrace_url, auth=self.dynatrace_auth, proxies=self.proxies
        )  # logger=self.logger)

        # Snyk API
        self.snyk_base_url: str = self.activation_config["connection"]["snykUrl"]
        self.snyk_base_api_url: str = self.snyk_base_url.replace("app", "api")
        self.api_token: str = self.activation_config["connection"]["apiToken"]

        self.snyk_client: SnykClient = SnykClient(
            self.api_token,
            version="2024-12-09",
            url=urljoin(self.snyk_base_api_url, "rest"),
            user_agent="dynatrace-snyk-1.0.0",
            tries=5,
        )
        self.snyk_v1: SnykClient = SnykClient(self.api_token, tries=5)

        self.snyk_auth: Auth = Auth(
            type="Header", header_key="Authorization", header_value=f"token {self.api_token}"
        )
        self.snyk_v1_manual: RestApiHandler = RestApiHandler(
            url=urljoin(self.snyk_base_api_url, "v1"), auth=self.snyk_auth
        )
        self.snyk_rest_manual: RestApiHandler = RestApiHandler(
            url=urljoin(self.snyk_base_api_url, "rest"), auth=self.snyk_auth
        )

        self.get_all_orgs: bool = self.activation_config["orgs"]["allOrgs"]
        self.org_names: str = self.activation_config["orgs"].get("orgList", [])
        self.org_ids: dict[str, str] = {}

        # Issues config
        self.fetch_events: bool = self.activation_config["products"].get("fetchEvents", False)
        self.issues_first_ingest_window: float = self.activation_config["advancedOptions"].get(
            "firstTimeFetchWindow"
        )
        self.issues_frequency: float = self.activation_config["advancedOptions"].get("vulnsFetchFrequency", 1)

        self.issues_last_fetched: datetime = datetime.fromtimestamp(0)

        self.issues_first_ingest: bool = True
        # self.number_of_vulnerabilites_reported: int = 0
        self.failed_vuln_chunks: list = []
        self.failed_scan_chunks: list = []

        # Filters
        self.issues_minimum_severity_level: str = self.activation_config["advancedOptions"].get(
            "minimumSeverityLevel", "info"
        )
        self.project_origin_filter: str | None = self.activation_config["advancedOptions"].get(
            "projectOrigins", None
        )

        severities = ["info", "low", "medium", "high", "critical"]
        self.list_of_severities = severities[severities.index(self.issues_minimum_severity_level) :]

        # Audit logs config
        self.fetch_audit_logs: bool = self.activation_config["products"].get("fetchAuditLogs", False)
        self.audit_logs_first_ingest_window: float = self.activation_config["advancedOptions"].get(
            "firstTimeFetchWindow"
        )
        self.audit_logs_collection_frequency: float = self.activation_config["advancedOptions"].get(
            "auditFetchFrequency", 1
        )
        self.audit_logs_last_fetched: datetime = datetime.fromtimestamp(0)

        self.audit_logs_first_ingest: bool = True

        # Enrichment fields
        self.enrichment_fields = self.activation_config._activation_context_json.get("dtAttributes", {})

        # Initialize
        self.find_orgs()

        # Scheduling
        if self.fetch_events:
            self.schedule(self.ingest_issues, interval=timedelta(hours=self.issues_frequency))

        if self.fetch_audit_logs:
            self.schedule(
                self.ingest_audit_logs, interval=timedelta(hours=self.audit_logs_collection_frequency)
            )

    def find_orgs(self):
        self.logger.debug("Getting orgs")
        orgs = [
            Org(org) for org in list(PaginatedList(self.snyk_client, "orgs", target_params={"limit": 100}))
        ]
        self.logger.info(f"Got list of orgs: {[f'{org.attributes.slug} ({org.id})' for org in orgs]}")
        for org in orgs:
            if self.get_all_orgs or org.attributes.slug in self.org_names:
                self.org_ids[org.id] = org.attributes.slug
                self.logger.debug(f"Org {org.attributes.slug} found.")

    def ingest_issues(self):
        if self.issues_first_ingest:
            datetime_to_query = datetime.now(timezone.utc) - timedelta(hours=self.issues_first_ingest_window)
            self.issues_first_ingest = False
            self.issues_last_fetched = datetime.now(timezone.utc)
        else:
            datetime_to_query = self.issues_last_fetched
            self.issues_last_fetched = datetime.now(timezone.utc)
        multi_status: MultiStatus = MultiStatus()
        self.logger.info(f"Starting issue ingest with datetime_to_query {datetime_to_query}")

        if len(self.org_ids) == 0:
            self.logger.error(
                "DEC:D7 No Snyk organizations found or organizations "
                "found do not match the configured organizations. "
                "Double check your Snyk service account permissions."
            )
            multi_status.add_status(
                StatusValue.GENERIC_ERROR,
                (
                    "DEC:D7 No Snyk organizations found or organizations "
                    "found do not match the configured organizations. "
                    "Double check your Snyk service account permissions."
                ),
            )

        for org_id, org_name in self.org_ids.items():
            projects = self.get_projects_for_org(org_id)
            if len(projects) > 0:
                self.ingest_issues_and_scans_for_org(
                    org_id, org_name, projects, datetime_to_query, multi_status
                )
            else:
                self.logger.warning(
                    f"No projects found for organization {org_name}, org ID {org_id}. Skipping."
                )

        self.logger.info(f"Finished issue ingest with datetime_to_query {datetime_to_query}")

        return multi_status

    def ingest_audit_logs(self):
        if self.audit_logs_first_ingest:
            timestamp_to_collect = (
                (datetime.now(timezone.utc) - timedelta(hours=self.audit_logs_first_ingest_window))
                .isoformat()
                .replace("+00:00", "Z")
            )
            self.audit_logs_first_ingest = False
            self.audit_logs_last_fetched = datetime.now(timezone.utc)
        else:
            timestamp_to_collect = self.audit_logs_last_fetched.isoformat().replace("+00:00", "Z")
            self.audit_logs_last_fetched = datetime.now(timezone.utc)

        multi_status: MultiStatus = MultiStatus()

        for org_id in self.org_ids:
            self.report_audit_logs(org_id, timestamp_to_collect, multi_status)

        self.logger.info("Audit log ingest finished.")
        return multi_status

    ###################
    # Security events #
    ###################

    def get_projects_for_org(self, org_id: str, project_ids: None | list[str] = None) -> dict[str, Project]:
        self.logger.debug(f"Getting projects for org {org_id}")
        query_params = {"expand": "target", "meta.latest_issue_counts": True}
        if project_ids is not None:
            query_params["ids"] = ",".join(project_ids)
        if self.project_origin_filter is not None:
            query_params["origins"] = self.project_origin_filter

        projects = list(
            PaginatedList(
                self.snyk_client, f"orgs/{org_id}/projects", target_params={**query_params, "limit": 100}
            )
        )
        self.logger.info(f"Got list of projects with length {len(projects)}")
        project_dict = {project.get("id"): Project(project) for project in projects}
        self.logger.info("Enriching project data with container information.")
        for project_id, project in project_dict.items():
            if "build_args" in project.attributes.original_data:
                try:
                    enrich_project_with_container_details(
                        org_id,
                        project_id,
                        project,
                        self.snyk_v1_manual,
                        self.snyk_base_api_url,
                        self.snyk_client,
                    )
                except Exception as e:
                    self.logger.warning(f"Unable to enrich project {project_id} with container details.")
                    self.logger.warning(e)

        return project_dict

    def ingest_issues_and_scans_for_org(
        self,
        org_id: str,
        org_name: str,
        projects: dict[str, Project],
        datetime_to_query: str,
        multi_status: MultiStatus,
    ):
        """
        Ingests both issues and scans for a specific org.
        These have to be ingest at the same time since we rely on the presence of project history
        to determine whether an issue was "present" or not.
        We make a separate API call to the issues API for each project, since this allows us to take
        advantage of project filtering.
        """

        total_scans = 0
        total_findings = 0
        projects_with_issues = 0
        self.logger.info(f"Starting scan and vulnerability finding ingestion for org {org_name}.")

        # Getting scans for projects
        for project in projects.values():
            if datetime.timestamp(
                datetime.fromisoformat(project.meta.latest_issue_counts.updated_at.replace("Z", "+00:00"))
            ) > datetime.timestamp(datetime_to_query):
                self.logger.debug(
                    f"Generating scan events for project {project.id} "
                    f"(updated at {project.meta.latest_issue_counts.updated_at})."
                )

                project_history_response: Response = self.snyk_v1_manual.post_url(
                    url=urljoin(self.snyk_base_api_url, f"v1/org/{org_id}/project/{project.id}/history"),
                    headers=[Header({"headerKey": "User-Agent", "headerValue": "dynatrace-snyk-1.0.0"})],
                )
                project_history: SnapshotsData = SnapshotsData(project_history_response.json())

                scan_events = generate_scan_from_project_history(
                    project,
                    project_history,
                    datetime_to_query,
                    org_name,
                    self.snyk_base_url,
                    self.enrichment_fields,
                )

                self.logger.debug(f"Generating {len(scan_events)} scan events for project {project.id}")
                if len(scan_events) > 0:
                    # Ingest issues for this project
                    total_findings += self.ingest_issues_for_project(
                        org_id, org_name, project, scan_events, multi_status
                    )
                    # Ingest scans for this project
                    self.ingest_chunks(scan_events, self.failed_scan_chunks, multi_status)
                    total_scans += len(scan_events)
                    projects_with_issues += 1
            else:
                self.logger.debug(
                    f"Project {project.id} did not have scans within this period"
                    " (no issues will be ingested)."
                )
        self.logger.info(
            f"Generated {total_scans} scan events across {len(projects)} projects for org {org_name}"
        )
        multi_status.add_status(
            StatusValue.OK,
            (f"Generated {total_scans} scan events across {len(projects)} projects for org {org_name}"),
        )

        self.logger.info(
            f"Generated {total_findings} vulnerability findings across "
            f"{projects_with_issues} projects for org {org_name}"
        )
        multi_status.add_status(
            StatusValue.OK,
            (
                f"Generated {total_findings} vulnerability findings across "
                f"{projects_with_issues} projects for org {org_name}"
            ),
        )

    def ingest_issues_for_project(
        self,
        org_id: str,
        org_name: str,
        project: Project,
        scan_events: list,
        multi_status: MultiStatus,
    ) -> int:
        self.logger.debug(f"Getting all open issues for project {project.id} org {org_name} in batches.")
        query_params = {
            "status": "open",
            "scan_item.type": "project",
            "scan_item.id": project.id,
            "effective_severity_level": ",".join(self.list_of_severities),
        }
        issues = []
        batch_count = 0
        project_findings = 0
        try:
            for index, issue in enumerate(
                PaginatedList(
                    self.snyk_client,
                    f"orgs/{org_id}/issues",
                    target_params={**query_params, "limit": 100},
                )
            ):
                issues.append(Issue(issue))
                if index % 1000 == 0:
                    project_findings += self.ingest_issues_from_batch(
                        issues,
                        org_id,
                        org_name,
                        project,
                        scan_events,
                        multi_status,
                        batch_count,
                    )
                    issues = []
            if len(issues) > 0:
                project_findings += self.ingest_issues_from_batch(
                    issues, org_id, org_name, project, scan_events, multi_status, batch_count
                )
                issues = []
        except PaginationError as e:
            multi_status.add_status(
                StatusValue.GENERIC_ERROR,
                (f"DEC:D8 API error when fetching open issues for project {project.id} org {org_name} - {e}"),
            )

        return project_findings

    def ingest_issues_from_batch(
        self,
        issues: list[Issue],
        org_id: str,
        org_name: str,
        project: Project,
        scan_events: list,
        multi_status: MultiStatus,
        batch_count: int,
    ) -> int:
        batch_count += 1
        self.logger.debug(
            f"Ingesting findings for {len(issues)} issues for project {project.id} "
            f"org {org_name} (batch {batch_count})."
        )
        # Aggregating issues by project id in order to get data from other APIs
        vuln_events_to_ingest: list[dict] = []
        aggregated_issues: Response = self.snyk_v1_manual.post_url(
            url=urljoin(
                self.snyk_base_api_url,
                f"v1/org/{org_id}/project/{project.id}/aggregated-issues",
            ),
            json={"includeDescription": True},
            headers=[Header({"headerKey": "User-Agent", "headerValue": "dynatrace-snyk-1.0.0"})],
        )
        v1_issues_data: dict[str, IssueV1] = {
            issue.get("id"): IssueV1(issue) for issue in aggregated_issues.json().get("issues", [])
        }
        for scan_event in scan_events:
            vuln_events = [
                finding
                for issue in issues
                for finding in generate_finding_from_issue(
                    issue,
                    project,
                    scan_event,
                    v1_issues_data,
                    org_name,
                    self.snyk_base_url,
                    self.enrichment_fields,
                )
            ]
            vuln_events_to_ingest.extend(vuln_events)
        self.logger.debug(f"Generated finding events for {project.id} on batch {batch_count}.")
        self.ingest_chunks(vuln_events_to_ingest, self.failed_vuln_chunks, multi_status)
        return len(vuln_events_to_ingest)

    ##############
    # Audit Logs #
    ##############

    def report_audit_logs(self, org_id: str, timestamp_to_collect: str, multi_status: MultiStatus):
        events: list = get_audit_paged(
            self.snyk_rest_manual,
            self.snyk_base_api_url,
            org_id,
            params={"from": timestamp_to_collect, "version": "2024-12-09"},
            headers=[Header({"headerKey": "User-Agent", "headerValue": "dynatrace-snyk-1.0.0"})],
        )

        for e in events:
            event = AuditEvent(e)
            log_entry = {
                "level": "INFO",
                "log.source": "Snyk",
                "content": json.dumps(event.original_data),
                "audit.identity": event.user_id,
                "audit.action": event.event,
                # "description": event.content,
                "audit.time": event.created,
                "dt.extension.name": "com.dynatrace.extension.snyk",
                "dt.extension.config.id": self.monitoring_config_id,
                "extension.config.name": self.monitoring_config_name,
            }

            self.report_log_event(log_entry)

        self.logger.info(f"Attempted ingest of {len(events)} audit events for org {org_id}.")
        multi_status.add_status(StatusValue.OK, f"Generated {len(events)} audit events for org {org_id}")

    #########
    # Other #
    #########

    def ingest_chunks(self, chunk_events, failed_chunks_list, multi_status: MultiStatus) -> None:
        resized_chunks = split_by_size(
            chunk_events, 10000000
        )  # ensure we don't send payloads larger than 10MBs to OpenPipeline
        failed_chunks = []
        for chunk in chain(resized_chunks, failed_chunks_list):
            try:
                self.security_events_interface.post_url(json=chunk)
            except RequestException as e:
                failed_chunks.append(chunk)
                self.logger.warning(f"DEC:C6 Failed POSTing security events to Dynatrace with exception {e}")

        if failed_chunks != []:
            self.logger.error(
                f"DEC:C6 Failed ingest for {len(failed_chunks)} chunks of events. "
                "Will attempt re-ingest on the next run"
            )
            multi_status.add_status(
                StatusValue.GENERIC_ERROR,
                (
                    f"DEC:C6 Failed ingest for {len(failed_chunks)} chunks of events. "
                    "Will attempt re-ingest on the next run"
                ),
            )
            failed_chunks_list = failed_chunks

    def fastcheck(self) -> Status:
        """
        This is called when the extension runs for the first time.
        If this AG cannot run this extension, raise an Exception or return StatusValue.ERROR!
        """
        return Status(StatusValue.OK)


def main():
    ExtensionImpl(name="appsec_snyk").run()


if __name__ == "__main__":
    main()
