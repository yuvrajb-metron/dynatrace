import logging
from typing import List, Optional, Dict
import logging
from datetime import datetime, timezone
import urllib
import urllib.parse
import time
import jwt
import re
import uuid
import json
import pycountry
from copy import deepcopy

from .pagination import PaginatedList
from .http_client import HttpClient
from .models.dependabot_vulnerability import DependabotAlert
from .models.code_scanning import CodeScanningAlert, CodeScanAnalysis
from .models.secret_scanning import SecretScanningAlert
from .models.audit_log import AuditLogEntry
from .models.dependency_graph import DependencyGraph
from .models.app_installation import AppInstallation, TIME_FORMAT
from .models.repository import Repository
from .shared import SCHEMA_VERSION, Location, AdditionalLocation

log = logging.getLogger(__name__)

DEFAULT_PAGE_SIZE = 100
TIME_FORMAT = r"%Y-%m-%dT%H:%M:%S"
GHAS_NAMESPACE = uuid.UUID("2948f268-ff0e-4bb6-b728-986b634f77ba")


class NotInstalledException(Exception):
    pass


EVENT_SOURCE = "GitHub Advanced Security"


class Github:
    def __init__(
        self,
        host: str,
        proxies: Optional[dict],
        token: Optional[str] = None,
        client_id: Optional[str] = None,
        account: Optional[str] = None,
        private_key: Optional[str] = None,
        verify: bool = True,
        repository_filters: Optional[List] = None,
        organization_logs: Optional[List] = None,
        log=log,
    ):
        self.log = log

        self.verify: bool = verify
        if not verify:
            self.log.warning(
                f"Certifcate validation has been disabled in the configuration, to avoid log congestion insecure request warnings are suppressed."
            )
        self.proxies = proxies

        url_parse_result = urllib.parse.urlparse(host)
        if not url_parse_result.scheme and url_parse_result.netloc:
            raise Exception(f"'{host}' is not a valid URL")
        if url_parse_result.scheme != "https":
            raise Exception(
                f"Non-HTTPS protocol being used. This is insecure and will result in clear-text credentials on the network. Switch to an HTTPS endpoint."
            )
        else:
            self.processed_host = (
                f"{url_parse_result.scheme}://{url_parse_result.netloc}"
            )

        self.client_id = client_id
        self.account = account
        self.private_key = private_key
        self.jwt = None
        self.app_installations: List[AppInstallation] = []
        self.repository_filters = repository_filters
        self.organization_logs = organization_logs
        self.update_lock: bool = False
        self.last_app_update: datetime = None

        self.http_client: HttpClient = HttpClient(
            host=self.processed_host,
            token=token,
            proxies=proxies,
            verify=verify,
            log=log,
        )

        self.last_dependabot_query_time: Optional[datetime] = None
        self.last_code_scanning_query_time: Optional[datetime] = None
        self.last_secret_scanning_query_time: Optional[datetime] = None

    def update_app_installations(self):
        self.update_lock = True

        if self.last_app_update:
            if (
                datetime.now(tz=timezone.utc) - self.last_app_update
            ).total_seconds() < 300:
                self.log.info(
                    f"App installations updated recently ({self.last_app_update}). Not updating."
                )
                return
        self.log.info(
            f"App installations updated ({self.last_app_update}). Updating installations and tokens..."
        )
        try:
            self._update_jwt()
            self.get_installations()
            self.last_app_update = datetime.now(tz=timezone.utc)
        except Exception as e:
            self.log.error(f"Error updating App installations and authentication: {e}")
        finally:
            self.update_lock = False

    def repo_is_included(self, repo: str) -> bool:
        for repo_filter in self.repository_filters:
            if re.search(repo_filter, repo):
                return True
        return False

    def org_is_included(self, org: str) -> bool:
        for org_filter in self.organization_logs:
            if re.search(org_filter, org):
                return True
        return False

    def get_installations(self):
        self.log.info(f"Retrieving installations for client {self.client_id}.")
        self.app_installations = []
        installations: List[AppInstallation] = PaginatedList(
            AppInstallation,
            self.http_client,
            "app/installations",
            headers={"Authorization": f"Bearer {self.jwt}"},
            target_params={"per_page": DEFAULT_PAGE_SIZE},
        )
        for installation in installations:
            installation.set_http_client(
                self.processed_host, self.proxies, self.verify, self.log
            )
            installation.log = self.log
            self.app_installations.append(installation)
        self.update_app_authentication()

    def update_app_authentication(self):
        self._update_jwt()
        for installation in self.app_installations:
            try:
                installation.set_access_token(self.jwt)
            except Exception as e:
                self.log.error(
                    f"Unable to update installation access token for {installation.id}"
                )

    def _update_jwt(self):
        self.log.info(f"Updating token for App with client id {self.client_id}.")
        payload = {
            # Issued at time
            "iat": int(time.time()),
            # JWT expiration time (10 minutes maximum)
            "exp": int(time.time()) + 500,
            # GitHub App's client ID
            "iss": self.client_id,
        }
        encoded_jwt = jwt.encode(payload, self.private_key, algorithm="RS256")
        self.jwt = encoded_jwt

    def is_reachable(self):
        resp = self.http_client.make_request("")
        resp.raise_for_status()
        self.log.info(f"Successfully tested connection.")

    def get_dependency_graph(self, owner: str):
        try:
            self.log.info(f"Getting dependency graph for {owner}")
            return DependencyGraph(
                raw_element=self.http_client.make_request(
                    f"repos/{owner}/dependency-graph/sbom"
                ).json()
            )
        except Exception as e:
            self.log.error(f"Unable to get dependency graph for {owner}: {e}")
            return None

    def get_file_hash(self, owner: str, path: str):
        try:
            self.log.info(f"Getting hash for {owner}/{path}")
            resp = self.http_client.make_request(f"repos/{owner}/contents/{path}")
            resp.raise_for_status()
            hash = resp.json()["sha"]
            return hash
        except Exception as e:
            self.log.error(f"Unable to get hash of file {owner}/{path}: {e}")
            return None

    def get_repositories(self) -> PaginatedList[Repository]:
        # PAT
        self.log.info(f"Getting repositories for authenticated user.")
        return PaginatedList(
            Repository,
            self.http_client,
            f"user/repos",
            target_params={"per_page": DEFAULT_PAGE_SIZE},
        )

    def prepare_audit_log_entries(
        self, from_time: datetime, to_time: datetime, enterprise: str = None
    ):

        phrase = f"created:{from_time.strftime(TIME_FORMAT)}..{to_time.strftime(TIME_FORMAT)}"

        entries: List[AuditLogEntry] = []
        log_events: List[Dict] = []

        if self.app_installations:
            for installation in self.app_installations:
                if installation.target_type == "Organization":
                    if not self.organization_logs or self.org_is_included(
                        installation.account.login
                    ):
                        self.log.info(
                            f"Getting audit logs for organization {installation.account.login}..."
                        )
                        entries.extend(
                            PaginatedList(
                                AuditLogEntry,
                                installation.http_client,
                                f"organizations/{installation.account.login}/audit-log",
                                target_params=(
                                    {"per_page": DEFAULT_PAGE_SIZE, "phrase": {phrase}}
                                ),
                            )
                        )
        elif enterprise:
            entries.extend(
                PaginatedList(
                    AuditLogEntry,
                    self.http_client,
                    f"enterprises/{enterprise}/audit-log",
                    target_params=({"per_page": DEFAULT_PAGE_SIZE, "phrase": {phrase}}),
                )
            )

        for entry in entries:
            log_event = {
                "level": "INFO",
                "log.source": EVENT_SOURCE,
                "content": json.dumps(entry.original_content),
                "audit.identity": entry.actor,
                "audit.action": entry.action,
                "audit.time": entry.created_at.isoformat(),
                "audit.result": "Succeeded",
                "dt.extension.name": "com.dynatrace.extension.github-advanced-security",
            }
            if entry.actor_location:
                try:
                    country = pycountry.countries.get(
                        alpha_2=entry.actor_location.country_code
                    )
                    log_event["actor.geo.country.name"] = country.name
                except Exception as e:
                    self.log.warning(
                        f"Unable to map country: {entry.actor_location.country_code}"
                    )
            log_events.append(log_event)

        return log_events

    def get_audit_logs(
        self,
        from_time: datetime,
        to_time: datetime,
        enterprise: Optional[str] = None,
        organization: Optional[str] = None,
    ) -> PaginatedList[AuditLogEntry]:
        phrase = f"created:{from_time.strftime(TIME_FORMAT)}..{to_time.strftime(TIME_FORMAT)}"
        if enterprise:
            return PaginatedList(
                AuditLogEntry,
                self.http_client,
                f"enterprises/{enterprise}/audit-log",
                target_params=({"per_page": DEFAULT_PAGE_SIZE, "phrase": {phrase}}),
            )
        elif organization:
            return PaginatedList(
                AuditLogEntry,
                self.http_client,
                f"organizations/{organization}/audit-log",
                target_params=({"per_page": DEFAULT_PAGE_SIZE, "phrase": {phrase}}),
            )
        else:
            return []

    def get_secret_alerts(self, oldest_allowed: datetime, severity_level: str = "HIGH"):
        security_events: List[Dict] = []
        if self.app_installations:
            for installation in self.app_installations:
                for repository in installation.repositories:
                    if not self.repository_filters or self.repo_is_included(
                        repository.full_name
                    ):
                        try:
                            repo_events = self.prepare_secret_alerts(
                                repository=repository.full_name,
                                from_time=oldest_allowed,
                                installation=installation,
                                severity_level=severity_level,
                            )
                            security_events.extend(repo_events)
                        except Exception as e:
                            self.log.exception(
                                f"Unable to get secret alerts for repository {repository.full_name}: {e}"
                            )
        else:
            for repository in self.get_repositories():
                if not self.repository_filters or self.repo_is_included(
                    repository.full_name
                ):
                    try:
                        repo_events = self.prepare_secret_alerts(
                            repository=repository.full_name,
                            from_time=oldest_allowed,
                            severity_level=severity_level,
                        )
                        security_events.extend(repo_events)
                    except Exception as e:
                        self.log.exception(
                            f"Unable to get secret alerts for repository {repository.full_name}: {e}"
                        )
        return security_events

    def prepare_secret_alerts(
        self,
        repository: str,
        from_time: datetime,
        installation: Optional[AppInstallation] = None,
        severity_level: str = "HIGH",
    ):

        security_events = []

        # would be nice to use scan-history but it's availability is
        # not guaranteed. Many config aspects/repo characteristics can
        # prevent it from being available. It would only be used to
        # decide whether to check for secret alerts.

        scans: dict[str, dict] = {}  # stores scans 'inferred' from findings

        # 'generic' types must be filtered for explicitly
        # meaning we have to break collection up into 2 calls.

        alerts: list[SecretScanningAlert] = []
        generic_secret_types = [
            "http_basic_authentication_header",
            "http_bearer_authentication_header",
            "mongodb_connection_string",
            "mysql_connection_string",
            "openssh_private_key",
            "pgp_private_key",
            "postgres_connection_string",
            "rsa_private_key",
        ]

        generic_alerts: list[SecretScanningAlert] = PaginatedList(
            SecretScanningAlert,
            installation.http_client if installation else self.http_client,
            f"repos/{repository}/secret-scanning/alerts",
            target_params=(
                {
                    "per_page": DEFAULT_PAGE_SIZE,
                    "state": "open",
                    "sort": "updated",
                    "hide_secret": "true",
                    "secret_type": ",".join(generic_secret_types),
                }
            ),
            time_field="updated_at",
            oldest_allowed=from_time,
        )
        for alert in generic_alerts:
            alerts.append(alert)

        default_alerts: list[SecretScanningAlert] = PaginatedList(
            SecretScanningAlert,
            installation.http_client if installation else self.http_client,
            f"repos/{repository}/secret-scanning/alerts",
            target_params=(
                {
                    "per_page": DEFAULT_PAGE_SIZE,
                    "state": "open",
                    "sort": "updated",
                    "hide_secret": "true",
                }
            ),
            time_field="updated_at",
            oldest_allowed=from_time,
        )
        for alert in default_alerts:
            alerts.append(alert)

        for alert in alerts:
            eval_time = alert.updated_at if alert.updated_at else alert.created_at
            if eval_time >= from_time:

                secret_alert_payload_base = {
                    "event.kind": "SECURITY_EVENT",
                    "event.type": "VULNERABILITY_FINDING",
                    "event.category": "VULNERABILITY_MANAGEMENT",
                    "event.original_content": alert.original_content,
                    "event.version": SCHEMA_VERSION,
                    "event.provider": EVENT_SOURCE,
                    "component.name": repository,
                    "finding.type": "EXPOSED_SECRET",
                    "finding.time.created": alert.created_at.isoformat(),
                    "finding.url": alert.html_url,
                    "finding.id": alert.html_url,
                    "finding.tags": (
                        ["publicly_leaked"] if alert.publicly_leaked else []
                    ),
                    "github.secret.type": alert.secret_type,
                    "github.secret.validity": alert.validity,
                    "github.secret.publicly_leaked": alert.publicly_leaked,
                    "product.name": "Secret scanning",
                    "product.vendor": "GitHub",
                    "vulnerability.id": "CWE-798",
                    "vulnerability.title": "CWE-798: Use of Hard-coded Credentials",
                    "vulnerability.description": "The product contains hard-coded credentials, such as a password or cryptographic key.",
                    "vulnerability.references.cwe": ["CWE-798"],
                    "dt.security.risk.level": severity_level,
                    "dt.security.risk.score": self.map_risk_level_to_score(
                        severity_level
                    ),
                }

                locations: List[Location] = []
                if alert.has_more_locations:
                    additional_locations: list[AdditionalLocation] = PaginatedList(
                        AdditionalLocation,
                        installation.http_client if installation else self.http_client,
                        f"repos/{repository}/secret-scanning/alerts/{alert.number}/locations",
                        target_params=({"per_page": DEFAULT_PAGE_SIZE}),
                    )
                    locations = [location.location for location in additional_locations]
                else:
                    locations = [alert.first_location_detected]

                for location in locations:
                    object_type = (
                        "CODE_ARTIFACT"
                        if location.type == "commit"
                        else location.type.upper()
                    )
                    secret_alert_payload = deepcopy(secret_alert_payload_base)
                    secret_alert_payload.update(
                        {"event.id": str(uuid.uuid4()), "object.type": object_type}
                    )
                    if location.type == "commit":
                        object_identifier = f"{repository}/{location.path}"
                        secret_alert_payload.update(
                            {
                                "artifact.path": location.path,
                                "artifact.repository": repository,
                                "code.filepath": location.path,
                                "code.line.number": location.start_line,
                                "code.line.start": location.start_line,
                                "code.line.end": location.end_line,
                                "code.line.offset.start": location.start_column,
                                "code.line.offset.end": location.end_column,
                                "github.secret.location": location.path,
                                "finding.title": f"Exposed {alert.secret_type} found in {location.path}"
                            }
                        )
                    else:
                        object_identifier = f"{repository}/{location.type}"
                        shortened_location = location.url.rsplit("/repos/", maxsplit=1)[1]
                        secret_alert_payload.update(
                            {
                                "github.secret.location": location.url,
                                "finding.title": f"Exposed {alert.secret_type} found in {shortened_location}"
                            }
                        )
                    secret_alert_payload["object.name"] = object_identifier
                    secret_alert_payload["object.id"] = str(
                        uuid.uuid5(GHAS_NAMESPACE, object_identifier)
                    )
                    scan_id = str(
                        uuid.uuid5(
                            GHAS_NAMESPACE,
                            f"{eval_time}/{repository}/{object_identifier}",
                        )
                    )
                    scan_name = f"{eval_time}/{object_identifier}"
                    secret_alert_payload["scan.id"] = scan_id
                    secret_alert_payload["scan.name"] = scan_name
                    if not (object_identifier in scans):
                        scans.update(
                            {
                                object_identifier: {
                                    "event.type": "VULNERABILITY_SCAN",
                                    "event.id": str(uuid.uuid4()),
                                    "event.provider": EVENT_SOURCE,
                                    "event.version": SCHEMA_VERSION,
                                    "product.vendor": "GitHub",
                                    "product.name": "GitHub",
                                    "scan.id": scan_id,
                                    "scan.name": scan_name,
                                    "scan.time.completed": alert.updated_at.isoformat(),
                                    "object.type": object_type,
                                    "object.name": object_identifier,
                                    "object.id": str(
                                        uuid.uuid5(GHAS_NAMESPACE, object_identifier)
                                    ),
                                }
                            }
                        )
                        if location.type == "commit":
                            scans[object_identifier]["artifact.path"] = location.path
                            scans[object_identifier]["artifact.repository"] = repository

                    security_events.append(secret_alert_payload)

        security_events.extend([scans[x] for x in scans])

        return security_events

    def get_code_scanning_alerts(self, oldest_allowed: datetime):
        security_events: List[Dict] = []
        if self.app_installations:
            for installation in self.app_installations:
                for repository in installation.repositories:
                    if not self.repository_filters or self.repo_is_included(
                        repository.full_name
                    ):
                        try:
                            repo_events = self.prepare_code_scanning_alerts(
                                repository=repository.full_name,
                                from_time=oldest_allowed,
                                installation=installation,
                            )
                            security_events.extend(repo_events)
                        except Exception as e:
                            self.log.exception(
                                f"Unable to get code scanning alerts for repository {repository.full_name}: {e}"
                            )
        else:
            for repository in self.get_repositories():
                if not self.repository_filters or self.repo_is_included(
                    repository.full_name
                ):
                    try:
                        repo_events = self.prepare_code_scanning_alerts(
                            repository=repository.full_name, from_time=oldest_allowed
                        )
                        security_events.extend(repo_events)
                    except Exception as e:
                        self.log.exception(
                            f"Unable to get code scanning alerts for repository {repository.full_name}: {e}"
                        )
        return security_events

    def prepare_code_scanning_alerts(
        self,
        repository: str,
        from_time: datetime,
        installation: Optional[AppInstallation] = None,
    ):

        scan_templates = (
            {}
        )  # holds a scan body for each analysis - for each path we find a logical scan event will be reported
        reported_file_paths = (
            []
        )  # ensures we only report a scan for a given file path once
        security_events_to_report = []

        try:
            analyses: list[CodeScanAnalysis] = PaginatedList(
                CodeScanAnalysis,
                installation.http_client if installation else self.http_client,
                f"repos/{repository}/code-scanning/analyses",
                target_params=({"per_page": DEFAULT_PAGE_SIZE}),
                oldest_allowed=from_time,
                time_field="created_at",
            )
            for analysis in analyses:
                if analysis.created_at >= from_time:
                    analysis_identifier = f"{repository}/{analysis.analysis_key}{analysis.category}/{analysis.created_at}"
                    analysis_scan_payload = {
                        "event.kind": "SECURITY_EVENT",
                        "event.provider": EVENT_SOURCE,
                        "event.original_content": analysis.original_content,
                        "event.id": str(uuid.uuid4()),
                        "event.version": SCHEMA_VERSION,
                        "event.type": "VULNERABILITY_SCAN",
                        "scan.id": None,  # added when parsing alert
                        "scan.name": None,  # added when parsing alert
                        "scan.time.completed": analysis.created_at.isoformat(),
                        "product.name": analysis.tool.name,
                        "product.vendor": (
                            "GitHub"
                            if analysis.tool.name == "CodeQL"
                            else analysis.tool.name
                        ),
                        "object.id": None,  # added when parsing alert
                        "object.name": None,  # added when parsing alert
                        "code.filepath": None,  # added when parsing alert
                        "object.type": "CODE_ARTIFACT",
                    }

                    scan_templates.update({analysis_identifier: analysis_scan_payload})

            if len(scan_templates) == 0:
                self.log.info(
                    f"No analyses for {repository} occurred in window. Nothing to report."
                )
                return []

        except Exception as e:
            self.log.exception(f"Error getting scans for {repository}: {e}")

        alerts: List[CodeScanningAlert] = PaginatedList(
            CodeScanningAlert,
            installation.http_client if installation else self.http_client,
            f"repos/{repository}/code-scanning/alerts",
            target_params=(
                {"per_page": DEFAULT_PAGE_SIZE, "state": "open", "sort": "updated"}
            ),
        )

        for alert in alerts:
            eval_time = alert.updated_at if alert.updated_at else alert.created_at
            if eval_time >= from_time:

                risk_level, risk_score = (
                    self.determine_code_scanning_alert_risk_level_and_score(alert)
                )

                cwes: list[str] = []
                for tag in alert.rule.tags:
                    match: re.Match = re.search(r"\/(cwe-\d+)$", tag)
                    if match:
                        cwes.append(match.group(1).upper())

                analysis_identifier = f"{repository}/{alert.most_recent_instance.analysis_key}{alert.most_recent_instance.category}/{eval_time}"

                if (
                    f"{repository}/{alert.most_recent_instance.location.path}"
                    not in reported_file_paths
                ):
                    code_scan_payload = scan_templates.get(analysis_identifier)
                    code_scan_payload["scan.id"] = str(
                        uuid.uuid5(
                            GHAS_NAMESPACE,
                            f"{analysis_identifier}/{alert.most_recent_instance.location.path}",
                        )
                    )
                    code_scan_payload["scan.name"] = (
                        f"{eval_time}/{repository}/{alert.most_recent_instance.location.path}"
                    )
                    code_scan_payload["object.id"] = str(
                        uuid.uuid5(
                            GHAS_NAMESPACE,
                            f"{repository}/{alert.most_recent_instance.location.path}",
                        )
                    )
                    code_scan_payload["object.name"] = (
                        f"{repository}/{alert.most_recent_instance.location.path}"
                    )
                    code_scan_payload["code.filepath"] = (
                        alert.most_recent_instance.location.path
                    )
                    security_events_to_report.append(deepcopy(code_scan_payload))
                    reported_file_paths.append(
                        f"{repository}/{alert.most_recent_instance.location.path}"
                    )

                code_scan_alert_payload = {
                    "event.kind": "SECURITY_EVENT",
                    "event.provider": EVENT_SOURCE,
                    "event.original_content": alert.original_content,
                    "event.id": str(uuid.uuid4()),
                    "event.version": SCHEMA_VERSION,
                    "event.type": "VULNERABILITY_FINDING",
                    "event.category": "VULNERABILITY_MANAGEMENT",
                    "component.name": repository,
                    "object.id": str(
                        uuid.uuid5(
                            GHAS_NAMESPACE,
                            f"{repository}/{alert.most_recent_instance.location.path}",
                        )
                    ),
                    "object.type": "CODE_ARTIFACT",
                    "object.name": f"{repository}/{alert.most_recent_instance.location.path}",
                    "artifact.path": alert.most_recent_instance.location.path,
                    "artifact.repository": repository,
                    "vulnerability.id": alert.rule.id,
                    "vulnerability.title": f"{alert.rule.name}: {alert.rule.description}",
                    "vulnerability.references.cwe": cwes,
                    "vulnerability.remediation.description": alert.rule.help,
                    "dt.security.risk.level": risk_level,
                    "dt.security.risk.score": risk_score,
                    "finding.id": alert.html_url,
                    "finding.type": "CODE_VULNERABILITY",
                    "finding.title": f"{alert.rule.description} found in {alert.most_recent_instance.location.path}",
                    "finding.time.created": alert.created_at.isoformat(),
                    "finding.tags": alert.rule.tags,
                    "finding.url": alert.html_url,
                    "finding.severity": (
                        alert.rule.security_severity_level
                        if alert.rule.security_severity_level
                        else alert.rule.severity
                    ),
                    "product.name": alert.tool.name,
                    "product.vendor": (
                        "GitHub" if alert.tool.name == "CodeQL" else alert.tool.name
                    ),
                    "scan.id": str(
                        uuid.uuid5(
                            GHAS_NAMESPACE,
                            f"{analysis_identifier}/{alert.most_recent_instance.location.path}",
                        )
                    ),
                    "scan.name": f"{analysis_identifier}/{alert.most_recent_instance.location.path}",
                    "code.filepath": alert.most_recent_instance.location.path,
                    "code.line.number": alert.most_recent_instance.location.start_line,
                    "code.line.start": alert.most_recent_instance.location.start_line,
                    "code.line.end": alert.most_recent_instance.location.end_line,
                    "code.line.offset.start": alert.most_recent_instance.location.start_column,
                    "code.line.offset.end": alert.most_recent_instance.location.end_column,
                }

                security_events_to_report.append(code_scan_alert_payload)

        return security_events_to_report

    def get_dependabot_alerts(self, oldest_allowed: datetime):
        security_events: List[Dict] = []
        if self.app_installations:
            for installation in self.app_installations:
                for repository in installation.repositories:
                    if not self.repository_filters or self.repo_is_included(
                        repository.full_name
                    ):
                        try:
                            repo_events = self.prepare_dependabot_alerts(
                                repository=repository.full_name,
                                from_time=oldest_allowed,
                                installation=installation,
                            )
                            security_events.extend(repo_events)
                        except Exception as e:
                            self.log.error(
                                f"Unable to get security events for repository {repository.full_name}: {e}"
                            )
        else:
            for repository in self.get_repositories():
                if not self.repository_filters or self.repo_is_included(
                    repository.full_name
                ):
                    try:
                        repo_events = self.prepare_dependabot_alerts(
                            repository=repository.full_name, from_time=oldest_allowed
                        )
                        security_events.extend(repo_events)
                    except Exception as e:
                        self.log.error(
                            f"Unable to get security events for repository {repository.full_name}: {e}"
                        )
        return security_events

    def prepare_dependabot_alerts(
        self,
        repository: str,
        from_time: datetime,
        installation: Optional[AppInstallation] = None,
    ):
        scans: Dict[str, Dict] = {}  # stores scans 'inferred' from findings
        security_events_to_report = []

        alerts: List[DependabotAlert] = PaginatedList(
            DependabotAlert,
            installation.http_client if installation else self.http_client,
            f"repos/{repository}/dependabot/alerts",
            target_params=(
                {"per_page": DEFAULT_PAGE_SIZE, "state": "open", "sort": "updated"}
            ),
            time_field="updated_at",
            oldest_allowed=from_time,
        )

        for alert in alerts:
            if alert.updated_at >= from_time:
                repository_name = re.search(
                    r"repos\/(.+)(?=\/dependabot)", alert.url
                ).group(1)

                file_identifier = f"{repository_name}/{alert.dependency.manifest_path}"

                if file_identifier in scans:
                    # decide if need to update time
                    if alert.updated_at > datetime.fromisoformat(
                        scans[file_identifier]["scan.time.completed"]
                    ):
                        scans[file_identifier][
                            "scan.time.completed"
                        ] = alert.updated_at.isoformat()
                        scans[file_identifier]["scan.id"] = str(
                            uuid.uuid5(
                                GHAS_NAMESPACE,
                                f"{from_time}/{repository_name}/{alert.dependency.manifest_path}",
                            )
                        )
                        scans[file_identifier][
                            "scan.name"
                        ] = f"{from_time}/{repository_name}/{alert.dependency.manifest_path}"
                else:
                    # add scan payload
                    scans.update(
                        {
                            file_identifier: {
                                "event.type": "VULNERABILITY_SCAN",
                                "event.id": str(uuid.uuid4()),
                                "event.provider": EVENT_SOURCE,
                                "product.vendor": "GitHub",
                                "product.name": "Dependabot",
                                "scan.id": str(
                                    uuid.uuid5(
                                        GHAS_NAMESPACE,
                                        f"{from_time}/{repository_name}/{alert.dependency.manifest_path}",
                                    )
                                ),
                                "scan.name": f"{from_time}/{repository_name}/{alert.dependency.manifest_path}",
                                "scan.time.completed": alert.updated_at.isoformat(),
                                "object.id": file_identifier,
                                "object.type": "CODE_ARTIFACT",
                                "object.name": f"{repository_name}/{alert.dependency.manifest_path}",
                            }
                        }
                    )

                risk_level, risk_score, ui_score = (
                    self.determine_dependabot_risk_level_and_score(alert)
                )
                alert_payload = {
                    "scan.id": scans[file_identifier]["scan.id"],
                    "scan.name": scans[file_identifier]["scan.id"],
                    "artifact.repository": repository_name,
                    "artifact.path": f"{repository_name}/{alert.dependency.manifest_path}",
                    "event.kind": "SECURITY_EVENT",
                    "event.original_content": alert.original_content,
                    "event.id": str(uuid.uuid4()),
                    "event.version": SCHEMA_VERSION,
                    "event.provider": EVENT_SOURCE,
                    "event.type": "VULNERABILITY_FINDING",
                    "event.category": "VULNERABILITY_MANAGEMENT",
                    "event.name": "Vulnerability finding event",
                    "object.id": str(
                        uuid.uuid5(
                            GHAS_NAMESPACE,
                            f"{repository_name}/{alert.dependency.manifest_path}",
                        )
                    ),
                    "object.type": "CODE_ARTIFACT",
                    "object.name": f"{repository_name}/{alert.dependency.manifest_path}",
                    "vulnerability.id": alert.security_advisory.ghsa_id,
                    "vulnerability.title": alert.security_advisory.summary,
                    "vulnerability.description": alert.security_advisory.description,
                    "vulnerability.references.cve": (
                        [alert.security_advisory.cve_id]
                        if alert.security_advisory.cve_id
                        else None
                    ),
                    "vulnerability.references.cwe": [
                        cwe.cwe_id for cwe in alert.security_advisory.cwes
                    ],
                    "vulnerability.remediation.fix_versions": [
                        vuln.first_patched_version.identifier
                        for vuln in alert.security_advisory.vulnerabilities
                        if vuln.first_patched_version
                    ],
                    "vulnerability.remediation.description": f"Update {alert.security_vulnerability.package.name} ({alert.security_vulnerability.package.ecosystem}) to one of {[vuln.first_patched_version.identifier for vuln in alert.security_advisory.vulnerabilities if vuln.first_patched_version]}.",
                    "vulnerability.remediation.status": (
                        "AVAILABLE"
                        if alert.security_vulnerability.first_patched_version
                        else "NOT_AVAILABLE"
                    ),
                    "component.name": alert.security_vulnerability.package.name,
                    "component.version": alert.security_vulnerability.vulnerable_version_range,
                    "finding.id": alert.html_url,
                    "finding.type": "DEPENDENCY_VULNERABILITY",
                    "finding.title": f"{alert.security_advisory.summary} detected in {alert.dependency.manifest_path}",
                    "finding.time.created": alert.updated_at.isoformat(),
                    "finding.severity": alert.security_advisory.severity.upper(),
                    "finding.score": ui_score,
                    "finding.url": alert.html_url,
                    "dt.security.risk.level": risk_level,
                    "dt.security.risk.score": risk_score,
                    "product.name": "Dependabot",
                    "product.vendor": "GitHub",
                    "github.dependency.scope": alert.dependency.scope,
                    "github.dependency.relationship": alert.dependency.relationship,
                    "github.epss.percentage": (
                        alert.security_advisory.epss.percentage
                        if alert.security_advisory.epss
                        else None
                    ),
                    "github.epss.percentile": (
                        alert.security_advisory.epss.percentile
                        if alert.security_advisory.epss
                        else None
                    ),
                    "github.ecosystem": alert.dependency.package.ecosystem,
                }

                security_events_to_report.append(alert_payload)

        self.log.info(f"Ingesting scans and findings...")
        security_events_to_report.extend([scans[x] for x in scans])

        return security_events_to_report

    def determine_dependabot_risk_level_and_score(self, alert: DependabotAlert):
        risk_level = alert.security_advisory.severity.upper()
        risk_score = 0
        ui_score = 0  # what gets displayed in the GitHub UI for a GHSA

        # prioritize v4 over v3 score by checking for vector string (shows 0 if no score)
        if alert.security_advisory.cvss_severities.get("cvss_v4", {}).vector_string:
            risk_score = alert.security_advisory.cvss_severities["cvss_v4"].score
            ui_score = alert.security_advisory.cvss_severities["cvss_v4"].score
        elif alert.security_advisory.cvss_severities.get("cvss_v3", {}).vector_string:
            risk_score = alert.security_advisory.cvss_severities["cvss_v3"].score
            ui_score = alert.security_advisory.cvss_severities["cvss_v3"].score

        # if available score doesn't align with the reported severity override the score
        if (
            (risk_level == "CRITICAL" and risk_score < 9.0)
            or (risk_level == "HIGH" and (risk_score < 7.0 or risk_score > 8.9))
            or (risk_level == "MEDIUM" and (risk_score < 4.0 or risk_score > 6.9))
            or (risk_level == "LOW" and (risk_score < 0.1 or risk_score > 3.9))
        ):
            risk_score = self.map_risk_level_to_score(risk_level)

        return risk_level, risk_score, ui_score

    def determine_code_scanning_alert_risk_level_and_score(
        self,
        code_alert: CodeScanningAlert,
    ):
        security_severity_level = code_alert.rule.security_severity_level
        severity = code_alert.rule.severity
        risk_level = None
        if security_severity_level:
            risk_level = security_severity_level.upper()
        else:
            if severity == "error":
                risk_level = "HIGH"
            elif severity == "warning":
                risk_level = "MEDIUM"
            elif severity == "note":
                risk_level = "LOW"

        risk_score = self.map_risk_level_to_score(risk_level)

        return risk_level, risk_score

    @staticmethod
    def map_risk_level_to_score(risk_level: str):
        if risk_level == "CRITICAL":
            risk_score = 10
        elif risk_level == "HIGH":
            risk_score = 8.9
        elif risk_level == "MEDIUM":
            risk_score = 6.9
        elif risk_level == "LOW":
            risk_score = 3.9
        else:
            risk_score = 0

        return risk_score
