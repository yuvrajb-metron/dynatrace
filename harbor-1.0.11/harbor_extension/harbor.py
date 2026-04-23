import logging
from typing import List, Optional
import logging
from datetime import datetime
from functools import lru_cache
import urllib
import urllib.parse

from .pagination import PaginatedList
from .artifact import Artifact
from .vulnerability import Vulnerability
from .project import Project
from .repository import Repository
from .audit_log import AuditLogEntry
from .http_client import HttpClient
from .shared import datetime_to_harbor_timestamp

log = logging.getLogger(__name__)

DEFAULT_PAGE_SIZE = 100


class Harbor:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        proxies: Optional[dict],
        verify: bool = True,
        log=log,
    ):

        self.log = log

        if not verify:
            self.log.warning(
                f"Certifcate validation has been disabled in the configuration, to avoid log congestion insecure request warnings are suppressed."
            )

        url_parse_result = urllib.parse.urlparse(host)
        if not url_parse_result.scheme and url_parse_result.netloc:
            raise Exception(f"'{host}' is not a valid URL")
        if url_parse_result.scheme != "https":
            raise Exception(
                f"Non-HTTPS protocol being used. This is insecure and will result in clear-text credentials on the network. Switch to an HTTPS endpoint."
            )
        else:
            processed_host = f"{url_parse_result.scheme}://{url_parse_result.netloc}"

        self.http_client: HttpClient = HttpClient(
            host=processed_host,
            username=username,
            password=password,
            proxies=proxies,
            verify=verify,
            log=log,
        )

    @lru_cache
    def initialize(self):
        system_info = self.http_client.make_request("/systeminfo").json()
        self.registry_url: str = system_info.get("registry_url")
        self.harbor_version: str = system_info.get("harbor_version")
        self.external_url: str = system_info.get("external_url")

    def get_repositories(
        self, project: Optional[str] = None
    ) -> PaginatedList[Repository]:
        if project:
            return PaginatedList(
                Repository,
                self.http_client,
                f"/projects/{project}/repositories",
                target_params={"page_size": DEFAULT_PAGE_SIZE},
            )
        else:
            return PaginatedList(
                Repository,
                self.http_client,
                "/repositories",
                target_params={"page_size": DEFAULT_PAGE_SIZE},
            )

    def get_projects(self) -> PaginatedList[Project]:
        return PaginatedList(
            Project,
            self.http_client,
            "/projects",
            target_params={"page_size": DEFAULT_PAGE_SIZE},
        )

    def lookup_project(self, project_id: int):
        return Artifact._create_from_raw_data(
            self.http_client.make_request(f"/projects/{project_id}")
        )

    def get_artifacts(
        self, project: str = None, repository: str = None
    ) -> PaginatedList[Artifact]:
        return PaginatedList(
            Artifact,
            self.http_client,
            f"/projects/{project}/repositories/{urllib.parse.quote_plus(repository)}/artifacts",
            target_params={"page_size": DEFAULT_PAGE_SIZE, "with_scan_overview": True},
            headers={
                "X-Accept-Vulnerabilities": "application/vnd.security.vulnerability.report; version=1.1, application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
            },
        )

    def get_vulnerabilities(self, artifacts: list[str]) -> PaginatedList[Vulnerability]:
        vulns: List[Vulnerability] = []
        for artifact in artifacts:
            vulns.extend(
                PaginatedList(
                    Vulnerability,
                    self.http_client,
                    f"/security/vul",
                    target_params={
                        "page_size": DEFAULT_PAGE_SIZE,
                        "q": f"digest={artifact}",
                    },
                )
            )
        return vulns

    def get_audit_logs(
        self, from_time: datetime, to_time: datetime
    ) -> PaginatedList[AuditLogEntry]:
        from_time = datetime_to_harbor_timestamp(from_time)
        to_time = datetime_to_harbor_timestamp(to_time)
        self.log.info(f"Querying logs from {from_time} to {to_time}.")
        return PaginatedList(
            AuditLogEntry,
            self.http_client,
            f"/audit-logs",
            target_params={"q": f"op_time=[{from_time}~{to_time}]"},
        )

    def ping(self):
        try:
            resp = self.http_client.make_request("/ping")
            resp.raise_for_status()
            if resp.text == "Pong":
                return True
            else:
                return False
        except Exception as e:
            self.log.exception(f"Error checking API health status: {e}")
            return False
