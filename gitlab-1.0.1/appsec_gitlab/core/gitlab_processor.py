"""
GitLab REST and GraphQL API access for the extension.

``GitLabProcessor`` centralizes URL building, pagination, and security-relevant endpoints
(groups, projects, jobs, vulnerabilities, audit events, container registry).
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone

from dynatrace_extension.sdk.extension import extension_logger as logger

from ..clients.http_client import RestApiHandler
from ..utils.constants import GITLAB_FETCH_PAGE_SIZE, GITLAB_GRAPHQL_PAGE_SIZE
from ..utils.helpers import filter_groups
from ..utils.urlutil import gitlab_graphql_url, gitlab_rest_url, quote_path_segment

SECURITY_JOB_NAME_HINTS = (
    "dependency_scanning",
    "container_scanning",
)


def _filter_security_scan_jobs(jobs: list[dict], started_after: str) -> list[dict]:
    """Keep successful security-named jobs whose ``created_at`` is within the window."""
    filtered: list[dict] = []
    for job in jobs:
        raw_job_name = job.get("name")
        job_name = raw_job_name.lower() if isinstance(raw_job_name, str) else None
        created_at = job.get("created_at")
        if created_at and created_at < started_after:
            continue
        if isinstance(job_name, str) and any(hint in job_name for hint in SECURITY_JOB_NAME_HINTS):
            filtered.append(job)
    return filtered


class GitLabProcessor:
    """
    Facade for GitLab API operations used by polling and audit collection.

    Responsibility:
        Provide typed methods for each HTTP/GraphQL resource; hide pagination and path templates.
    """

    def __init__(self, base_url: str, interface: RestApiHandler) -> None:
        """
        Args:
            base_url: GitLab root URL (e.g. ``https://gitlab.com``).
            interface: Authenticated ``RestApiHandler`` (typically ``PRIVATE-TOKEN``).
        """
        self._base_url = base_url.rstrip("/")
        self._interface = interface

    def _iter_paginated_pages(
        self,
        url: str,
        params: dict | None = None,
    ) -> Iterator[list[dict]]:
        """
        Yield each page of JSON list results from a GitLab REST collection.

        Args:
            url: Full REST URL (including query params base).
            params: Query parameters; ``per_page`` defaulted from constants.

        Yields:
            Non-empty page rows; stops when a page is empty or there is no ``X-Next-Page``.
        """
        page = 1
        params = dict(params or {})
        params.setdefault("per_page", GITLAB_FETCH_PAGE_SIZE)
        while True:
            current_params = {**params, "page": page}
            logger.debug(f"Fetching page {page} from {url} with params {current_params}")
            response = self._interface.get_url(url, params=current_params)
            rows = response.json()
            if not rows:
                break
            yield rows
            next_page = response.headers.get("X-Next-Page")
            if not next_page:
                break
            page = int(next_page)

    def _fetch_paginated_results(
        self,
        url: str,
        params: dict | None = None,
    ) -> list[dict]:
        """
        Args:
            url: Full REST URL (including query params base).
            params: Query parameters; ``per_page`` defaulted from constants.

        Returns:
            All rows from all pages following ``X-Next-Page`` headers.
        """
        return [row for page in self._iter_paginated_pages(url, params) for row in page]

    def fetch_target_groups(
        self,
        all_groups: bool,
        group_filters: list[str],
    ) -> list[dict]:
        """
        Args:
            all_groups: If True, return every group the token can see (with ``member`` filter).
            group_filters: When ``all_groups`` is False, substring/path filters from activation.

        Returns:
            List of raw group dicts to iterate for projects and audits.
        """
        url = gitlab_rest_url(self._base_url, "groups")
        groups = self._fetch_paginated_results(url, params={"member": True})
        filtered = filter_groups(groups, all_groups, group_filters)
        logger.info(
            f"GitLab groups: {len(groups)} visible to token, {len(filtered)} after activation filter "
            f"(all_groups={all_groups})"
        )
        return filtered

    def list_group_projects(self, group_id: str | int) -> list[dict]:
        """
        Args:
            group_id: Numeric or string group id.

        Returns:
            Project dicts including subgroup projects.
        """
        url = gitlab_rest_url(self._base_url, "groups", group_id, "projects")
        return self._fetch_paginated_results(url, params={"include_subgroups": True})

    def iter_project_security_jobs_pages(
        self,
        project_id: int,
        first_time_fetch_window_days: int,
    ) -> Iterator[list[dict]]:
        """
        Yield batches of security-relevant jobs one API page at a time.

        Avoids holding every successful job for the project in memory at once; callers
        can persist each batch (e.g. ``JobDatabase.sync_jobs``) before fetching the next page.

        Args:
            project_id: GitLab project id.
            first_time_fetch_window_days: Only jobs with ``created_at`` after this window are kept.

        Yields:
            Lists of job dicts (possibly empty pages are skipped — only non-empty filtered batches).
        """
        started_after = (
            datetime.now(timezone.utc) - timedelta(days=first_time_fetch_window_days)
        ).isoformat()
        url = gitlab_rest_url(self._base_url, "projects", project_id, "jobs")
        list_params = {"scope[]": ["success"], "include_retried": False}
        total_raw = 0
        total_filtered = 0
        for page_rows in self._iter_paginated_pages(url, params=list_params):
            total_raw += len(page_rows)
            filtered = _filter_security_scan_jobs(page_rows, started_after)
            total_filtered += len(filtered)
            if filtered:
                yield filtered
        logger.debug(
            f"Project {project_id} jobs: {total_raw} total success jobs paged, {total_filtered} "
            f"security-named in {first_time_fetch_window_days}-day window"
        )

    def list_project_registry_repositories(
        self,
        project_id: int | str,
    ) -> list[dict]:
        """
        Args:
            project_id: GitLab project id.

        Returns:
            Registry repository metadata dicts for digest resolution.
        """
        url = gitlab_rest_url(self._base_url, "projects", project_id, "registry", "repositories")
        return self._fetch_paginated_results(url)

    def fetch_registry_tag_detail(
        self,
        project_id: int | str,
        repository_id: int | str,
        tag_name: str,
    ) -> dict:
        """
        Args:
            project_id: GitLab project id.
            repository_id: Registry repository id.
            tag_name: Image tag to resolve.

        Returns:
            Tag detail JSON (includes ``digest`` when available).
        """
        url = gitlab_rest_url(
            self._base_url,
            "projects",
            project_id,
            "registry",
            "repositories",
            repository_id,
            "tags",
            quote_path_segment(tag_name),
        )
        response = self._interface.get_url(url)
        return response.json()

    def fetch_pipeline(self, project_id: int, pipeline_id: int) -> dict:
        """
        Args:
            project_id: GitLab project id.
            pipeline_id: Pipeline database id from the job payload.

        Returns:
            Raw pipeline dict.
        """
        url = gitlab_rest_url(self._base_url, "projects", project_id, "pipelines", pipeline_id)
        response = self._interface.get_url(url)
        return response.json()

    def list_group_audit_events(
        self,
        group_id: int | str,
        created_after: str,
    ) -> list[dict]:
        """
        Args:
            group_id: GitLab group id.
            created_after: ISO8601 lower bound (API ``created_after``).

        Returns:
            Raw audit event dicts (paginated internally).
        """
        params: dict = {"member": True}
        if created_after:
            params["created_after"] = created_after
        url = gitlab_rest_url(self._base_url, "groups", group_id, "audit_events")
        return self._fetch_paginated_results(url, params=params)

    def list_project_audit_events(
        self,
        project_id: int | str,
        created_after: str,
    ) -> list[dict]:
        """
        Args:
            project_id: GitLab project id.
            created_after: ISO8601 lower bound for the query.

        Returns:
            Raw audit event dicts (paginated internally).
        """
        params: dict = {"member": True}
        if created_after:
            params["created_after"] = created_after
        url = gitlab_rest_url(self._base_url, "projects", project_id, "audit_events")
        return self._fetch_paginated_results(url, params=params)

    def fetch_project_vulnerabilities(self, project_full_path: str) -> list[dict]:
        """
        Args:
            project_full_path: Project path with namespace (GraphQL ``fullPath``).

        Returns:
            All vulnerability nodes for the project (paginated).
        """
        query = f"""
    query ProjectVulnerabilities($projectPath: ID!, $after: String) {{
      project(fullPath: $projectPath) {{
        vulnerabilities(first: {GITLAB_GRAPHQL_PAGE_SIZE}, after: $after) {{
          pageInfo {{
            hasNextPage
            endCursor
          }}
          nodes {{
            id
            uuid
            reportType
            title
            severity
            description
            solution
            state
            falsePositive
            scanner {{
              externalId
              name
              vendor
            }}
            identifiers {{
              externalType
              externalId
              name
              url
            }}
            location {{
              ... on VulnerabilityLocationDependencyScanning {{
                file
                dependency {{
                  package {{
                    name
                  }}
                  version
                }}
              }}
              ... on VulnerabilityLocationContainerScanning {{
                image
                operatingSystem
                dependency {{
                  package {{
                    name
                  }}
                  version
                }}
              }}
            }}
            links {{
              url
              name
            }}
            project {{
              id
              name
              fullPath
            }}
          }}
        }}
      }}
    }}
    """
        graphql_url = gitlab_graphql_url(self._base_url)
        vulnerabilities: list[dict] = []
        after = None
        page_idx = 0
        while True:
            data = self._interface.graphql(
                graphql_url,
                query,
                variables={"projectPath": project_full_path, "after": after},
            )
            connection = (((data.get("project") or {}).get("vulnerabilities")) or {})
            nodes = connection.get("nodes", [])
            vulnerabilities.extend(nodes)
            page_idx += 1
            logger.debug(
                f"GraphQL vulnerabilities page {page_idx} for {project_full_path}: "
                f"+{len(nodes)} rows (total {len(vulnerabilities)})"
            )
            page_info = connection.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                break
            after = page_info.get("endCursor")
            if not after:
                break
        logger.debug(f"Fetched {len(vulnerabilities)} vulnerability record(s) for project {project_full_path}")
        return vulnerabilities

    def fetch_pipeline_security_findings(
        self,
        project_full_path: str,
        pipeline_iid: int | str,
    ) -> list[dict]:
        """
        Args:
            project_full_path: Project path with namespace.
            pipeline_iid: Pipeline internal id (``iid``).

        Returns:
            Security report finding nodes for that pipeline (paginated).
        """
        query = f"""
    query PipelineSecurityFindings($projectPath: ID!, $pipelineIid: ID!, $after: String) {{
      project(fullPath: $projectPath) {{
        pipeline(iid: $pipelineIid) {{
          securityReportFindings(first: {GITLAB_GRAPHQL_PAGE_SIZE}, after: $after) {{
            pageInfo {{
              hasNextPage
              endCursor
            }}
            nodes {{
              uuid
              title
              description
              severity
              state
              reportType
              solution
              falsePositive
              identifiers {{
                externalType
                name
                externalId
                url
              }}
              scanner {{
                externalId
                name
                vendor
              }}
              location {{
                __typename
                ... on VulnerabilityLocationSast {{
                  file
                  startLine
                  endLine
                  vulnerableClass
                  vulnerableMethod
                  blobPath
                }}
                ... on VulnerabilityLocationDependencyScanning {{
                  file
                  blobPath
                  dependency {{
                    package {{
                      name
                    }}
                    version
                  }}
                }}
                ... on VulnerabilityLocationDast {{
                  path
                }}
                ... on VulnerabilityLocationContainerScanning {{
                  image
                  operatingSystem
                  dependency {{
                    package {{
                      name
                    }}
                    version
                  }}
                }}
              }}
              remediations {{
                diff
                summary
              }}
            }}
          }}
        }}
      }}
    }}
    """
        graphql_url = gitlab_graphql_url(self._base_url)
        findings: list[dict] = []
        after = None
        page_idx = 0
        while True:
            data = self._interface.graphql(
                graphql_url,
                query,
                variables={
                    "projectPath": project_full_path,
                    "pipelineIid": str(pipeline_iid),
                    "after": after,
                },
            )
            connection = (
                (((data.get("project") or {}).get("pipeline") or {}).get("securityReportFindings"))
                or {}
            )
            nodes = connection.get("nodes", [])
            findings.extend(nodes)
            page_idx += 1
            logger.debug(
                f"GraphQL pipeline findings page {page_idx} for {project_full_path} pipeline {pipeline_iid}: "
                f"+{len(nodes)} rows (total {len(findings)})"
            )
            page_info = connection.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                break
            after = page_info.get("endCursor")
            if not after:
                break
        logger.debug(
            f"Fetched {len(findings)} pipeline security finding(s) for {project_full_path} pipeline {pipeline_iid}"
        )
        return findings
