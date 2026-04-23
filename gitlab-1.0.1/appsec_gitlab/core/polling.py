"""
GitLab polling and event assembly for security scans and audit logs.

**Security pipeline**
    Discover groups/projects, list new CI jobs (filtered by name and time window),
    persist processed job IDs in ``JobDatabase``, merge pipeline findings with project
    vulnerabilities, build ``RepositoryScan`` / ``VulnerabilityDetails`` models, emit
    flat Dynatrace security event dicts, and POST them via ``ingest.push_security_events_to_dynatrace``.
    When both dependency and container collection are enabled, jobs are partitioned by
    name hint (``dependency_scanning`` / ``container_scanning``); dependency jobs and their
    findings are processed first with ``enabled_report_types`` scoped to dependency only,
    then container jobs with scope limited to container — so objects and merge logic do
    not mix across scan kinds.
    Per-group results are appended to a ``MultiStatus`` for the extension scheduler.

**Audit pipeline**
    Fetch group and project audit events newer than the caller-supplied ISO8601
    ``created_after`` (extension implements an incremental cursor via ``last_log_time``),
    map each row through ``AuditLogDetails`` and ``build_audit_log_event``, and return
    log dicts for ``Extension.report_log_event``.
"""

from __future__ import annotations

from dynatrace_extension import StatusValue
from dynatrace_extension.sdk.extension import extension_logger as logger
from dynatrace_extension.sdk.status import MultiStatus

from .gitlab_processor import GitLabProcessor
from ..events import SecurityEventsForIngestBuilder, build_audit_log_event
from ..ingest import push_security_events_to_dynatrace
from ..models import AuditLogDetails, RepositoryScan, VulnerabilityDetails
from ..storage import JobDatabase
from ..utils.helpers import filter_projects, split_container_image
from .scan_pipeline import (
    ReportTypeActivationScope,
    infer_job_report_type,
    partition_security_jobs_by_report_type,
)


def _optional_nonempty_str(value: object) -> str | None:
    if isinstance(value, str):
        normalized = value.strip()
        return normalized or None
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _optional_upper_str(value: object) -> str | None:
    normalized = _optional_nonempty_str(value)
    return normalized.upper() if normalized else None


def fetch_new_security_jobs(client: GitLabProcessor, group: dict, project: dict, first_time_fetch_window_days: int) -> list[dict]:
    """
    Return security-relevant GitLab jobs that have not been ingested yet.

    Jobs are fetched one GitLab API page at a time and each page is passed to
    ``JobDatabase.sync_jobs`` before the next page is requested, limiting peak memory.

    Args:
        client: GitLab API processor.
        group: Raw GitLab group dict (for job history keying).
        project: Raw GitLab project dict.
        first_time_fetch_window_days: Passed through to job listing (recent jobs only).

    Returns:
        List of raw job dicts that are new relative to ``JobDatabase``; persisted
        inside this call.
    """
    group_name = group.get("full_path") or group.get("name") or str(group.get("id"))
    project_path = project.get("path_with_namespace") or project.get("name") or str(project.get("id"))
    new_jobs: list[dict] = []
    with JobDatabase() as database:
        for batch in client.iter_project_security_jobs_pages(project["id"], first_time_fetch_window_days):
            new_jobs.extend(database.sync_jobs(batch, group_name=group_name, project_path=project_path))
    return new_jobs


def _merge_vulnerability_into_finding(finding: dict, vulnerability: dict) -> dict:
    """
    Merge GraphQL pipeline finding with the richer project vulnerability node.

    Args:
        finding: Security report finding node (pipeline-scoped).
        vulnerability: Project vulnerability node keyed by the same ``uuid``.

    Returns:
        Shallow copy of ``finding`` with non-empty keys from ``vulnerability`` applied.
    """
    merged = dict(finding)
    for key, value in vulnerability.items():
        if value not in (None, "", [], {}):
            merged[key] = value
    return merged


def fetch_and_merge_pipeline_findings(
    client: GitLabProcessor,
    project: dict,
    pipeline: dict,
    job_report_type: str | None,
    enabled_report_types: set[str],
) -> list[dict]:
    """
    Load findings for one pipeline and enrich them from the project vulnerability list.

    Args:
        client: GitLab API processor.
        project: Project dict (must include ``path_with_namespace``).
        pipeline: Pipeline dict (uses ``iid`` or ``id``).
        job_report_type: If set, require findings to match this report type (from job name).
        enabled_report_types: Allowed ``reportType`` values from activation (uppercase set).

    Returns:
        List of merged finding dicts that passed filters and have a matching vulnerability.
    """
    project_path = project.get("path_with_namespace")
    pipeline_id = pipeline.get("iid") or pipeline.get("id")
    findings = client.fetch_pipeline_security_findings(project_path, pipeline_id)
    vulnerabilities = client.fetch_project_vulnerabilities(project_path)
    vulnerabilities_by_uuid = {
        uuid: item
        for item in vulnerabilities
        if (uuid := _optional_nonempty_str(item.get("uuid")))
    }
    matched_findings: list[dict] = []
    for finding in findings:
        finding_report_type = _optional_upper_str(
            finding.get("reportType") or finding.get("report_type")
        )
        if enabled_report_types and finding_report_type not in enabled_report_types:
            continue
        if job_report_type and finding_report_type != job_report_type:
            continue
        finding_uuid = _optional_nonempty_str(finding.get("uuid"))
        if not finding_uuid:
            continue
        vulnerability = vulnerabilities_by_uuid.get(finding_uuid)
        if vulnerability:
            matched_findings.append(_merge_vulnerability_into_finding(finding, vulnerability))
    return matched_findings


def _find_registry_repository_for_image(
    repositories: list[dict],
    registry: str | None,
    repository: str,
    project_path_with_namespace: str | None,
) -> dict | None:
    """
    Find a container registry repository record for an image reference.

    Args:
        repositories: Output of ``list_project_registry_repositories``.
        registry: Optional registry host from the finding location.
        repository: Repository path component from the finding location.
        project_path_with_namespace: Used to strip project prefix when matching by name.

    Returns:
        Matching repository dict, or ``None``.
    """
    expected_location = f"{registry}/{repository}" if registry else repository
    repository_name_without_project = (
        repository.removeprefix(f"{project_path_with_namespace}/") if project_path_with_namespace else repository
    )
    for repo in repositories:
        if str(repo.get("location") or "") == expected_location:
            return repo
        if str(repo.get("path") or "") == repository:
            return repo
        if str(repo.get("name") or "") == repository_name_without_project:
            return repo
    return None


def _resolve_container_metadata_for_one_finding(
    client: GitLabProcessor,
    project: dict,
    finding: dict,
    repositories: list[dict],
    tag_cache: dict[tuple[int | str, str], dict],
) -> dict:
    """
    Resolve digest and tag metadata for one container-scanning finding.

    Args:
        client: GitLab API processor.
        project: Project dict.
        finding: Raw finding dict (uses ``location`` and ``uuid``).
        repositories: Registry repositories for the project.
        tag_cache: Mutable cache ``(repository_id, tag) -> tag detail dict`` to avoid duplicate API calls.

    Returns:
        Dict with keys such as ``registry``, ``repository``, ``tags``, ``digest``,
        ``tag_detail`` (may be partial if the tag cannot be resolved).
    """
    location = finding.get("location") or {}
    image = _optional_nonempty_str(location.get("image"))
    finding_uuid = _optional_nonempty_str(finding.get("uuid"))
    if not image or not finding_uuid:
        return {}

    registry, repository, tags = split_container_image(location)
    tag_name = tags[0] if tags else None
    if not repository or not tag_name:
        return {"registry": registry, "repository": repository, "tags": tags}

    project_path = project.get("path_with_namespace")
    matching_repository = _find_registry_repository_for_image(
        repositories, registry, repository, project_path
    )

    tag_detail = None
    if matching_repository:
        cache_key = (matching_repository.get("id"), tag_name)
        if cache_key not in tag_cache:
            try:
                tag_cache[cache_key] = client.fetch_registry_tag_detail(
                    project["id"],
                    matching_repository["id"],
                    tag_name,
                )
            except Exception as error:
                project_ref = project.get("path_with_namespace") or project.get("name")
                expected_location = f"{registry}/{repository}" if registry else repository
                logger.warning(
                    f"Failed to fetch registry tag detail for project={project_ref} image={expected_location} tag={tag_name}: {error}"
                )
                tag_cache[cache_key] = {}
        tag_detail = tag_cache[cache_key]

    return {
        "registry": registry,
        "repository": repository,
        "tags": tags,
        "digest": (tag_detail or {}).get("digest"),
        "tag_detail": tag_detail or {},
    }


def fetch_container_metadata_for_findings(client: GitLabProcessor, project: dict, matched_findings: list[dict]) -> dict[str, dict]:
    """
    Build a map ``finding_uuid -> container metadata`` for container scan findings.

    Args:
        client: GitLab API processor.
        project: Project dict.
        matched_findings: Merged findings list (only ``CONTAINER_SCANNING`` entries are used).

    Returns:
        Empty dict if none apply or registry listing fails; otherwise UUID-keyed metadata dicts.
    """
    container_findings = [
        finding for finding in matched_findings
        if _optional_upper_str(finding.get("reportType") or finding.get("report_type")) == "CONTAINER_SCANNING"
    ]
    if not container_findings:
        return {}

    try:
        repositories = client.list_project_registry_repositories(project["id"])
    except Exception as error:
        project_ref = project.get("path_with_namespace") or project.get("name")
        logger.warning(f"Failed to list registry repositories for project={project_ref}: {error}")
        return {}

    metadata_by_uuid: dict[str, dict] = {}
    tag_cache: dict[tuple[int | str, str], dict] = {}

    for finding in container_findings:
        finding_uuid = _optional_nonempty_str(finding.get("uuid"))
        if not finding_uuid:
            continue
        metadata = _resolve_container_metadata_for_one_finding(
            client, project, finding, repositories, tag_cache
        )
        if metadata:
            metadata_by_uuid[finding_uuid] = metadata

    return metadata_by_uuid


def _build_vulnerability_details_from_findings(
    client: GitLabProcessor,
    group: dict,
    project: dict,
    job: dict,
    pipeline: dict,
    matched_findings: list[dict],
) -> list[VulnerabilityDetails]:
    """
    Instantiate ``VulnerabilityDetails`` for each merged finding that maps cleanly.

    Args:
        client, group, project, job, pipeline: API context for the model.
        matched_findings: Output of ``fetch_and_merge_pipeline_findings``.

    Returns:
        List of models with ``has_required_mapping_values()`` true; others are skipped with a log line.
    """
    vulnerability_details_list: list[VulnerabilityDetails] = []
    container_image_metadata_by_uuid = fetch_container_metadata_for_findings(client, project, matched_findings)
    for finding in matched_findings:
        details = VulnerabilityDetails(
            group,
            project,
            job,
            pipeline,
            finding,
            container_image_metadata=container_image_metadata_by_uuid.get(
                _optional_nonempty_str(finding.get("uuid"))
            )
            or {},
        )
        if details.has_required_mapping_values():
            vulnerability_details_list.append(details)
        else:
            group_ref = group.get("full_path") or group.get("name")
            project_ref = project.get("path_with_namespace") or project.get("name")
            logger.debug(
                f"Skipping finding for group={group_ref} project={project_ref} job={job.get('id')}: "
                "required mapped values missing"
            )
    return vulnerability_details_list


def build_job_models(
    client: GitLabProcessor,
    group: dict,
    project: dict,
    job: dict,
    enabled_report_types: set[str],
) -> tuple[RepositoryScan | None, list[VulnerabilityDetails]]:
    """
    Build domain models for a single CI job (scan + findings), without Dynatrace payloads.

    Args:
        client: GitLab API processor.
        group, project: Scope dicts.
        job: Raw job dict (must reference a pipeline).
        enabled_report_types: Allowed report types from activation.

    Returns:
        ``(RepositoryScan | None, list[VulnerabilityDetails])``. ``(None, [])`` if the
        job is skipped, filtered out, or an exception occurs while building models.
    """
    try:
        job_report_type = infer_job_report_type(job)
        if enabled_report_types and job_report_type and job_report_type not in enabled_report_types:
            logger.debug(
                f"Skipping job {job.get('id')}: report type {job_report_type} not enabled for this phase"
            )
            return (None, [])

        pipeline_id = (job.get("pipeline") or {}).get("id")
        if not pipeline_id:
            logger.debug(f"Skipping job {job.get('id')}: no pipeline reference")
            return (None, [])
        pipeline = client.fetch_pipeline(project["id"], pipeline_id)

        repository_scan = RepositoryScan(group, project, job, pipeline)
        matched_findings = fetch_and_merge_pipeline_findings(
            client, project, pipeline, job_report_type, enabled_report_types
        )
        vulnerability_details_list = _build_vulnerability_details_from_findings(
            client, group, project, job, pipeline, matched_findings
        )

        return (repository_scan, vulnerability_details_list)
    except Exception as error:
        group_ref = group.get("full_path") or group.get("name")
        project_ref = project.get("path_with_namespace") or project.get("name")
        logger.error(f"Failed to build models for group={group_ref} project={project_ref} job={job.get('id')}: {error}", exc_info=True)
        return (None, [])


def _collect_events_for_jobs(
    client: GitLabProcessor,
    group: dict,
    project: dict,
    jobs: list[dict],
    scoped_enabled_report_types: set[str],
    phase_label: str,
) -> list[dict]:
    """
    Run ``build_job_models`` + ``SecurityEventsForIngestBuilder`` for each job with a scoped
    ``enabled_report_types`` set (single scan kind per phase).
    """
    project_name = project.get("path_with_namespace") or project.get("name")
    project_events: list[dict] = []
    for job in jobs:
        try:
            repository_scan, vulnerability_details_list = build_job_models(
                client, group, project, job, scoped_enabled_report_types
            )
            if repository_scan is None and not vulnerability_details_list:
                continue
            events = SecurityEventsForIngestBuilder(repository_scan, vulnerability_details_list).build()
            group_ref = group.get("full_path") or group.get("name")
            logger.debug(
                f"Built {len(events)} events for group={group_ref} project={project_name} "
                f"job={job.get('id')} ({phase_label})"
            )
            project_events.extend(events)
        except Exception as error:
            group_ref = group.get("full_path") or group.get("name")
            logger.error(
                f"Failed to build events for group={group_ref} project={project_name} job={job.get('id')} ({phase_label}): {error}",
                exc_info=True,
            )
    return project_events


def collect_project_events(
    client: GitLabProcessor,
    group: dict,
    project: dict,
    enabled_report_types: set[str],
    first_time_fetch_window_days: int,
) -> list[dict]:
    """
    Produce all Dynatrace security event dicts for one project in one poll cycle.

    New jobs are partitioned by CI job name (``dependency_scanning`` vs ``container_scanning``).
    If both toggles are on, dependency jobs are processed first with ``enabled_report_types``
    intersected with ``DEPENDENCY_SCANNING`` only, then container jobs with scope limited to
    ``CONTAINER_SCANNING``. Jobs whose names cannot be classified are processed last with the
    full ``enabled_report_types`` set (same as pre-partition behavior).

    Args:
        client: GitLab API processor.
        group, project: Scope dicts.
        enabled_report_types: Allowed report types (from activation toggles).
        first_time_fetch_window_days: Job listing window.

    Returns:
        Flat list of ingest-ready dicts (scan + findings), possibly empty. Order: all dependency
        job events for this poll, then all container job events, then any unclassified jobs.
    """
    project_name = project.get("path_with_namespace") or project.get("name")
    new_jobs = fetch_new_security_jobs(client, group, project, first_time_fetch_window_days)
    logger.debug(f"Found {len(new_jobs)} new security job(s) for project {project_name}")
    dependency_jobs, container_jobs, unknown_jobs = partition_security_jobs_by_report_type(new_jobs)
    scope = ReportTypeActivationScope.from_set(enabled_report_types)

    project_events: list[dict] = []

    if scope.run_dependency_phase():
        project_events.extend(
            _collect_events_for_jobs(
                client,
                group,
                project,
                dependency_jobs,
                scope.scope_for_dependency_phase(),
                "dependency scan",
            )
        )

    if scope.run_container_phase():
        project_events.extend(
            _collect_events_for_jobs(
                client,
                group,
                project,
                container_jobs,
                scope.scope_for_container_phase(),
                "container scan",
            )
        )

    # Names that do not contain the template hints: keep legacy behavior (full toggle set,
    # no single-kind scoping) so custom security job names still emit events.
    if unknown_jobs:
        for job in unknown_jobs:
            logger.debug(
                f"Processing unclassified job {job.get('id')} (name={job.get('name')!r}) for project {project_name} "
                "with full enabled report types"
            )
        project_events.extend(
            _collect_events_for_jobs(
                client,
                group,
                project,
                unknown_jobs,
                set(enabled_report_types),
                "unclassified job",
            )
        )

    return project_events


def _convert_audit_events_to_ingest_payloads(
    raw_audit_events: list[dict],
    group: dict | None,
    project: dict | None,
) -> list[dict]:
    """
    Map raw GitLab audit API rows to Dynatrace log event dicts.

    Args:
        raw_audit_events: Items from ``groups/:id/audit_events`` or ``projects/:id/audit_events``.
        group: Group dict for context (always provided by callers).
        project: Project dict if the event is project-scoped, else ``None`` for group-only scope.

    Returns:
        List of payloads suitable for ``Extension.report_log_event`` (invalid rows omitted).
    """
    ingest_events: list[dict] = []
    for raw_event in raw_audit_events:
        audit_detail = AuditLogDetails(group=group, project=project, audit_log=raw_event)
        event_payload = build_audit_log_event(audit_detail)
        if event_payload is not None:
            ingest_events.append(event_payload)
    return ingest_events


def collect_group_audit_log_events(
    client: GitLabProcessor,
    group: dict,
    created_after: str,
) -> list[dict]:
    """
    Fetch audit events for a GitLab group and return log-ingest payloads.

    Args:
        client: GitLab API processor.
        group: Group dict (uses ``id``).
        created_after: ISO8601 lower bound for ``created_after`` query parameter.

    Returns:
        Log event dicts without ``gitlab.project.*`` keys (group scope only).
    """
    raw_audit_events = client.list_group_audit_events(group["id"], created_after)
    return _convert_audit_events_to_ingest_payloads(raw_audit_events, group, None)


def collect_project_audit_log_events(
    client: GitLabProcessor,
    group: dict,
    project: dict,
    created_after: str,
) -> list[dict]:
    """
    Fetch audit events for a GitLab project and return log-ingest payloads.

    Args:
        client: GitLab API processor.
        group: Parent group dict (for ``AuditLogDetails`` context).
        project: Project dict (uses ``id``).
        created_after: ISO8601 lower bound for the API.

    Returns:
        Log event dicts including ``gitlab.project.id`` / ``gitlab.project.name`` when mapped.
    """
    raw_audit_events = client.list_project_audit_events(project["id"], created_after)
    return _convert_audit_events_to_ingest_payloads(raw_audit_events, group, project)


def _collect_audit_events_for_single_group(
    client: GitLabProcessor,
    group: dict,
    created_after: str,
    all_projects: bool,
    selected_projects: list[str],
    cumulative_audit_events: list[dict],
) -> None:
    """
    Append group- and project-scoped audit payloads for one GitLab group to a shared list.

    Args:
        client: GitLab API processor.
        group: Group dict.
        created_after: ISO8601 audit time lower bound.
        all_projects: If false, restrict to ``selected_projects``.
        selected_projects: Path or name filters when ``all_projects`` is false.
        cumulative_audit_events: Output list extended in place.

    Returns:
        None.
    """
    group_name = group.get("full_path") or group.get("name") or group.get("id")

    try:
        cumulative_audit_events.extend(collect_group_audit_log_events(client, group, created_after))
        logger.debug(f"Fetched group-level audit events for group={group_name}")
    except Exception as error:
        logger.warning(f"Skipping group-level audit events for group={group_name}: {error}")

    try:
        group_projects = client.list_group_projects(group["id"])
    except Exception as error:
        logger.warning(f"Skipping project audit discovery for group={group_name}: {error}")
        return

    for project in filter_projects(group_projects, all_projects, selected_projects):
        project_name = project.get("path_with_namespace") or project.get("name") or project.get("id")
        try:
            cumulative_audit_events.extend(
                collect_project_audit_log_events(client, group, project, created_after)
            )
            logger.debug(f"Fetched project-level audit events for group={group_name} project={project_name}")
        except Exception as error:
            logger.warning(f"Skipping project-level audit events for group={group_name} project={project_name}: {error}")


def collect_audit_log_events(
    base_url: str,
    gitlab_interface,
    target_groups: list[dict],
    all_projects: bool,
    selected_projects: list[str],
    created_after: str,
) -> list[dict]:
    """
    Collect audit log payloads across all target groups (and their projects).

    Args:
        base_url: GitLab instance URL.
        gitlab_interface: ``RestApiHandler`` with ``PRIVATE-TOKEN``.
        target_groups: Groups to scan (from ``GitLabProcessor.fetch_target_groups``).
        all_projects: Whether to include every project under each group.
        selected_projects: Filter list when ``all_projects`` is false.
        created_after: ISO8601 lower bound for GitLab audit API ``created_after`` (set by
            the extension from ``last_log_time`` or the first-run day window).

    Returns:
        Log event dicts ready for ``Extension.report_log_event``.
    """
    client = GitLabProcessor(base_url, gitlab_interface)
    audit_events: list[dict] = []
    logger.info(f"Collecting audit log events created after {created_after} for {len(target_groups)} groups.")
    for group in target_groups:
        _collect_audit_events_for_single_group(
            client, group, created_after, all_projects, selected_projects, audit_events
        )
    logger.info(f"Collected {len(audit_events)} audit log events.")
    return audit_events


def _ingest_security_events_for_group(
    client: GitLabProcessor,
    group: dict,
    all_projects: bool,
    selected_projects: list[str],
    enabled_report_types: set[str],
    first_time_fetch_window_days: int,
    dynatrace_url: str,
    security_events_interface,
    dynatrace_chunk_max_bytes: int,
    multi_status: MultiStatus,
) -> None:
    """
    Ingest all new security events for one GitLab group and record scheduler status.

    Args:
        client: GitLab API processor.
        group: Group dict.
        all_projects: Project filter flag.
        selected_projects: Explicit project identifiers when not ``all_projects``.
        enabled_report_types: Allowed vulnerability report types.
        first_time_fetch_window_days: Job listing window.
        dynatrace_url: Security events ingest URL.
        security_events_interface: HTTP client with ``Api-Token`` authorization header.
        dynatrace_chunk_max_bytes: Maximum JSON body size per POST chunk.
        multi_status: Collects ``StatusValue`` entries for this group.

    Returns:
        None.
    """
    group_id = group.get("id")
    group_name = group.get("full_path") or group.get("name") or str(group_id)
    group_projects = client.list_group_projects(group_id)
    selected_group_projects = filter_projects(group_projects, all_projects, selected_projects)
    logger.info(
        f"Group {group_name} has {len(group_projects)} projects and {len(selected_group_projects)} selected projects."
    )
    all_project_events: list[dict] = []
    for project in selected_group_projects:
        project_name = project.get("path_with_namespace") or project.get("name")
        project_events = collect_project_events(
            client, group, project, enabled_report_types, first_time_fetch_window_days
        )
        logger.debug(
            f"Collected {len(project_events)} security event(s) for group={group_name} project={project_name}"
        )
        all_project_events.extend(project_events)

    if not all_project_events:
        multi_status.add_status(
            StatusValue.OK,
            f"Group {group_name}: no new security events (scan/finding) to ingest.",
        )
        return

    if not security_events_interface:
        multi_status.add_status(
            StatusValue.GENERIC_ERROR,
            f"Group {group_name}: {len(all_project_events)} event(s) collected but Dynatrace ingest client is not configured.",
        )
        return

    ok_count, failed_chunks = push_security_events_to_dynatrace(
        dynatrace_url, all_project_events, security_events_interface, dynatrace_chunk_max_bytes
    )
    logger.info(f"Group {group_name} pushed {ok_count} event(s) to Dynatrace ({failed_chunks} failed chunk(s)).")
    if failed_chunks > 0:
        multi_status.add_status(
            StatusValue.GENERIC_ERROR,
            f"Group {group_name}: Dynatrace ingest failed for {failed_chunks} chunk(s); "
            f"{ok_count} event POST(s) succeeded in this run.",
        )
    else:
        multi_status.add_status(
            StatusValue.OK,
            f"Group {group_name}: ingested {ok_count} security event(s) (VULNERABILITY_SCAN / VULNERABILITY_FINDING).",
        )


def poll_groups_and_ingest_security_events(
    base_url: str,
    gitlab_interface,
    all_groups: bool,
    group_ids: list[str],
    all_projects: bool,
    selected_projects: list[str],
    enabled_report_types: set[str],
    dynatrace_url: str,
    security_events_interface,
    first_time_fetch_window_days: int,
    dynatrace_chunk_max_bytes: int,
    multi_status: MultiStatus,
) -> None:
    """
    End-to-end vulnerability poll: groups → projects → events → Dynatrace POST.

    Args:
        base_url: GitLab base URL.
        gitlab_interface: Authenticated ``RestApiHandler``.
        all_groups: Whether to include every accessible group.
        group_ids: Explicit group identifiers when not ``all_groups``.
        all_projects: Whether to include every project under each group.
        selected_projects: Project filters when not ``all_projects``.
        enabled_report_types: Allowed GitLab report types (uppercase strings).
        dynatrace_url: Security ingest endpoint.
        security_events_interface: Client for ``POST`` (or ``None`` to skip push — should be set by caller).
        first_time_fetch_window_days: Job listing window.
        dynatrace_chunk_max_bytes: Chunk size for ingest.
        multi_status: Receives per-group (and setup) status lines.

    Returns:
        None.
    """
    try:
        client = GitLabProcessor(base_url, gitlab_interface)
        target_groups = client.fetch_target_groups(all_groups, group_ids)
    except Exception as error:
        logger.error(f"Failed to initialize GitLab client or fetch groups: {error}", exc_info=True)
        multi_status.add_status(
            StatusValue.GENERIC_ERROR,
            f"GitLab vulnerability poll failed (setup): {error}",
        )
        return

    logger.info(f"Found {len(target_groups)} target groups.")
    if not target_groups:
        multi_status.add_status(
            StatusValue.OK,
            "No target GitLab groups matched the configuration (scan/finding collection skipped).",
        )
        return

    for group in target_groups:
        group_name = group.get("full_path") or group.get("name") or str(group.get("id"))
        try:
            _ingest_security_events_for_group(
                client,
                group,
                all_projects,
                selected_projects,
                enabled_report_types,
                first_time_fetch_window_days,
                dynatrace_url,
                security_events_interface,
                dynatrace_chunk_max_bytes,
                multi_status,
            )
        except Exception as error:
            logger.error(f"Failed to process group {group_name}: {error}", exc_info=True)
            multi_status.add_status(
                StatusValue.GENERIC_ERROR,
                f"Group {group_name}: scan/finding collection or ingest failed: {error}",
            )
