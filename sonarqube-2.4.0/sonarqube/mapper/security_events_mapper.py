import uuid
from functools import lru_cache
from urllib.parse import quote

from sonarqube.clients.binding_client import ComponentBinding, extract_slug_and_object_id_from_binding
from sonarqube.clients.components_client import Analysis, ComponentLeaf, FullComponent
from sonarqube.clients.issues_client import Issue, IssuesClient, Rule

SCHEMA_VERSION = "1.309"


@lru_cache
def cached_get_rule_details(issue_client: IssuesClient, rule_key: str) -> Rule:
    return issue_client.get_rule_details(rule_key)


def get_repo(binding: ComponentBinding, component_key: str) -> str | None:
    _, repo_url = extract_slug_and_object_id_from_binding(binding)
    return repo_url if repo_url is not None else component_key.split(":")[0]


def to_security_events(
    component: FullComponent,
    issues: list[Issue],
    scan: Analysis,
    issue_client: IssuesClient,
    sonarqube_url: str,
    enrichment_attributes: dict[str, str],
) -> list[dict]:
    events = []
    for issue in issues:
        rule_key = issue.rule if issue.rule is not None else issue.rule_key
        rule = cached_get_rule_details(issue_client, rule_key)
        events.append(
            issue_to_security_event(component, issue, scan, rule, sonarqube_url, enrichment_attributes)
        )

    return events


def to_scan_finished_event(
    component: FullComponent,
    component_tree: list[ComponentLeaf],
    scan: Analysis,
    enrichment_attributes: dict[str, str],
) -> list[dict]:
    return [
        enrich_with_generic(
            {
                **enrichment_attributes,
                "event.original_content": scan.model_dump(exclude_none=True),
                "event.type": "VULNERABILITY_SCAN",
                "event.name": "Vulnerability scan event",
                "event.description": f"Vulnerability scan completed for project {component.details.name}",
                "object.type": "CODE_ARTIFACT",
                "object.id": component_leaf.key,
                "object.name": component_leaf.name,
                "artifact.id": component_leaf.key,
                "artifact.version": component.details.version,
                "artifact.name": component_leaf.name,
                "artifact.repository": get_repo(component.binding, component_leaf.key),
                "artifact.path": component_leaf.key.split(":")[-1],
                "artifact.filename": component_leaf.name,
                "code.filepath": component_leaf.path,
            },
            component,
            scan,
        )
        for component_leaf in component_tree
    ]


def enrich_with_generic(event: dict, component: FullComponent, scan: Analysis) -> dict:
    details = component.details

    event["event.kind"] = "SECURITY_EVENT"
    event["event.provider"] = "SonarQube"
    event["event.id"] = str(uuid.uuid4())
    event["event.version"] = SCHEMA_VERSION
    event["event.category"] = "VULNERABILITY_MANAGEMENT"
    event["product.name"] = "SonarQube"
    event["product.vendor"] = "Sonar"
    event["scan.id"] = scan.key
    event["scan.name"] = scan.key
    event["scan.time.started"] = scan.date
    event["scan.time.completed"] = scan.date
    event["scan.url"] = (
        f"{component.url}project/activity?id={component.details.key}&selected_date={quote(scan.date)}"
    )
    event["sonarqube.tenant"] = component.url
    event["sonarqube.tags"] = details.tags
    event["sonarqube.revision.name"] = scan.revision
    event["sonarqube.project.name"] = details.name
    event["sonarqube.project.id"] = details.key
    event["sonarqube.project.url"] = f"{component.url}dashboard?id={component.details.key}&codeScope=overall"

    return event


@lru_cache
def determine_risk_level_and_score(severity: str) -> tuple[str, float]:
    risk_level = severity.upper()
    if risk_level == "INFO":
        risk_level = "NONE"

    risk_score = 0
    if risk_level in ["BLOCKER", "CRITICAL", "HIGH"]:
        risk_level = "HIGH"
        risk_score = 8.9
    elif risk_level in ["MEDIUM", "MAJOR"]:
        risk_level = "MEDIUM"
        risk_score = 6.9
    elif risk_level in ["MINOR", "INFO", "LOW"]:
        risk_level = "LOW"
        risk_score = 3.9

    return risk_level, risk_score


def issue_to_security_event(
    component: FullComponent,
    issue: Issue,
    scan: Analysis,
    rule: Rule,
    sonarqube_url: str,
    enrichment_attributes: dict[str, str],
) -> dict:
    details = component.details
    severity = (
        issue.severity
        if issue.severity is not None
        else (issue.vulnerability_probability if issue.vulnerability_probability else "LOW")
    )
    risk_level, risk_score = determine_risk_level_and_score(severity)

    file_name = None
    file_path = None

    if issue.component is not None:
        file_name = issue.component.split("/")[-1]
        file_path = issue.component.split(":")[-1]

    how_to_fix = None
    if rule.description_sections is not None:
        for section in rule.description_sections:
            if section.key == "how_to_fix":
                how_to_fix = section.content

    line_start = None
    line_end = None
    offset_start = None
    offset_end = None

    if issue.text_range is not None:
        line_start = issue.text_range.start_line
        line_end = issue.text_range.end_line
        offset_start = issue.text_range.start_offset
        offset_end = issue.text_range.end_offset

    return enrich_with_generic(
        {
            **enrichment_attributes,
            "event.original_content": issue.model_dump(exclude_none=True),
            "event.type": "VULNERABILITY_FINDING",
            "event.name": "Vulnerability finding event",
            "event.description": f"Vulnerability {rule.key} was detected in "
            f"CODE_ARTIFACT object ({issue.project})"
            f" in {issue.component} component.",
            "vulnerability.id": rule.key,
            "vulnerability.title": rule.name,
            "vulnerability.remediation.status": ("AVAILABLE" if how_to_fix is not None else "NOT_AVAILABLE"),
            "vulnerability.remediation.description": how_to_fix,
            "dt.security.risk.level": risk_level,
            "dt.security.risk.score": risk_score,
            "component.name": file_name,
            "finding.id": issue.key,
            "finding.status": issue.issue_status,
            "finding.title": issue.message,
            "finding.type": "CODE_ISSUE",
            "finding.time.created": issue.update_date,
            "finding.description": issue.message,
            "finding.severity": risk_level,
            "finding.url": (
                f"{sonarqube_url}project/issues?issues={issue.key}&open={issue.key}&id={quote(issue.project)}"
            ),
            "object.id": issue.component,
            "object.type": "CODE_ARTIFACT",
            "object.name": file_name,
            "artifact.id": issue.component,
            "artifact.name": file_name,
            "artifact.repository": get_repo(component.binding, issue.component),
            "artifact.version": details.version,
            "artifact.path": issue.component.split(":")[-1],
            "artifact.filename": file_name,
            "code.filepath": file_path,
            "code.line.number": line_start,
            "code.line.start": line_start,
            "code.line.end": line_end,
            "code.line.offset.start": offset_start,
            "code.line.offset.end": offset_end,
            "sonarqube.revision.author": issue.author,
        },
        component,
        scan,
    )
