# ruff: noqa: A002

import uuid
from urllib.parse import urljoin

from dynatrace_extension.sdk.extension import extension_logger as logger

from appsec_snyk.utils.shared import get_filename_from_path, parse_repository_name

from ..models.issues import Issue
from ..models.issues_v1 import IssueV1
from ..models.projects import Project


def _get_risk_score_from_level(risk_level: str) -> float:
    risk_score = 0
    if risk_level == "CRITICAL":
        risk_score = 10
    elif risk_level == "HIGH":
        risk_score = 8.9
    elif risk_level == "MEDIUM":
        risk_score = 6.9
    elif risk_level == "LOW":
        risk_score = 3.9

    return risk_score


def _get_v1_details_for_issue(issue: Issue, v1_issues: dict[str, IssueV1]) -> tuple[str, IssueV1]:
    if issue.attributes.problems != []:
        issue_type = issue.attributes.problems[0].type
        problem_id = issue.attributes.problems[0].id
    else:
        issue_type = None
        problem_id = None

    v1_issue = v1_issues.get(issue.attributes.key, None)

    if not v1_issue and issue_type == "rule":
        for v1_issue in v1_issues.values():
            if v1_issue.issueData.violatedPolicyPublicId == problem_id:
                return v1_issue.issueData.violatedPolicyPublicId, v1_issue
        else:
            return None, None

    return issue.attributes.key, v1_issue


def _get_exploit_status(snyk_exploit_maturity):
    if snyk_exploit_maturity in ["mature", "proof-of-concept"]:
        return "AVAILABLE"
    return "NOT_AVAILABLE"


def _get_product_from_type(type: str) -> None | str:
    if type == "package_vulnerability" or type == "license":
        return "Snyk Open Source"
    if type == "code":
        return "Snyk Code"
    if type == "config":
        return "Snyk IaC"
    return None


def _get_finding_type_from_issue_type(type: str) -> None | str:
    if type == "package_vulnerability":
        return "DEPENDENCY_VULNERABILITY"
    if type == "license":
        return "LICENSE_ISSUE"
    if type == "code":
        return "CODE_VULNERABILITY"
    if type == "config":
        return "CONFIGURATION_ISSUE"
    return None


def group_issues_by_project(issues: list[Issue]) -> dict[str, list[Issue]]:
    aggregated: dict[str, list[Issue]] = {}
    for issue in issues:
        project_id = (
            issue.relationships.scan_item.data.id
            if issue.relationships.scan_item.data.type == "project"
            else None
        )
        if project_id in aggregated:
            aggregated[project_id].append(issue)
        else:
            aggregated[project_id] = [issue]
    return aggregated


def generate_finding_from_issue(
    issue: Issue,
    project: Project | None,
    project_scan_event: dict,
    v1_issues: dict[str, IssueV1],
    org_name: str,
    snyk_base_url: str,
    enrichment_fields: dict[str, str],
) -> list[dict]:
    cves = [problem.id for problem in issue.attributes.problems if problem.source == "NVD"]

    project_id = (
        issue.relationships.scan_item.data.id
        if issue.relationships.scan_item.data.type == "project"
        else None
    )
    if project.container.image_id:
        snyk_product = "Snyk Container"
    else:
        snyk_product = _get_product_from_type(issue.attributes.type)

    if project:
        project_original_data: dict = project.original_data
        project_name: str = project.attributes.name
        project_tags: list = project.attributes.tags
        project_lifecycle: str = project.attributes.lifecycle
        project_business_criticality: str = project.attributes.business_criticality
        project_origin: str = project.attributes.origin

        target_reference: str = project.attributes.target_reference

        target_name: str = project.relationships.target.data.attributes.display_name
        target_id: str = project.relationships.target.data.id
    else:
        logger.warning(
            f"Unable to find project details for issue with key: {issue.attributes.key} "
            f"and project id: {project_id}"
        )
        project_original_data = None
        project_name = None
        project_tags = None
        project_lifecycle = None
        project_business_criticality = None
        project_origin = None
        target_reference = None
        target_name = None
        target_id = None

    vuln_key, v1_issue_details = _get_v1_details_for_issue(issue, v1_issues)
    if v1_issue_details:
        issue_description = v1_issue_details.issueData.description
        exploit_status = v1_issue_details.issueData.exploitMaturity
        vuln_url = v1_issue_details.issueData.url
        fixed_in = v1_issue_details.fixInfo.fixedIn
        issue_title = v1_issue_details.issueData.title
        issue_cvss = v1_issue_details.issueData.cvssScore
        issue_severity = v1_issue_details.issueData.severity
        if len(v1_issue_details.issueData.cvssDetails) > 0:
            issue_cvss_base_score = v1_issue_details.issueData.cvssDetails[0].cvssV3BaseScore
            issue_cvss_vector = v1_issue_details.issueData.cvssDetails[0].cvssV3Vector
    else:
        if issue.attributes.type != "code":
            logger.warning(
                f"Unable to find issue details for issue with key: {issue.attributes.key} "
                f"and project id: {project_id}"
            )
        issue_description = None
        exploit_status = None
        vuln_url = None
        fixed_in = None
        issue_cvss = None
        issue_severity = issue.attributes.effective_severity_level
        issue_title = issue.attributes.title

    if len(issue.attributes.severities) > 0:
        issue_cvss_base_score = issue.attributes.severities[0].score
        issue_cvss_vector = issue.attributes.severities[0].vector
    else:
        issue_cvss_base_score = None
        issue_cvss_vector = None

    dt_security_risk_level = issue_severity.upper() if issue_cvss != 0 else "NONE"
    dt_security_risk_score = _get_risk_score_from_level(dt_security_risk_level)

    remediation_available = False
    if len(issue.attributes.coordinates) > 0 and (
        issue.attributes.coordinates[0].is_fixable_manually
        or issue.attributes.coordinates[0].is_fixable_snyk
        or issue.attributes.coordinates[0].is_fixable_upstream
    ):
        remediation_available = True

    base_event = {
        **enrichment_fields,
        "event.kind": "SECURITY_EVENT",
        "event.original_content": issue.original_data,
        "event.id": str(uuid.uuid4()),
        "event.version": "1.306",
        "event.provider": "Snyk",
        "product.vendor": "Snyk",
        "product.name": snyk_product,
        "event.type": "VULNERABILITY_FINDING",
        "event.category": "VULNERABILITY_MANAGEMENT",
        "event.name": "Vulnerability finding event",
        "dt.security.risk.level": dt_security_risk_level,
        "dt.security.risk.score": dt_security_risk_score,
        "finding.type": _get_finding_type_from_issue_type(issue.attributes.type),
        "finding.title": issue.attributes.title,
        # "finding.description": issue_description,
        "finding.time.created": issue.attributes.updated_at,
        "finding.severity": issue.attributes.effective_severity_level,
        "finding.score": issue_cvss if issue_cvss else dt_security_risk_score,
        "finding.url": urljoin(
            snyk_base_url, f"org/{org_name}/project/{project_id}/#issue-{issue.attributes.key}"
        ),
        "vulnerability.id": vuln_key,
        "vulnerability.title": issue_title,
        "vulnerability.description": issue_description,
        "vulnerability.references.cve": cves,
        "vulnerability.remediation.status": "AVAILABLE" if remediation_available else "NOT_AVAILABLE",
        "vulnerability.remediation.fix_versions": fixed_in,
        # "vulnerability.remediation.description": plugin_solution,
        "vulnerability.exploit.status": _get_exploit_status(exploit_status),
        "vulnerability.cvss.base_score": issue_cvss_base_score,
        "vulnerability.cvss.vector": issue_cvss_vector,
        "scan.id": project_scan_event.get("scan.id"),
        "scan.time.started": project_scan_event.get("scan.time.started"),
        "scan.time.completed": project_scan_event.get("scan.time.completed"),
        "scan.url": project_scan_event.get("scan.url"),
        "snyk.project.original_content": project_original_data,
        "snyk.project.id": project_id,
        "snyk.project.origin": project_origin,
        "snyk.project.name": project_name,
        "snyk.project.tags": [f"{tag.get('key')}:{tag.get('value')}" for tag in project_tags],
        "snyk.project.lifecycle": project_lifecycle,
        "snyk.project.business_criticality": project_business_criticality,
        "snyk.target.reference": target_reference,
        "snyk.target.name": target_name,
        "snyk.target.id": target_id,
        "snyk.org.id": issue.relationships.organization.data.id,
        "snyk.org.name": org_name,
        "snyk.vulnerability.url": vuln_url,
        "snyk.issue.url": urljoin(
            snyk_base_url, f"org/{org_name}/project/{project_id}/#issue-{issue.attributes.key}"
        ),
        "snyk.issue.id": issue.id,
        "snyk.issue.risk_score": issue.attributes.risk.score.value,
    }

    if project.container.image_id:
        container_info = {
            "container_image.digest": project.container.image_digest,
            "container_image.tags": [project.container.image_tag],
            "container_image.repository": project.relationships.target.data.attributes.display_name,
            "container_image.registry": project.attributes.origin,
            "container_image.id": project.container.image_id,
            "object.id": (
                f"{project.attributes.origin}/"
                f"{project.relationships.target.data.attributes.display_name}/{project.container.image_id}"
            ),
            "object.type": "CONTAINER_IMAGE",
            "object.name": project.relationships.target.data.attributes.display_name,
        }
        base_event = {
            **base_event,
            **container_info,
        }
    elif issue.attributes.type != "code":
        name = get_filename_from_path(project.attributes.target_file)
        base_event = {
            **base_event,
            "object.id": project.id,
            "object.type": "CODE_ARTIFACT",
            "object.name": name if name != "" else project.attributes.name,
            "artifact.id": project.id,
            "artifact.name": name if name != "" else project.attributes.name,
            "artifact.filename": get_filename_from_path(project.attributes.target_file),
            "artifact.path": project.attributes.target_file,
            "artifact.repository": parse_repository_name(project.attributes.name),
        }

    vulnerability_events: list[dict] = []

    if issue.attributes.type in ["package_vulnerability", "license"]:
        for coordinate in issue.attributes.coordinates:
            for representation in coordinate.representations:
                if "dependency" in representation.original_data:
                    vulnerability_events.append(
                        {
                            **base_event,
                            "component.name": representation.dependency.package_name,
                            "component.version": representation.dependency.package_version,
                            "software_component.name": representation.dependency.package_name,
                            "software_component.version": representation.dependency.package_version,
                            "finding.id": (
                                f"{issue.id}/"
                                f"{representation.dependency.package_name}{representation.dependency.package_version}"
                            ),
                        }
                    )

    elif issue.attributes.type == "config" and v1_issue_details:
        vulnerability_events.append(
            {
                **base_event,
                "finding.title": issue.attributes.title
                + (
                    f" {v1_issue_details.issueData.path}"
                    if v1_issue_details.issueData.path is not None
                    else ""
                ),
                "finding.id": f"{issue.id}/{v1_issue_details.issueData.path}",
                "component.name": v1_issue_details.issueData.path,
            }
        )

    elif issue.attributes.type == "code":
        for coordinate in issue.attributes.coordinates:
            for representation in coordinate.representations:
                vulnerability_events.append(
                    {
                        **base_event,
                        "finding.id": issue.id,
                        "object.id": (
                            f"{project.attributes.name}:{representation.sourceLocation.file}:{representation.sourceLocation.commit_id}"
                        ),
                        "object.type": "CODE_ARTIFACT",
                        "object.name": get_filename_from_path(representation.sourceLocation.file),
                        "artifact.id": (
                            f"{project.attributes.name}:{representation.sourceLocation.file}:{representation.sourceLocation.commit_id}"
                        ),
                        "artifact.name": get_filename_from_path(representation.sourceLocation.file),
                        "artifact.filename": get_filename_from_path(representation.sourceLocation.file),
                        "artifact.path": representation.sourceLocation.file,
                        "artifact.repository": parse_repository_name(project.attributes.name),
                        "code.filepath": representation.sourceLocation.file,
                        "code.line.number": representation.sourceLocation.region.start.line,
                        "component.name": representation.sourceLocation.file,
                        "component.version": representation.sourceLocation.commit_id,
                    }
                )

    if vulnerability_events == []:
        vulnerability_events.append({**base_event, "finding.id": issue.id})

    return vulnerability_events
