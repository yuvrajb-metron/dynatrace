import uuid
from datetime import datetime
from urllib.parse import urljoin

from appsec_snyk.utils.shared import get_filename_from_path, parse_repository_name

from ..models.project_history_v1 import SnapshotsData
from ..models.projects import Project


def generate_scan_from_project_history(
    project: Project,
    project_history: SnapshotsData,
    datetime_to_query: datetime,
    org_name: str,
    snyk_base_url: str,
    enrichment_fields: dict[str, str],
) -> list[dict]:
    base_event = {
        **enrichment_fields,
        "event.kind": "SECURITY_EVENT",
        "event.id": str(uuid.uuid4()),
        "event.version": "1.304",
        "event.provider": "Snyk",
        "product.vendor": "Snyk",
        "product.name": "Snyk",
        "event.type": "VULNERABILITY_SCAN",
        "event.category": "VULNERABILITY_MANAGEMENT",
        "event.name": f"Vulnerability scan completed on {project.attributes.name}",
        "scan.name": project.attributes.name,
        "scan.status": "Completed",
        "snyk.project.original_content": project.original_data,
        "snyk.project.id": project.id,
        "snyk.project.origin": project.attributes.origin,
        "snyk.project.name": project.attributes.name,
        "snyk.project.tags": [f"{tag.get('key')}:{tag.get('value')}" for tag in project.attributes.tags],
        "snyk.project.lifecycle": project.attributes.lifecycle,
        "snyk.project.business_criticality": project.attributes.business_criticality,
        "snyk.target.reference": project.attributes.target_reference,
        "snyk.target.name": project.relationships.target.data.attributes.display_name,
        "snyk.target.id": project.relationships.target.data.id,
        "snyk.org.id": project.relationships.organization.data.id,
        "snyk.org.name": org_name,
        "snyk.project.url": urljoin(snyk_base_url, f"org/{org_name}/project/{project.id}"),
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
    elif project.attributes.type != "sast":
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
    else:
        base_event = {
            **base_event,
            "object.id": project.id,
            "object.type": "CODE_REPOSITORY",
            "object.name": project.attributes.name,
        }

    scan_events: list[dict] = []
    for history in project_history.snapshots:
        if datetime.timestamp(
            datetime.fromisoformat(history.created.replace("Z", "+00:00"))
        ) > datetime.timestamp(datetime_to_query):
            scan_events.append(
                {
                    **base_event,
                    "event.original_content": history.original_data,
                    "scan.id": history.id,
                    "scan.url": urljoin(
                        snyk_base_url, f"org/{org_name}/project/{project.id}/history/{history.id}"
                    ),
                    "scan.time.started": history.created,
                    "scan.time.completed": history.created,
                }
            )
        else:  # We assume the API response is ordered
            break

    return scan_events
