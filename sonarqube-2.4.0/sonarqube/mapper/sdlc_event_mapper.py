import uuid

from sonarqube.clients.binding_client import extract_slug_and_object_id_from_binding
from sonarqube.clients.components_client import Analysis, FullComponent


def to_sdlc_events(
    component: FullComponent, scan: Analysis, enrichment_attributes: dict[str, str]
) -> list[dict]:
    events = []
    for measure in component.measures:
        if measure.metric == "security_rating":
            events.append(
                to_sdlc_event("Security Rating", component, scan, measure.value, enrichment_attributes)
            )
        if measure.metric == "new_maintainability_rating":
            events.append(
                to_sdlc_event(
                    "Maintainability Rating", component, scan, measure.period.value, enrichment_attributes
                )
            )

    return events


def to_sdlc_event(
    metric_name: str,
    component: FullComponent,
    analysis: Analysis,
    score: str,
    enrichment_attributes: dict[str, str],
) -> dict:
    task_status = "Success"
    reason = None

    revision = analysis.revision if analysis.revision is not None else ""

    _, repo_url = (
        extract_slug_and_object_id_from_binding(component.binding)
        if component.binding is not None
        else (None, None)
    )

    if analysis.events is not None and len(analysis.events) > 0:
        for event in analysis.events:
            if event.category == "QUALITY_GATE":
                if event.name == "Failed":
                    task_status = "Failure"
                    reason = event.description
                elif event.name == "Passed":
                    task_status = "Success"

    event_description = (
        f"Maintainability rating set to {score}. "
        if metric_name == "new_maintainability_rating"
        else f"Security rating set to {score}. "
    )

    return {
        **enrichment_attributes,
        "artifact.id": component.details.key,
        "artifact.name": component.details.name,
        "artifact.version": component.details.version,
        "artifact.repository": repo_url,
        "artifact.tags": component.details.tags,
        "artifact.revision": revision,
        "event.kind": "SDLC_EVENT",
        "event.provider": "SonarQube",
        "event.category": "task",
        "event.name": "SDLC task control finished event",
        "event.type": "control",
        "event.status": "finished",
        "event.version": "0.0.1",
        "event.description": event_description
        + (f"Quality gate failed with reason: {reason}." if reason else ""),
        "task.id": str(uuid.uuid4()),
        "task.name": f"Security control assessment for {component.details.name}",
        "task.outcome": task_status,
        "task.group": "Security",
        "control.score": float(score),
        "control.correlationId": analysis.key,
        "start_time": analysis.date,
        "end_time": analysis.date,
        "sonarqube.project.id": component.details.key,
        "sonarqube.project.name": component.details.name,
        "sonarqube.project.url": f"{component.url}dashboard?id={component.details.key}&codeScope=overall",
        "sonarqube.revision.name": analysis.revision,
        "sonarqube.tags": component.details.tags,
        "sonarqube.tenant": component.url,
    }
