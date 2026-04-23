from sonarqube.clients.components_client import FullComponent
from sonarqube.utils.constants import METRIC_ID_LOOKUP


def mint_lines_from_full_component(full_component: FullComponent) -> list[str]:
    mint_lines = []
    security_hotspots_reviewed_seen = False
    url = full_component.url
    for measure in full_component.measures:
        if measure.metric == "security_hotspots_reviewed":
            security_hotspots_reviewed_seen = True
        if measure.metric in METRIC_ID_LOOKUP:
            mint_lines.append(
                f"{METRIC_ID_LOOKUP[measure.metric]}"
                f",tenant={url},project={full_component.name} {measure.value}"
            )

    if not security_hotspots_reviewed_seen:
        sec_review_id = METRIC_ID_LOOKUP["security_hotspots_reviewed"]
        mint_lines.append(f"{sec_review_id},tenant={url},project={full_component.name} 0")

    return mint_lines
