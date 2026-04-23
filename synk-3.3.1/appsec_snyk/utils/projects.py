from urllib.parse import urljoin

from dynatrace_extension.sdk.extension import extension_logger as logger
from snyk import SnykClient

from ..models.container_image import ContainerImage
from ..models.projects import ContainerData, Project
from ..rest_interface import Header, RestApiHandler


def enrich_project_with_container_details(
    org_id: str,
    project_id: str,
    project: Project,
    snyk_v1_manual: RestApiHandler,
    snyk_api_url: str,
    snyk_client: SnykClient,
):
    v1_project_details_response = snyk_v1_manual.get_url(
        urljoin(snyk_api_url, f"/v1/org/{org_id}/project/{project_id}"),
        headers=[Header({"headerKey": "User-Agent", "headerValue": "dynatrace-snyk-1.0.0"})],
    )
    v1_project_details = v1_project_details_response.json()
    image_id = v1_project_details.get("imageId")
    if image_id:
        container_image_details_response = snyk_client.get(f"/orgs/{org_id}/container_images/{image_id}")
        container_image_details = container_image_details_response.json()
        project.container = ContainerData(
            {
                "imageId": image_id,
                "imageTag": v1_project_details.get("imageTag"),
                "imagePlatform": v1_project_details.get("imagePlatform"),
                "imageBaseImage": v1_project_details.get("imageBaseImage"),
                "imageDigest": get_container_image_digest(ContainerImage(container_image_details)),
            }
        )
    else:
        logger.debug("Even though build_args was present, no container data was found in v1 API.")


def get_container_image_digest(container_image: ContainerImage) -> str | None:
    for name in container_image.data.attributes.names:
        if "@sha256" in name:
            return name.split("@")[1]
    else:
        return None
