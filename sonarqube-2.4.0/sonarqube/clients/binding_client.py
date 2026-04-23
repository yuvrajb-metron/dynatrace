import requests

from sonarqube.clients.base_schema import BaseSchema
from sonarqube.config.sonarqube_config import SonarQubeConfig
from sonarqube.utils.url_util import ensure_trailing_slash


class ComponentBinding(BaseSchema):
    key: str | None = None
    alm: str | None = None
    repository: str | None = None
    url: str | None = None
    slug: str | None = None
    monorepo: bool | None = None


class BindingClient:
    def __init__(self, config: SonarQubeConfig, logger):
        self.config = config
        self.logger = logger

    def get_repo_binding(self, component_name: str) -> ComponentBinding:
        response = requests.get(
            self.config.get_binding_endpoint(component_name),
            headers=self.config.get_headers(),
            verify=self.config.verify,
            proxies=self.config.get_proxies(),
        )
        if response.status_code == 404:
            return {}

        response.raise_for_status()
        self.logger.debug(f"Successfully got repo binding for component {component_name}")
        return ComponentBinding(**response.json())


def extract_slug_and_object_id_from_binding(binding: ComponentBinding) -> tuple[str | None, str | None]:
    slug = binding.slug
    object_id = None
    if binding.url is not None and binding.repository is not None and binding.slug is not None:
        object_id = f"{ensure_trailing_slash(binding.url)}{binding.repository}/{binding.slug}"

    return slug, object_id
