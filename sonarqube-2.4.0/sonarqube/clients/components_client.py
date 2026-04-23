from datetime import datetime

import requests

from sonarqube.clients.base_schema import BaseSchema
from sonarqube.clients.binding_client import ComponentBinding
from sonarqube.clients.metrics_client import Metric, PeriodMetric
from sonarqube.config.sonarqube_config import SonarQubeConfig
from sonarqube.utils.pagination_util import get_page, pages_for


class Component(BaseSchema):
    key: str
    name: str | None = None
    description: str | None = None
    project: str | None = None


class ComponentDetails(BaseSchema):
    key: str
    name: str | None = None
    description: str | None = None
    qualifier: str | None = None
    analysis_date: str | None = None
    tags: list[str] | None = None
    visibility: str | None = None
    leak_period_date: str | None = None
    version: str | None = None
    need_issue_sync: bool | None = None
    is_ai_code_fix_enabled: bool | None = None

    def model_post_init(self, context):
        if self.version == "not provided":
            self.version = None
        return super().model_post_init(context)


class FullComponent(BaseSchema):
    name: str
    measures: list[Metric | PeriodMetric] | None = None
    details: ComponentDetails | None = None
    url: str | None = None
    binding: ComponentBinding | None = None


class AnalysisEvents(BaseSchema):
    key: str
    category: str | None = None
    name: str | None = None
    description: str | None = None


class Analysis(BaseSchema):
    key: str
    date: str | None = None
    events: list[AnalysisEvents] | None = None
    project_version: str | None = None
    manual_new_code_period_baseline: bool | None = None
    revision: str | None = None
    detected_c_i: str | None = None


class ComponentLeaf(BaseSchema):
    key: str
    name: str | None = None
    qualifier: str | None = None
    path: str | None = None
    language: str | None = None


class ComponentsClient:
    def __init__(self, config: SonarQubeConfig, logger):
        self.config = config
        self.logger = logger

    def get_component_details(self, component_name: str) -> ComponentDetails:
        response = requests.get(
            self.config.get_component_endpoint(component_name),
            headers=self.config.get_headers(),
            verify=self.config.verify,
            proxies=self.config.get_proxies(),
        )
        response.raise_for_status()
        self.logger.debug(f"Successfully got component details for component {component_name}")
        return ComponentDetails(**response.json()["component"])

    def get_all_components(self, context: dict) -> tuple[list[Component], dict]:
        entries, new_context = get_page(
            self.config.get_components_endpoint(),
            self.config.get_headers(),
            self.config.verify,
            "components",
            self.logger,
            context,
            proxies=self.config.get_proxies(),
        )
        self.logger.debug("Successfully got all components.")
        return [Component(**entry) for entry in entries], new_context

    def get_component_analyses_since(self, component: str, from_date: datetime) -> list[Analysis]:
        analyses = [
            Analysis(**analysis)
            for analysis in pages_for(
                self.config.get_analysis_endpoint(component, from_date),
                self.config.get_headers(),
                self.config.verify,
                "analyses",
                self.logger,
                proxies=self.config.get_proxies(),
            )
        ]
        self.logger.debug(f"Successfully got analyses for component {component} from date {from_date}.")
        return analyses

    def get_component_tree(self, component: str) -> list[ComponentLeaf]:
        leafs = [
            ComponentLeaf(**leaf)
            for leaf in pages_for(
                self.config.get_component_tree_endpoint(component),
                self.config.get_headers(),
                self.config.verify,
                "components",
                self.logger,
                proxies=self.config.get_proxies(),
            )
        ]
        self.logger.debug(f"Successfully got full tree for component {component}.")
        return leafs
