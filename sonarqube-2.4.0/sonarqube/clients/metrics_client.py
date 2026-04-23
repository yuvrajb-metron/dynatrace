from typing import Literal

import requests

from sonarqube.clients.base_schema import BaseSchema
from sonarqube.config.sonarqube_config import SonarQubeConfig


class Metric(BaseSchema):
    metric: str
    value: str
    component: str | None = None
    best_value: bool | None = None


class Period(BaseSchema):
    value: str
    component: str | None = None
    best_value: bool | None = None


class PeriodMetric(BaseSchema):
    metric: Literal["new_maintainability_rating"]
    period: Period


class MetricsClient:
    def __init__(self, config: SonarQubeConfig, logger):
        self.config = config
        self.logger = logger

    def get_metrics(self, component_name: str) -> list[Metric | PeriodMetric]:
        response = requests.get(
            self.config.get_metrics_endpoint_mqr(component_name),
            headers=self.config.get_headers(),
            verify=self.config.verify,
            proxies=self.config.get_proxies(),
        )
        if response.status_code == 404:
            response = requests.get(
                self.config.get_metrics_endpoint(component_name),
                headers=self.config.get_headers(),
                verify=self.config.verify,
                proxies=self.config.get_proxies(),
            )
        response.raise_for_status()
        self.logger.debug(f"successfully queried metrics for component {component_name}")
        return [
            Metric(**metric) if metric["metric"] != "new_maintainability_rating" else PeriodMetric(**metric)
            for metric in response.json()["component"]["measures"]
        ]
