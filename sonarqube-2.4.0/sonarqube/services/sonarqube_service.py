from datetime import datetime, timedelta

from dynatrace_extension import Extension, StatusValue
from dynatrace_extension.sdk.status import MultiStatus

from sonarqube.clients.binding_client import BindingClient
from sonarqube.clients.components_client import (
    Analysis,
    Component,
    ComponentLeaf,
    ComponentsClient,
    FullComponent,
)
from sonarqube.clients.ingest_client import IngestClient
from sonarqube.clients.issues_client import IssuesClient
from sonarqube.clients.metrics_client import MetricsClient
from sonarqube.config.ingest_config import IngestConfig
from sonarqube.config.sonarqube_config import SonarQubeConfig
from sonarqube.mapper.metric_mapper import mint_lines_from_full_component
from sonarqube.mapper.sdlc_event_mapper import to_sdlc_events
from sonarqube.mapper.security_events_mapper import to_scan_finished_event, to_security_events
from sonarqube.utils.pagination_util import PAGE_SIZE
from sonarqube.utils.size_util import size_of_record


class SonarQubeService:
    def __init__(
        self,
        extension: Extension,
        sonarqube_url: str,
        sonarqube_token: str,
        sonarqube_verify: str | bool,
        sonarqube_cloud: bool,
        sonarqube_org: None | str,
        sonarqube_proxy: None | str,
        security_events_endpoint: str,
        sdlc_events_endpoint: str,
        ingest_events: bool,
        ingest_metrics: bool,
        dynatrace_token: str,
        first_ingest_window_hours=1.0,
        sync_interval=1.0,
    ):
        self.logger = extension.logger
        self.extension = extension
        self.sonar_config = SonarQubeConfig(
            sonarqube_url,
            sonarqube_token,
            sonarqube_verify,
            sonarqube_cloud,
            sonarqube_org,
            sonarqube_proxy,
        )
        self.component_client = ComponentsClient(self.sonar_config, self.logger)
        self.metrics_client = MetricsClient(self.sonar_config, self.logger)
        self.issues_client = IssuesClient(self.sonar_config, extension.issue_severities, self.logger)
        self.binding_client = BindingClient(self.sonar_config, self.logger)

        self.ingest_config = IngestConfig(security_events_endpoint, sdlc_events_endpoint, dynatrace_token)
        self.ingest_client = IngestClient(self.ingest_config, self.logger)

        self.ingest_events = ingest_events
        self.ingest_metrics = ingest_metrics

        self.sync_from = datetime.now() - timedelta(hours=first_ingest_window_hours)
        self.sync_interval = sync_interval
        self.first_sync = True

    def sync(self) -> MultiStatus:
        self.sdlc_events = []
        self.sdlc_events_counter = 0
        self.security_events = []
        self.security_events_counter = 0
        component_counter = 0
        self.multi_status = MultiStatus()

        if not self.first_sync:
            self.sync_from = datetime.now() - timedelta(hours=self.sync_interval)

        current_context = {
            "page": 1,
            "next_page": 1,
            "page_size": PAGE_SIZE,
            "current": -1,
            "total": 0,
            "selected_properties": ["name", "key"],
        }

        if self.ingest_metrics or self.ingest_events:
            while current_context["current"] < current_context["total"]:
                components, current_context = self.component_client.get_all_components(current_context)
                for component in components:
                    component_counter += 1

                    try:
                        full_component = self.get_full_component(component.key)
                        if self.ingest_metrics:
                            self.logger.info(
                                f"[{component_counter}/{current_context['total']}] "
                                f"Fetching metrics for component {component.name}"
                            )
                            self.extension.report_mint_lines(mint_lines_from_full_component(full_component))
                        if self.ingest_events:
                            self.logger.info(
                                f"[{component_counter}/{current_context['total']}] "
                                f"Fetching events for component {component.name}"
                            )
                            scans = self.component_client.get_component_analyses_since(
                                component.key, self.sync_from
                            )
                            if len(scans) > 0:
                                self.sync_for_each_scan(component, scans, full_component)
                            else:
                                self.logger.info(f"No analysis found component {component.name}. Skipping.")
                    except Exception as e:
                        self.logger.warning(
                            f"Unable to generate data for component {component.name}. Skipping ingest."
                        )
                        self.logger.warning(f"Exception {e}")
                        self.multi_status.add_status(
                            StatusValue.WARNING,
                            f"Unable to generate data for component {component.name}. "
                            "Skipping.\n"
                            f"Exception {type(e).__name__}",
                        )

            if self.extension.ingest_sdlc:
                self.sdlc_events_counter += len(self.sdlc_events)
                self.ingest_client.ingest_openpipeline(
                    self.sdlc_events, [], self.ingest_config.ingest_sdlc_endpoint(), self.multi_status
                )
                self.multi_status.add_status(
                    StatusValue.OK,
                    f"Ingested {self.sdlc_events_counter} SDLC events across {component_counter} components",
                )
            if self.extension.ingest_security_events:
                self.security_events_counter += len(self.security_events)
                self.ingest_client.ingest_openpipeline(
                    self.security_events,
                    [],
                    self.ingest_config.ingest_security_event_endpoint(),
                    self.multi_status,
                )
                self.multi_status.add_status(
                    StatusValue.OK,
                    f"Ingested {self.security_events_counter} security events "
                    f"across {component_counter} components",
                )
        self.first_sync = False

        return self.multi_status

    def sync_for_each_scan(
        self,
        component: Component,
        scans: list[Analysis],
        full_component: FullComponent,
    ):
        original_len_sdlc = len(self.sdlc_events)
        original_len_security = len(self.security_events)

        if self.extension.ingest_security_events:
            component_tree: list[ComponentLeaf] = self.component_client.get_component_tree(
                full_component.details.key
            )

        self.logger.info(f"Found {len(scans)} analyses. Generating data for each analysis.")
        for scan in scans:
            try:
                created_at = scan.date if scan.date is not None else self.sync_from

                if self.extension.ingest_sdlc:
                    self.sdlc_events.extend(
                        to_sdlc_events(full_component, scan, self.extension.enrichment_attributes)
                    )

                if self.extension.ingest_security_events:
                    issues = self.issues_client.get_issues(component.key, created_at)
                    self.security_events.extend(
                        to_security_events(
                            full_component,
                            issues,
                            scan,
                            self.issues_client,
                            self.sonar_config.url,
                            self.extension.enrichment_attributes,
                        )
                    )
                    self.security_events.extend(
                        to_scan_finished_event(
                            full_component, component_tree, scan, self.extension.enrichment_attributes
                        )
                    )
            except Exception as e:
                self.logger.warning(
                    f"Unable to generate events for analysis {scan.key} on component {component.name}. "
                    "Skipping."
                )
                self.logger.warning(f"Exception {e}")
                self.multi_status.add_status(
                    StatusValue.WARNING,
                    f"Unable to generate events for analysis {scan.key} on component {component.name}."
                    "Skipping.\n"
                    f"Exception {type(e).__name__}",
                )

        self.logger.info(
            f"Generated {len(self.sdlc_events) - original_len_sdlc} SDLC events "
            f"and {len(self.security_events) - original_len_security} security events."
        )

        # Send data if dicts bigger than 10MB
        if (
            self.extension.ingest_sdlc
            and len(self.sdlc_events) > 0
            and size_of_record(self.sdlc_events[-1]) * len(self.sdlc_events) > 10000000
        ):
            self.sdlc_events_counter += len(self.sdlc_events)
            self.ingest_client.ingest_openpipeline(
                self.sdlc_events, [], self.ingest_config.ingest_sdlc_endpoint(), self.multi_status
            )
            self.sdlc_events = []

        if (
            self.extension.ingest_security_events
            and len(self.security_events) > 0
            and size_of_record(self.security_events[-1]) * len(self.security_events) > 10000000
        ):
            self.security_events_counter += len(self.security_events)
            self.ingest_client.ingest_openpipeline(
                self.security_events,
                [],
                self.ingest_config.ingest_security_event_endpoint(),
                self.multi_status,
            )
            self.security_events = []

    def get_full_component(self, name: str) -> FullComponent:
        return FullComponent(
            name=name,
            measures=self.metrics_client.get_metrics(name),
            details=self.component_client.get_component_details(name),
            url=self.sonar_config.url,
            binding=self.binding_client.get_repo_binding(name),
        )
