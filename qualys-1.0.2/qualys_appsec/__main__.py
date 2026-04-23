from dynatrace_extension import Extension, Status, StatusValue
from dynatrace_extension.sdk.status import MultiStatus
from datetime import timedelta, datetime, timezone
import requests
from requests.exceptions import RequestException, ConnectionError, ProxyError
import json
from itertools import chain

from .qualys import Qualys
from .utils import split_by_size
from .qualys_models import Host, HostAsset
from .http_client import InvalidCredentialsError, MissingJWTError
from .environment import DynatraceEnvironmentUtils

dt_env_utils = DynatraceEnvironmentUtils()


class ExtensionImpl(Extension):

    def initialize(self):
        self.dev_mode = True if self.task_id == "development_task_id" else False
        self.extension_name: str = "com.dynatrace.extension.qualys"

        advanced = self.activation_config.get("advanced_options", {})
        self.logger.setLevel("DEBUG" if advanced.get("debug_logs", False) else "INFO")
        self.security_findings_frequency_hours = advanced.get(
            "security_findings_frequency_hours", 1
        )
        self.inclusion_time_window_days = advanced.get("inclusion_time_window_days", 7)

        self.dt_token = self.activation_config["dynatrace"]["token"]
        if self.dev_mode:
            self.generate_mock_data = self.activation_config.get("generate_mock_data", False),
            self.security_events_ingest_url = (
                f"https://localhost:9999/e/{self.activation_config.get('dt_environment_id')}/platform/ingest/v1/security.events"
                if not self.activation_config["dynatrace"].get(
                    "dynatrace_security_ingest_url"
                )
                else self.activation_config["dynatrace"].get(
                    "dynatrace_security_ingest_url"
                )
            )
        else:
            self.security_events_ingest_url = (
                self.activation_config["dynatrace"].get("dynatrace_security_ingest_url")
                if self.activation_config["dynatrace"].get(
                    "dynatrace_security_ingest_url"
                )
                else f"{dt_env_utils.get_api_url()}/platform/ingest/v1/security.events"
            )

        qualys_config: dict = self.activation_config["qualys"]
        self.url_base = qualys_config.get("url_base")
        self.username = qualys_config.get("username")
        self.qualys: Qualys = Qualys(
            self.url_base,
            self.username,
            qualys_config.get("password"),
            self.logger,
            proxies={
                "https": self.build_proxy_url(
                    self.activation_config.get("qualys", {}).get("proxy", {})
                )
            },
            private_platform=self.activation_config.get("qualys", {}).get("private_platform", False)
        )

        self.last_vmdr_collection_time: datetime = None
        self.last_audit_log_collection_time: datetime = None

        if self.activation_config["features"].get("collect_vmdr_alerts", False):
            self.schedule(
                self.collect_and_ingest_host_detections,
                timedelta(hours=self.security_findings_frequency_hours),
            )

        if self.activation_config["features"].get("collect_admin_audit_logs", False):
            self.qualys.gateway_client.update_jwt()
            self.schedule(self.qualys.gateway_client.update_jwt, timedelta(minutes=200))
            self.schedule(
                self.collect_and_ingest_audit_logs,
                timedelta(
                    minutes=self.activation_config.get("advanced_options", {}).get(
                        "audit_log_frequency_minutes", 5
                    )
                ),
            )

    def collect_and_ingest_audit_logs(self):
        multi_status: MultiStatus = MultiStatus()
        if not self.last_audit_log_collection_time:
            self.last_audit_log_collection_time = datetime.now(
                tz=timezone.utc
            ) - timedelta(minutes=200)

        from_time = self.last_audit_log_collection_time
        to_time = datetime.now(tz=timezone.utc) - timedelta(minutes=5)
        self.last_audit_log_collection_time = to_time

        try:
            audit_records = self.qualys.collect_audit_logs(
                from_time=from_time, to_time=to_time
            )
            for record in audit_records:
                self.report_log_event(record)
            multi_status.add_status(
                StatusValue.OK, f"Ingested {len(audit_records)} activity records."
            )
        except MissingJWTError as e:
            self.logger.error(
                f"DEC:1C5 Unable to collect activity logs due to no JWT being available."
            )
            multi_status.add_status(
                StatusValue.GENERIC_ERROR,
                f"DEC:1C5 Unable to collect activity logs due to no JWT being available.",
            )
            return multi_status
        except ProxyError as e:
            self.logger.error(
                f"DEC:1C2 An issue with the configured proxy was encountered: {e}."
            )
            multi_status.add_status(
                StatusValue.GENERIC_ERROR,
                f"DEC:1C2 An issue with the configured proxy was encountered: {e}.",
            )
            return multi_status
        except ConnectionError as e:
            self.logger.error(
                f"DEC:1C3 Unable to connect to the Qualys API at {self.qualys.gateway_base}: {e}"
            )
            multi_status.add_status(
                StatusValue.DEVICE_CONNECTION_ERROR,
                f"DEC:1C3 Unable to connect to the Qualys API at {self.qualys.gateway_base}: {e}",
            )
            return multi_status
        except InvalidCredentialsError as e:
            self.logger.error(
                f"DEC:1BF Unauthorized response returned when querying activity logs from {self.qualys.gateway_base}."
            )
            multi_status.add_status(
                StatusValue.AUTHENTICATION_ERROR,
                f"DEC:1BF Unauthorized response returned when querying activity logs from {self.qualys.gateway_base}.",
            )
            return multi_status
        except Exception as e:
            self.logger.exception(
                f"DEC:1C0 Unexpected error collecting activity log records: {e}."
            )
            multi_status.add_status(
                StatusValue.GENERIC_ERROR,
                f"DEC:1C0 Unexpected error collecting activity log records: {e}.",
            )
            return multi_status

        return multi_status

    def collect_and_ingest_host_detections(self):
        multi_status: MultiStatus = MultiStatus()

        if not self.last_vmdr_collection_time:
            self.last_vmdr_collection_time = datetime.now(tz=timezone.utc) - timedelta(
                days=self.inclusion_time_window_days
            )

        from_time = self.last_vmdr_collection_time
        to_time = datetime.now(tz=timezone.utc) - timedelta(minutes=5)
        self.last_vmdr_collection_time = to_time

        self.logger.info(
            f"Checking for vulns detected between {from_time.isoformat()} and {to_time.isoformat()}."
        )

        limit = 100
        start_from_offset = 1
        more_records = True
        while more_records:
            # handle reporting in batches
            qweb_ids: list[str] = []
            host_list: list[Host] = []
            qweb_id_map_of_host_assets: dict[str, HostAsset] = {}
            discovered_qids: list[str] = []

            try:
                host_assets, has_more = self.qualys.get_host_assets_for_scans(
                    vulns_updated_since=from_time,
                    vulns_updated_to=to_time,
                    result_limit=limit,
                    start_from_offset=start_from_offset,
                )
                more_records = has_more

                if (start_from_offset == 1) and (len(host_assets) == 0):
                    self.logger.warning(
                        f"DEC:1C4 No host assets were returned. Check that the user's Asset Group visbility in the VMDR module."
                    )
                    multi_status.add_status(
                        StatusValue.WARNING,
                        f"DEC:1C4 No host assets were returned. Check that the user's Asset Group visbility in the VMDR module.",
                    )

                for host_asset in host_assets:
                    qweb_id_map_of_host_assets.update(
                        {host_asset.qweb_host_id: host_asset}
                    )
                    qweb_ids.append(host_asset.qweb_host_id)

                start_from_offset = start_from_offset + limit

                if len(qweb_ids) > 0:
                    host_detections = self.qualys.retrieve_elements_paginated(
                        "/api/2.0/fo/asset/host/vm/detection",
                        {
                            "action": "list",
                            "show_qds": "1",
                            "show qds_factors": "1",
                            "ids": ",".join(qweb_ids),
                        },
                        "RESPONSE/HOST_LIST/HOST",
                    )
                    for host in host_detections:
                        host = Host(host)
                        host_list.append(host)
                        for detection in host.detection_list:
                            discovered_qids.append(detection.qid)

                    kb_map = self.qualys.lookup_knowledge_base(discovered_qids)

                    events_to_report = (
                        self.qualys.generate_security_events_from_detections(
                            hosts=host_list,
                            host_asset_map=qweb_id_map_of_host_assets,
                            kb_map=kb_map,
                            scans=[],
                        )
                    )

                    status_value, status_message = self.ingest_security_event_chunks(
                        events_to_report, []
                    )
                    multi_status.add_status(status_value, status_message)
            except ProxyError as e:
                self.logger.error(
                    f"DEC:1C2 An issue with the configured proxy was encountered: {e}."
                )
                multi_status.add_status(
                    StatusValue.GENERIC_ERROR,
                    f"DEC:1C2 An issue with the configured proxy was encountered: {e}.",
                )
                return multi_status
            except ConnectionError as e:
                self.logger.error(f"DEC:1C3 Unable to connect to the Qualys API: {e}")
                multi_status.add_status(
                    StatusValue.DEVICE_CONNECTION_ERROR,
                    f"DEC:1C3 Unable to connect to the Qualys API: {e}",
                )
                return multi_status
            except InvalidCredentialsError as e:
                self.logger.error(
                    f"DEC:1C1 Unauthorized response returned when collecting host VM detections from {self.qualys.api_server_base}."
                )
                multi_status.add_status(
                    StatusValue.AUTHENTICATION_ERROR,
                    f"DEC:1C1 Unauthorized response returned when collecting host VM detections from {self.qualys.api_server_base}.",
                )
                return multi_status
            except Exception as e:
                self.logger.exception(
                    f"DEC:1AC Error retrieving host VM detections: {e}"
                )
                multi_status.add_status(
                    StatusValue.GENERIC_ERROR,
                    f"DEC:1AC Error retrieving host VM detections: {e}",
                )
                return multi_status

        multi_status.add_status(
            StatusValue.OK, f"Successfully requested vulnerability detections."
        )
        return multi_status

    def ingest_security_event_chunks(
        self, chunk_events, failed_chunks_list
    ) -> tuple[StatusValue, str]:
        status_value: StatusValue = None
        status_message: str = None
        successful_events_count = 0
        # Add attributes to events
        attributes = self.activation_config._activation_context_json.get('dtAttributes', {})
        security_context = attributes.get("dt.security_context")
        cost_center = attributes.get("dt.cost.costcenter")
        product = attributes.get("dt.cost.product")
        for event in chunk_events:
            if security_context:
                event["dt.security_context"] = security_context
            if cost_center:
                event["dt.cost.costcenter"] = cost_center
            if product:
                event["dt.cost.product"] = product
            
            if self.dev_mode:
                if self.generate_mock_data:
                    # Read existing data or initialize empty list
                    try:
                        with open("mock_data.json", "r") as f:
                            existing_data = json.load(f)
                    except (FileNotFoundError, json.JSONDecodeError):
                        existing_data = []
                    existing_data.append(event)
                    with open("mock_data.json", "w") as f:
                        json.dump(existing_data, f)
                    continue
                print(json.dumps(event))
                print("----")
            
        self.logger.info(
            f"Sending {len(chunk_events)} events to {self.security_events_ingest_url}..."
        )
        resized_chunks = split_by_size(
            chunk_events, 10000000
        )  # ensure we don't send payloads larger than 10MBs to OpenPipeline

        failed_chunks = []
        for chunk in chain(resized_chunks, failed_chunks_list):
            try:
                resp = requests.post(
                    (self.security_events_ingest_url),
                    headers={"Authorization": f"Api-Token {self.dt_token}"},
                    json=chunk,
                    verify=(
                        False
                        if (
                            self.security_events_ingest_url.startswith(
                                "https://localhost"
                            )
                            or self.security_events_ingest_url.startswith(
                                "https://127.0.0.1"
                            )
                        )
                        else True
                    ),
                )
                self.logger.debug(f"Event ingestion result: {resp.status_code}")
                resp.raise_for_status()
                successful_events_count += len(chunk)
            except RequestException as e:
                reason = e
                try:
                    error = resp.json()
                    if error.get("error", {}).get("message"):
                        reason = error["error"]["message"]
                except Exception as e:
                    pass
                failed_chunks.append(chunk)
                self.logger.error(
                    f"DEC:C6 Failed POSTing security events to Dynatrace with exception: {reason}"
                )
                self.logger.debug(f"Failed chunk: {json.dumps(chunk)}")

        if failed_chunks != []:
            self.logger.error(
                f"DEC:C6 Failed ingest for {len(failed_chunks)} chunks of events."
            )
            failed_chunks_list = failed_chunks
            status_value = StatusValue.GENERIC_ERROR
            status_message = (
                f"DEC:C6 Failed ingest for {len(failed_chunks)} chunks of events."
            )
        if successful_events_count > 0:
            status_value = StatusValue.OK
            status_message = (
                f"Successfully ingested {successful_events_count} security events."
            )

        return status_value, status_message

    def fastcheck(self) -> Status:
        self.logger.setLevel("DEBUG")  # always debug for fast check
        try:
            qualys_config: dict = self.activation_config["qualys"]
            self.url_base = qualys_config.get("url_base")
            self.username = qualys_config.get("username")
            self.qualys: Qualys = Qualys(
                self.url_base,
                self.username,
                qualys_config.get("password"),
                self.logger,
                proxies={
                    "https": self.build_proxy_url(
                        self.activation_config.get("qualys", {}).get("proxy", {})
                    )
                },
            )
            self.qualys.get_host_assets_for_scans(
                vulns_updated_since=datetime.now(tz=timezone.utc)
                - timedelta(minutes=1),
                vulns_updated_to=datetime.now(tz=timezone.utc),
                result_limit=1,
            )
        except ProxyError as e:
            return Status(
                StatusValue.DEVICE_CONNECTION_ERROR,
                f"DEC:1C2 Unable to connect to {self.url_base} due to an issue with the configured proxy: {e}",
            )
        except ConnectionError as e:
            return Status(
                StatusValue.DEVICE_CONNECTION_ERROR,
                f"DEC:1C3 Unable to connect to the Qualys API: {e}",
            )
        except InvalidCredentialsError as e:
            return Status(
                StatusValue.AUTHENTICATION_ERROR,
                f"DEC:1C1 401 (unauthorized) response returned from {self.url_base}.",
            )
        except Exception as e:
            self.logger.exception(e)
            return Status(
                StatusValue.GENERIC_ERROR,
                f"DEC:1C0 Fastcheck to {self.url_base} failed for an unexpected reason: {e}.",
            )
        return Status(StatusValue.OK)

    @staticmethod
    def build_proxy_url(proxy_config: dict) -> str:
        proxy_address = proxy_config.get("address")
        proxy_username = proxy_config.get("username")
        proxy_password = proxy_config.get("password")

        if proxy_address:
            protocol, address = proxy_address.split("://")
            proxy_url = f"{protocol}://"
            if proxy_username:
                proxy_url += proxy_username
            if proxy_password:
                proxy_url += f":{proxy_password}"
            proxy_url += f"@{address}"
            return proxy_url

        return ""


def main():
    ExtensionImpl(name="qualys_appsec").run()


if __name__ == "__main__":
    main()
