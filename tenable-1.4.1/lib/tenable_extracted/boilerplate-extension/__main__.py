# Dynatrace Extension Boilerplate Template
# Based on appsec_tenable extension structure
# 
# This template provides a complete foundation for building Dynatrace extensions
# that integrate with external APIs and map data to Dynatrace semantic dictionary

import concurrent.futures
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from itertools import chain
from pathlib import Path
from urllib.parse import urljoin

from dynatrace_extension import Extension, Status, StatusValue
from dynatrace_extension.sdk.status import MultiStatus
from requests.exceptions import RequestException

# TODO: Replace with your API client library
# Example: from your_api_client import YourAPIClient
# from .models.your_domain.your_models import YourDataModel
# from .rest_interface import Auth, RestApiHandler
# from .utils.shared import format_with_in_clause, paged_endpoint, split_by_size
# from .utils.your_domain.your_logic import process_your_data


class ExtensionImpl(Extension):
    def initialize(self):
        """
        Initialize the extension with configuration and setup connections.
        This method is called once when the extension starts.
        """
        # TODO: Configure logging level based on debug settings
        if self.activation_config["advancedOptions"]["debugLogs"]:
            self.logger.setLevel("DEBUG")
        else:
            self.logger.setLevel("INFO")

        # TODO: Configure Dynatrace API connection
        # Option 1: Ingest as security events (recommended for security data)
        self.ingest_as_logs = self.activation_config["connection"].get("ingestAsLogs", False)
        if self.ingest_as_logs:
            self.logger.info("Ingesting all data as logs")
        else:
            # Option 2: Ingest as security events via REST API
            self.dynatrace_url: str = self.activation_config["connection"].get("dynatraceUrl")
            self.dynatrace_access_token: str = self.activation_config["connection"].get(
                "dynatraceAccessToken"
            )

            self.dynatrace_auth: Auth = Auth(
                type="Header",
                header_key="Authorization",
                header_value=f"Api-Token {self.dynatrace_access_token}",
            )

            self.security_events_interface = RestApiHandler(
                url=self.dynatrace_url, auth=self.dynatrace_auth
            )

        # TODO: Configure your external API connection
        # Replace these with your API configuration
        self.external_api_url: str = self.activation_config["connection"]["externalApiUrl"]
        self.external_api_key: str = self.activation_config["connection"]["apiKey"]
        self.external_api_secret: str = self.activation_config["connection"].get("apiSecret", "")

        # TODO: Initialize your API client
        # Example: self.external_client = YourAPIClient(
        #     api_key=self.external_api_key,
        #     api_secret=self.external_api_secret,
        #     base_url=self.external_api_url
        # )

        # TODO: Configure manual REST interface if needed
        # self.manual_api_handler = RestApiHandler(
        #     self.external_api_url,
        #     Auth(
        #         type="Header",
        #         header_key="Authorization",  # Replace with your API's auth header
        #         header_value=f"Bearer {self.external_api_key}",  # Replace with your auth format
        #     ),
        # )

        # TODO: Configure your data collection settings
        # Replace with your specific data types and settings
        self.fetch_data_type_1: bool = self.activation_config["products"]["dataType1"]
        self.fetch_data_type_2: bool = self.activation_config["products"].get("dataType2", False)
        
        # TODO: Configure collection frequency and lookback window
        self.data_collection_frequency: int = self.activation_config["advancedOptions"].get("collectionFrequency", 1)
        self.first_ingest_window: int = self.activation_config["advancedOptions"].get("firstTimeFetchWindow", 24)
        
        # TODO: Initialize tracking variables
        self.first_ingest: bool = True
        self.number_of_records_reported: int = 0
        self.failed_chunks: list = []

        # TODO: Setup database for temporary storage if needed
        if self.fetch_data_type_1:
            self.database_file = f"your_extension-{self.monitoring_config_id}.db"
            database_file_path = Path(self.database_file)
            if database_file_path.exists():
                database_file_path.unlink()

        # TODO: Schedule your data collection methods
        # Replace with your specific data collection methods
        if self.fetch_data_type_1:
            self.schedule(
                self.collect_data_type_1, 
                interval=timedelta(hours=self.data_collection_frequency)
            )

        if self.fetch_data_type_2:
            self.schedule(
                self.collect_data_type_2, 
                interval=timedelta(hours=self.data_collection_frequency)
            )

    ####################################
    # TODO: Replace with your data collection methods
    ####################################

    def collect_data_type_1(self):
        """
        TODO: Replace this method with your primary data collection logic.
        This is where you'll fetch data from your external API and process it.
        """
        multi_status: MultiStatus = MultiStatus()

        # TODO: Setup database if needed
        sqlite_conn = sqlite3.connect(self.database_file)
        with sqlite_conn:
            sqlite_conn.execute(
                """CREATE TABLE IF NOT EXISTS your_table (
                    id TEXT PRIMARY KEY,
                    data_object TEXT
                )"""
            )

        self.logger.info("Starting data type 1 collection")
        self.number_of_records_reported = 0

        # TODO: Calculate time window for data collection
        if self.first_ingest:
            datetime_to_query = datetime.now(timezone.utc) - timedelta(hours=self.first_ingest_window)
            timestamp_to_query = int(datetime_to_query.timestamp())
            self.first_ingest = False
        else:
            datetime_to_query = datetime.now(timezone.utc) - timedelta(hours=self.data_collection_frequency)
            timestamp_to_query = int(datetime_to_query.timestamp())

        # TODO: Fetch data from your external API
        # Example:
        # try:
        #     external_data = self.external_client.get_data(
        #         since=timestamp_to_query,
        #         limit=1000
        #     )
        # except Exception as e:
        #     self.logger.error(f"Failed to fetch data from external API: {e}")
        #     return multi_status

        # TODO: Process and transform your data
        # Example:
        # processed_events = []
        # for item in external_data:
        #     event = self.transform_to_dynatrace_event(item)
        #     processed_events.append(event)

        # TODO: Ingest data to Dynatrace
        # self.ingest_chunks(processed_events, self.failed_chunks, multi_status)

        self.logger.info(f"Attempted ingest of {self.number_of_records_reported} records.")
        multi_status.add_status(
            StatusValue.OK, f"Attempted ingest of {self.number_of_records_reported} records."
        )

        # TODO: Cleanup database
        sqlite_conn.close()
        database_file_path = Path(self.database_file)
        if database_file_path.exists():
            database_file_path.unlink()

        return multi_status

    def collect_data_type_2(self):
        """
        TODO: Replace this method with your secondary data collection logic.
        Use this for additional data types or different API endpoints.
        """
        multi_status: MultiStatus = MultiStatus()
        
        # TODO: Implement your secondary data collection logic here
        # Similar structure to collect_data_type_1 but for different data
        
        return multi_status

    ####################################
    # TODO: Replace with your data processing methods
    ####################################

    def process_data_chunk(
        self,
        data,
        export_uuid: str,
        export_type: str,
        export_chunk_id: str,
        version,
        multi_status: MultiStatus,
    ):
        """
        TODO: Replace this method with your data processing logic.
        This processes chunks of data from your external API.
        """
        self.logger.debug(f"Processing data chunk of length {len(data)}")
        
        # TODO: Process your data chunk
        # Example:
        # chunk_events = []
        # for item in data:
        #     event = self.transform_to_dynatrace_event(item)
        #     chunk_events.append(event)
        
        # self.number_of_records_reported += len(chunk_events)
        # self.ingest_chunks(chunk_events, self.failed_chunks, multi_status)

    def transform_to_dynatrace_event(self, external_data_item):
        """
        TODO: Replace this method with your data transformation logic.
        This converts your external API data to Dynatrace semantic dictionary format.
        
        Key Dynatrace semantic dictionary fields to consider:
        - dt.entity.* (for entity mapping)
        - security.* (for security events)
        - audit.* (for audit events)
        - custom.* (for custom fields)
        """
        
        # TODO: Map your external data to Dynatrace semantic dictionary
        # Example transformation:
        event = {
            # TODO: Add your specific event fields
            "event.type": "SECURITY_EVENT",  # or "AUDIT_EVENT", "CUSTOM_EVENT"
            "event.kind": "SECURITY_FINDING",  # or appropriate event kind
            
            # TODO: Map to Dynatrace semantic dictionary
            "security.finding.id": external_data_item.get("id"),
            "security.finding.name": external_data_item.get("name"),
            "security.finding.severity": self.map_severity(external_data_item.get("severity")),
            "security.finding.status": external_data_item.get("status"),
            
            # TODO: Add entity mapping if applicable
            "dt.entity.host": external_data_item.get("hostname"),
            "dt.entity.process_group": external_data_item.get("service"),
            
            # TODO: Add timestamps
            "event.start_time": external_data_item.get("timestamp"),
            "event.end_time": external_data_item.get("timestamp"),
            
            # TODO: Add custom fields
            "custom.your_field": external_data_item.get("your_field"),
            
            # TODO: Add extension metadata
            "dt.extension.name": "com.dynatrace.extension.your_extension",
            "dt.extension.config.id": self.monitoring_config_id,
            "extension.config.name": self.monitoring_config_name,
        }
        
        return event

    def map_severity(self, external_severity):
        """
        TODO: Replace this method with your severity mapping logic.
        Map your external API severity levels to Dynatrace severity levels.
        """
        # TODO: Implement your severity mapping
        # Example:
        severity_mapping = {
            "critical": "CRITICAL",
            "high": "HIGH", 
            "medium": "MEDIUM",
            "low": "LOW",
            "info": "INFO"
        }
        return severity_mapping.get(external_severity.lower(), "UNKNOWN")

    ####################################
    # Utility methods (keep these as-is)
    ####################################

    def ingest_chunks(self, chunk_events, failed_chunks_list, multi_status: MultiStatus) -> None:
        """
        Ingest data chunks to Dynatrace with proper error handling and retry logic.
        Keep this method as-is - it handles the ingestion mechanics.
        """
        resized_chunks = split_by_size(
            chunk_events, 10000000
        )  # ensure we don't send payloads larger than 10MBs
        failed_chunks = []
        for chunk in chain(resized_chunks, failed_chunks_list):
            try:
                if not self.ingest_as_logs:
                    self.security_events_interface.post_url(json=chunk)
                else:
                    self.report_log_events(chunk)
            except RequestException as e:
                failed_chunks.append(chunk)
                if not self.ingest_as_logs:
                    self.logger.warning(
                        f"Failed POSTing events to Dynatrace with exception {e}"
                    )
                else:
                    self.logger.warning(
                        f"Failed ingesting event logs into Dynatrace with exception {e}"
                    )

        if failed_chunks != []:
            self.logger.error(
                f"Failed ingest for {len(failed_chunks)} chunks of events. "
                "Will attempt re-ingest on the next run"
            )
            multi_status.add_status(
                StatusValue.GENERIC_ERROR,
                (
                    f"Failed ingest for {len(failed_chunks)} chunks of events. "
                    "Will attempt re-ingest on the next run"
                ),
            )
            failed_chunks_list = failed_chunks

    def fastcheck(self) -> Status:
        """
        This is called when the extension runs for the first time.
        If this AG cannot run this extension, raise an Exception or return StatusValue.ERROR!
        """
        # TODO: Add any pre-flight checks here
        # Example: verify API connectivity, check credentials, etc.
        return Status(StatusValue.OK)

    def on_shutdown(self):
        """
        Cleanup method called when the extension shuts down.
        """
        # TODO: Add any cleanup logic here
        # Example: close database connections, cleanup temporary files, etc.
        if hasattr(self, 'database_file'):
            database_file_path = Path(self.database_file)
            if database_file_path.exists():
                database_file_path.unlink()


def main():
    """
    Main entry point for the extension.
    TODO: Replace "your_extension_name" with your actual extension name.
    """
    ExtensionImpl(name="your_extension_name").run()


if __name__ == "__main__":
    main()
