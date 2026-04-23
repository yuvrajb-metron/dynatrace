# ruff: noqa: ARG002

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
from tenable.io import TenableIO

from .models.vulnerability_management.assets import Asset
from .models.vulnerability_management.scans import ScanDetails
from .models.vulnerability_management.vulns import VulnerabilityDetails
from .models.webapp_scanning.findings import WebAppFinding
from .models.webapp_scanning.scans import WAScan, WAScanConfig
from .models.webapp_scanning.vulnerabilities import VulnerabilityStore
from .rest_interface import Auth, RestApiHandler
from .utils.pci_asv.scans import generate_and_ingest_pci_asv_scan_events
from .utils.shared import format_with_in_clause, paged_endpoint, split_by_size
from .utils.vulnerability_management.scans import (
    generate_and_ingest_scan_events,
    save_scan_history,
)
from .utils.vulnerability_management.vulns import generate_event_from_vuln
from .utils.webapp_scanning.findings import generate_event_from_webapp_finding
from .utils.webapp_scanning.scans import generate_events_from_webapp_scan_details, get_webapp_scan_history


class ExtensionImpl(Extension):
    def initialize(self):
        if self.activation_config["advancedOptions"]["debugLogs"]:
            self.logger.setLevel("DEBUG")
        else:
            self.logger.setLevel("INFO")

        # Dynatrace API
        # logs or events
        self.ingest_as_logs = self.activation_config["connection"].get("ingestAsLogs", False)
        if self.ingest_as_logs:
            self.logger.info("Ingesting all data as logs")
        else:
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
            )  # logger=self.logger)

        # Tenable API
        self.url: str = self.activation_config["connection"]["tenableUrl"]
        self.access_key: str = self.activation_config["connection"]["accessKey"]
        self.secret_key: str = self.activation_config["connection"][
            "secretKey"
        ]  # os.environ.get("TENABLE_SECRET")

        self.tio: TenableIO = TenableIO(self.access_key, self.secret_key, url=self.url)
        self.manual_tio: RestApiHandler = RestApiHandler(
            self.url,
            Auth(
                type="Header",
                header_key="X-ApiKeys",
                header_value=f"accessKey={self.access_key};secretKey={self.secret_key}",
            ),
            # logger=self.logger,
        )

        # Vulnerability management config
        self.fetch_vulns: bool = self.activation_config["products"]["vulnerabilityManagement"]
        self.fetch_info_vulnerabilities: bool = self.activation_config["advancedOptions"].get(
            "fetchInfoVulnerabilities"
        )
        self.vulns_first_ingest_window: int = self.activation_config["advancedOptions"].get(
            "firstTimeFetchWindow"
        )
        self.vulns_frequency: int = self.activation_config["advancedOptions"].get("vulnsFetchFrequency")

        self.vulns_first_ingest: bool = True
        self.number_of_vulnerabilites_reported: int = 0
        self.failed_vuln_chunks: list = []
        self.failed_scan_chunks: list = []

        if self.fetch_vulns:
            self.vuln_management_database_file = f"vuln_management-{self.monitoring_config_id}.db"
            vuln_management_database_file_path = Path(self.vuln_management_database_file)
            if vuln_management_database_file_path.exists():
                vuln_management_database_file_path.unlink()

        # PCI ASV config
        self.fetch_pci_asv: bool = self.activation_config["products"].get("pciAsv", False)

        self.pci_vulns_first_ingest: bool = True

        if self.fetch_pci_asv:
            self.pci_asv_database_file = f"pci_asv-{self.monitoring_config_id}.db"
            pci_asv_database_file_path = Path(self.pci_asv_database_file)
            if pci_asv_database_file_path.exists():
                pci_asv_database_file_path.unlink()

        # Web app config
        self.fetch_webapp_vulns: bool = self.activation_config["products"].get("webAppScanning", False)

        self.webapp_first_ingest: bool = True
        self.number_of_webapp_findings_reported: int = 0

        # Audit logs config
        self.fetch_audit_logs: bool = self.activation_config["products"]["tenablePlatform"]
        self.audit_logs_first_ingest_window: int = self.activation_config["advancedOptions"].get(
            "firstTimeFetchWindow"
        )
        self.audit_logs_collection_frequency: int = self.activation_config["advancedOptions"].get(
            "auditFetchFrequency"
        )

        self.audit_logs_first_ingest: bool = True
        self.previously_collected_audit_ids: list[str] = []

        # Scheduling

        if self.fetch_vulns:
            self.schedule(self.report_vulnerabilities, interval=timedelta(hours=self.vulns_frequency))

        if self.fetch_pci_asv:
            self.schedule(self.report_pci_asv_vulns, interval=timedelta(hours=self.vulns_frequency))

        if self.fetch_webapp_vulns:
            self.schedule(self.report_webapp_vulns, interval=timedelta(hours=self.vulns_frequency))

        if self.fetch_audit_logs:
            self.schedule(
                self.report_audit_logs, interval=timedelta(hours=self.audit_logs_collection_frequency)
            )

    ####################################
    # Tenable vulnerability management #
    ####################################

    def report_vulnerabilities(self):
        multi_status: MultiStatus = MultiStatus()

        sqlite_conn = sqlite3.connect(self.vuln_management_database_file)
        with sqlite_conn:
            sqlite_conn.execute(
                """CREATE TABLE IF NOT EXISTS scan_history (
                    scan_history_uuid TEXT PRIMARY KEY,
                    scan_id INTEGER,
                    scan_history_object TEXT
                )"""
            )

        self.logger.info("Starting asset vulnerability ingest")
        self.number_of_vulnerabilites_reported = 0

        if self.vulns_first_ingest:
            datetime_to_query = datetime.now(timezone.utc) - timedelta(hours=self.vulns_first_ingest_window)
            timestamp_to_query = int(datetime_to_query.timestamp())
            self.vulns_first_ingest = False
        else:
            datetime_to_query = datetime.now(timezone.utc) - timedelta(hours=self.vulns_frequency)
            timestamp_to_query = int(datetime_to_query.timestamp())
        severity = (
            ["info", "low", "medium", "high", "critical"]
            if self.fetch_info_vulnerabilities
            else ["low", "medium", "high", "critical"]
        )

        # Get all assets in order to enrich vulns with metadata
        self.logger.info(f"Fetching asset data for last_assessed={datetime_to_query}.")
        assets_exporter = self.tio.exports.assets(chunk_size=1000, last_assessed=timestamp_to_query)
        assets: dict[str, Asset] = {}
        for page in assets_exporter:
            assets[page.get("id")] = Asset(page)
        self.logger.info("Finished fetching asset data.")

        # Get all recent scans filtering out PCI-ASV scans
        recent_scans = self.tio.scans.list(last_modified=timestamp_to_query)
        self.logger.info(f"Fetching scan execution details for {len(recent_scans)} scans.")
        save_scan_history(self.tio, recent_scans, datetime_to_query, pci_asv=False, conn=sqlite_conn)
        self.logger.info("Fetched scan execution details.")

        # Ingest vulnerabilities
        vulnerabilities = self.tio.exports.vulns(
            num_assets=100, last_found=timestamp_to_query, severity=severity
        )

        extra_scan_details: dict[str, ScanDetails] = {}
        jobs = vulnerabilities.run_threaded(
            self.ingest_vulns_chunk,
            {"assets": assets, "extra_scan_details": extra_scan_details, "multi_status": multi_status},
            num_threads=1,
        )
        concurrent.futures.wait(jobs)
        for job in jobs:
            try:
                job.result()
            except:
                raise

        self.logger.info(f"Attempted ingest of {self.number_of_vulnerabilites_reported} vulnerabilities.")
        multi_status.add_status(
            StatusValue.OK, f"Attempted ingest of {self.number_of_vulnerabilites_reported} vulnerabilities."
        )

        # Store newly generated scan events in database
        scan_details_to_store = (
            (history_uuid, -1, details.data) for history_uuid, details in extra_scan_details.items()
        )
        try:
            with sqlite_conn:
                sqlite_conn.executemany("INSERT INTO scan_history VALUES (?, ?, ?)", scan_details_to_store)
            self.logger.debug(f"Stored {len(extra_scan_details)} extra scan details in database.")
        except Exception as e:
            self.logger.warning(
                "Unable to store generated scans in database. Scan findings may be incomplete."
            )
            self.logger.exception(e)

        # Ingest scans
        # This needs to run after the vuln ingest, since we can potentially enrich with more scans
        self.logger.info("Generating scan events.")
        number_of_scan_events = generate_and_ingest_scan_events(
            assets,
            sqlite_conn,
            lambda x, y: self.ingest_chunks(x, y, multi_status),
            100,
            self.failed_scan_chunks,
            ingest_as_logs=self.ingest_as_logs,
        )

        self.logger.info(f"Attempted ingest of {number_of_scan_events} scan events.")
        multi_status.add_status(StatusValue.OK, f"Attempted ingest of {number_of_scan_events} scan events.")

        sqlite_conn.close()
        database_file_path = Path(self.vuln_management_database_file)
        if database_file_path.exists():
            database_file_path.unlink()

        return multi_status

    def ingest_vulns_chunk(
        self,
        data,
        export_uuid: str,
        export_type: str,
        export_chunk_id: str,
        version,
        assets: dict[str, Asset],
        extra_scan_details: dict[str, ScanDetails],
        multi_status: MultiStatus,
    ):
        self.logger.debug(f"Attempting ingest of vuln chunks of length {len(data)}")
        sqlite_conn = sqlite3.connect(self.vuln_management_database_file)
        with sqlite_conn:
            try:
                scan_uuids = {vuln.get("scan").get("uuid") for vuln in data}
                scans = sqlite_conn.execute(
                    format_with_in_clause(
                        (
                            "SELECT scan_history_uuid, scan_history_object FROM scan_history "
                            "WHERE scan_history_uuid"
                        ),
                        scan_uuids,
                    ),
                    tuple(scan_uuids),
                )
                scan_details: dict[str, ScanDetails] = {
                    scan[0]: ScanDetails(json.loads(scan[1])) for scan in scans
                }
            except Exception as e:
                self.logger.warning("Unable to find scan details for vulns in database.")
                self.logger.exception(e)
                scan_details = {}
            chunk_events = [
                event
                for vuln in data
                for event in generate_event_from_vuln(
                    self.access_key,
                    self.secret_key,
                    self.url,
                    VulnerabilityDetails(vuln),
                    assets,
                    scan_details,
                    extra_scan_details,
                    ingest_as_logs=self.ingest_as_logs,
                )
            ]
        sqlite_conn.close()

        self.number_of_vulnerabilites_reported += len(chunk_events)
        self.logger.debug(f"Number of vulns reported thus far: {self.number_of_vulnerabilites_reported}")

        self.ingest_chunks(chunk_events, self.failed_vuln_chunks, multi_status)

    ############################
    # Tenable PCI-ASV Scanning #
    ############################

    def report_pci_asv_vulns(self):
        multi_status: MultiStatus = MultiStatus()

        sqlite_conn = sqlite3.connect(self.pci_asv_database_file)
        with sqlite_conn:
            sqlite_conn.execute(
                """CREATE TABLE IF NOT EXISTS pci_asv_vulns (
                vulnerability_object TEXT
                )"""
            )
            sqlite_conn.execute(
                """CREATE TABLE IF NOT EXISTS pci_asv_scan_history (
                    scan_history_uuid TEXT PRIMARY KEY,
                    scan_id INTEGER,
                    scan_history_object TEXT
                )"""
            )

        self.logger.info("Starting PCI ASV vulnerability ingest")

        if self.pci_vulns_first_ingest:
            datetime_to_query = datetime.now(timezone.utc) - timedelta(hours=self.vulns_first_ingest_window)
            timestamp_to_query = int(datetime_to_query.timestamp())
            self.pci_vulns_first_ingest = False
        else:
            datetime_to_query = datetime.now(timezone.utc) - timedelta(hours=self.vulns_frequency)
            timestamp_to_query = int(datetime_to_query.timestamp())

        # Get all recent scans filtering only PCI-ASV scans
        recent_scans = self.tio.scans.list(last_modified=timestamp_to_query)
        self.logger.info(f"Fetching PCI scan execution details for {len(recent_scans)} scans.")
        save_scan_history(self.tio, recent_scans, datetime_to_query, pci_asv=True, conn=sqlite_conn)
        self.logger.info("Fetched PCI scan execution details.")

        # Ingest scans and populate PCI ASV vulns database
        self.logger.info("Generating scan events.")
        plugins = {}
        number_of_scan_events = generate_and_ingest_pci_asv_scan_events(
            self.access_key,
            self.secret_key,
            self.url,
            plugins,
            sqlite_conn,
            lambda x, y: self.ingest_chunks(x, y, multi_status),
            100,
            self.fetch_info_vulnerabilities,
            self.failed_scan_chunks,
            self.ingest_as_logs,
        )

        self.logger.info(f"Attempted ingest of {number_of_scan_events} scan events.")
        multi_status.add_status(StatusValue.OK, f"Attempted ingest of {number_of_scan_events} scan events.")

        # Ingest PCI-ASV vulnerabilities from database
        with sqlite_conn:
            pci_vulns = [
                json.loads(result[0])
                for result in sqlite_conn.execute("SELECT vulnerability_object FROM pci_asv_vulns")
            ]
            self.ingest_chunks(pci_vulns, failed_chunks_list=[], multi_status=multi_status)
        self.logger.info(f"Attempted ingest of {len(pci_vulns)} PCI ASV vulnerability finding events.")
        multi_status.add_status(
            StatusValue.OK, f"Attempted ingest of {len(pci_vulns)} PCI ASV vulnerability finding events."
        )

        sqlite_conn.close()
        database_file_path = Path(self.pci_asv_database_file)
        if database_file_path.exists():
            database_file_path.unlink()

        return multi_status

    ############################
    # Tenable Web App Scanning #
    ############################

    def report_webapp_vulns(self):
        multi_status: MultiStatus = MultiStatus()
        if self.webapp_first_ingest:
            datetime_to_query = datetime.now(timezone.utc) - timedelta(hours=self.vulns_first_ingest_window)
            self.webapp_first_ingest = False
        else:
            datetime_to_query = datetime.now(timezone.utc) - timedelta(hours=self.vulns_frequency)
        timestamp_to_query = int(datetime_to_query.timestamp())
        severity = (
            ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            if self.fetch_info_vulnerabilities
            else ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        )
        # datetime_iso_to_query = datetime_to_query.isoformat().replace("+00:00", "Z")
        # datetime_day_to_query = datetime_iso_to_query.split("T")[0].replace("-", "/")
        self.logger.info("Starting Web App vulnerability ingest")

        # Get scan data first
        was_scan_configs = [
            WAScanConfig(scan)
            for scan in paged_endpoint(
                self.manual_tio.post_url,
                url=urljoin(self.url, "/was/v2/configs/search"),
                headers=[],
                params={
                    "limit": 100,
                },
            )
        ]
        recent_was_scans_details = {
            scan_id: scan_details
            for scan_config in was_scan_configs
            for scan_history in get_webapp_scan_history(
                self.manual_tio, scan_config.config_id, datetime_to_query
            )
            for scan_id, scan_details in scan_history.items()
        }

        # Before doing the WAS export, get data from the old vulnerability APIs
        # to be able to complement missing data
        # To simplify, we don't do this yet.
        was_vulns = None  # get_vulns_data(self.manual_tio, datetime_day_to_query, datetime_to_query)

        was_exports = self.tio.exports.was(num_assets=100, last_found=timestamp_to_query, severity=severity)

        jobs = was_exports.run_threaded(
            self.ingest_webapp_chunks,
            {
                "was_scans_details": recent_was_scans_details,
                "was_vulns": was_vulns,
                "multi_status": multi_status,
            },
            num_threads=1,
        )
        concurrent.futures.wait(jobs)
        for job in jobs:
            try:
                job.result()
            except:
                raise

        multi_status.add_status(
            StatusValue.OK, f"Attempted ingest of {self.number_of_webapp_findings_reported} webapp findings."
        )

        # Ingest scan data after findings, since we enrich
        scan_events = [
            generate_events_from_webapp_scan_details(scan, self.ingest_as_logs)
            for scan in recent_was_scans_details.values()
        ]
        self.ingest_chunks(scan_events, self.failed_scan_chunks, multi_status)
        self.logger.info(f"Attempted ingest of {len(scan_events)} webapp scan events.")
        multi_status.add_status(StatusValue.OK, f"Attempted ingest of {len(scan_events)} webapp scan events.")

        return multi_status

    def ingest_webapp_chunks(
        self,
        data,
        export_uuid: str,
        export_type: str,
        export_chunk_id: str,
        version,
        was_scans_details: dict[str, WAScan],
        was_vulns: list[VulnerabilityStore],
        multi_status: MultiStatus,
    ):
        self.logger.debug(f"Attempting ingest of webapp vuln chunks of length {len(data)}")
        chunk_events = [
            event
            for vuln in data
            for event in generate_event_from_webapp_finding(
                WebAppFinding(vuln),
                was_scans_details,
                was_vulns,
                self.url,
                ingest_as_logs=self.ingest_as_logs,
            )
        ]
        self.number_of_webapp_findings_reported += len(chunk_events)
        self.logger.debug(
            f"Number of webapp vulns reported thus far: {self.number_of_vulnerabilites_reported}"
        )

        self.ingest_chunks(chunk_events, self.failed_vuln_chunks, multi_status)

    ##############
    # Audit Logs #
    ##############

    def report_audit_logs(self):
        multi_status: MultiStatus = MultiStatus()
        if self.audit_logs_first_ingest:
            timestamp_to_collect = (
                (datetime.now(timezone.utc) - timedelta(hours=self.audit_logs_first_ingest_window))
                .isoformat()
                .replace("+00:00", "Z")
            )
            self.audit_logs_first_ingest = False
        else:
            timestamp_to_collect = (
                (datetime.now(timezone.utc) - timedelta(hours=self.audit_logs_collection_frequency))
                .isoformat()
                .replace("+00:00", "Z")
            )
        events = self.tio.audit_log.events(
            ("date", "gt", timestamp_to_collect),
        )

        for e in events:
            audit_message = None
            if e.id not in self.previously_collected_audit_ids:
                if e.fields:
                    for field in e.fields:
                        if field.get("key") == "message":
                            audit_message = field.get("value")

                log_entry = {
                    "level": "INFO",
                    "log.source": "Tenable",
                    "content": json.dumps(e),
                    "audit.identity": e.actor.name if e.actor.name else e.target.name,
                    "audit.action": e.action,
                    "audit.result": "Succeeded" if not e.is_failure else "Failed",
                    "audit.status": "Succeeded" if not e.is_failure else "Failed",
                    "audit.time": e.received,
                    "result.message": audit_message,
                    "id": e.id,
                    "description": e.description,
                    "dt.extension.name": "com.dynatrace.extension.tenable",
                    "dt.extension.config.id": self.monitoring_config_id,
                    "extension.config.name": self.monitoring_config_name,
                }
                self.report_log_event(log_entry)
                self.previously_collected_audit_ids.append(e.id)

        self.logger.info(f"Attempted ingest of {len(self.previously_collected_audit_ids)} audit events.")
        multi_status.add_status(
            StatusValue.OK, f"Attempted ingest of {len(self.previously_collected_audit_ids)} audit events."
        )
        self.previously_collected_audit_ids = []

        return multi_status

    #########
    # Other #
    #########

    def ingest_chunks(self, chunk_events, failed_chunks_list, multi_status: MultiStatus) -> None:
        resized_chunks = split_by_size(
            chunk_events, 10000000
        )  # ensure we don't send payloads larger than 10MBs to OpenPipeline
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
                        f"DEC:C6 Failed POSTing security events to Dynatrace with exception {e}"
                    )
                else:
                    self.logger.warning(
                        f"DEC:C6 Failed ingesting event logs into Dynatrace with exception {e}"
                    )

        if failed_chunks != []:
            self.logger.error(
                f"DEC:C6 Failed ingest for {len(failed_chunks)} chunks of events. "
                "Will attempt re-ingest on the next run"
            )
            multi_status.add_status(
                StatusValue.GENERIC_ERROR,
                (
                    f"DEC:C6 Failed ingest for {len(failed_chunks)} chunks of events. "
                    "Will attempt re-ingest on the next run"
                ),
            )
            failed_chunks_list = failed_chunks

    def fastcheck(self) -> Status:
        """
        This is called when the extension runs for the first time.
        If this AG cannot run this extension, raise an Exception or return StatusValue.ERROR!
        """
        return Status(StatusValue.OK)

    def on_shutdown(self):
        if self.fetch_vulns:
            self.vuln_management_database_file = f"vuln_management-{self.monitoring_config_id}.db"
            vuln_management_database_file_path = Path(self.vuln_management_database_file)
            if vuln_management_database_file_path.exists():
                vuln_management_database_file_path.unlink()

        if self.fetch_pci_asv:
            self.pci_asv_database_file = f"pci_asv-{self.monitoring_config_id}.db"
            pci_asv_database_file_path = Path(self.pci_asv_database_file)
            if pci_asv_database_file_path.exists():
                pci_asv_database_file_path.unlink()


def main():
    ExtensionImpl(name="appsec_tenable").run()


if __name__ == "__main__":
    main()
