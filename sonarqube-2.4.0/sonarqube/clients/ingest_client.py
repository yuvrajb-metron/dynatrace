from itertools import chain

import requests
from dynatrace_extension.sdk.status import MultiStatus, StatusValue

from sonarqube.config.ingest_config import IngestConfig
from sonarqube.utils.size_util import split_by_size


class IngestClient:
    def __init__(self, config: IngestConfig, logger):
        self.config = config
        self.logger = logger

    def ingest_openpipeline(
        self, events: list, failed_chunks_list: list, endpoint: str, multi_status: MultiStatus
    ):
        total_chunks = 0
        resized_chunks = split_by_size(events, 10000000)
        failed_chunks = []
        for chunk in chain(resized_chunks, failed_chunks_list):
            total_chunks += 1
            try:
                response = requests.post(
                    endpoint,
                    json=chunk,
                    headers=self.config.get_headers_with_api_token(),
                    verify=(
                        not (
                            endpoint.startswith("https://localhost")
                            or endpoint.startswith("https://127.0.0.1")
                        )
                    ),
                )
                response.raise_for_status()
            except requests.RequestException as e:
                self.logger.warning(
                    f"DEC:C6 Failed POSTing events to Dynatrace endpoint {endpoint} with exception {e}"
                )
                failed_chunks.append(chunk)

        if failed_chunks != []:
            self.logger.error(
                f"DEC:C6 Failed ingest for {len(failed_chunks)}/{total_chunks} "
                f"chunks of events to endpoint {endpoint}."
            )
            multi_status.add_status(
                StatusValue.GENERIC_ERROR,
                f"DEC:C6 Failed ingest for {len(failed_chunks)}/{total_chunks} "
                f"chunks of events to endpoint {endpoint}.",
            )
            failed_chunks_list = failed_chunks
        else:
            self.logger.info(f"Successfully ingested {len(events)} events to endpoint {endpoint}")
