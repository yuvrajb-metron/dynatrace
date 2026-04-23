"""Push security events to Dynatrace in chunks."""

import logging
from typing import Any

from requests.exceptions import RequestException

from ..clients.http_client import RestApiHandler
from ..utils.chunking import split_by_size
from dynatrace_extension.sdk.extension import extension_logger as logger

INGEST_CHUNK_MAX_BYTES = 10_000_000

_failed_chunks_cache: list[list[dict[str, Any]]] = []


def push_events_to_dynatrace(
    url: str,
    events: list[dict[str, Any]],
    security_events_interface: RestApiHandler,
) -> None:
    """
    Push events to Dynatrace in chunks (max 10MB per request).
    Failed chunks are kept and retried on the next call to this function.
    """
    if not events:
        return
    if security_events_interface is None:
        logger.warning("security_events_interface is None; skipping push.")
        return
    current_chunks = list(split_by_size(events, INGEST_CHUNK_MAX_BYTES))
    chunks_to_send = _failed_chunks_cache + current_chunks
    _failed_chunks_cache.clear()

    verify_ssl = not (
        url.startswith("https://localhost") or url.startswith("https://127.0.0.1")
    )

    failed_chunks = []
    for chunk in chunks_to_send:
        try:
            security_events_interface.post_url(url=url, json=chunk, verify=verify_ssl)
            logger.info("Pushed %d event(s) to Dynatrace", len(chunk))
        except RequestException as err:
            failed_chunks.append(chunk)
            logger.warning(f"Failed POSTing events to Dynatrace: {err}")

    _failed_chunks_cache.extend(failed_chunks)
    if failed_chunks:
        logger.error(
            f"Failed ingest for {len(failed_chunks)} chunk(s). Will retry on the next run",
        )
