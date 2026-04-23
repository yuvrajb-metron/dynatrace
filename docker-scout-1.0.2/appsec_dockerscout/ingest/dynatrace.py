"""Push security events to Dynatrace in chunks."""

from typing import Any

from requests.exceptions import RequestException

from appsec_dockerscout.clients import RestApiHandler
from appsec_dockerscout.utils.chunking import split_by_size
from appsec_dockerscout.utils.constants import INGEST_CHUNK_MAX_BYTES
from dynatrace_extension.sdk.extension import extension_logger as logger

_failed_chunks_cache: list[list[dict[str, Any]]] = []


def push_events_to_dynatrace(
    url: str,
    events: list[dict[str, Any]],
    security_events_interface: RestApiHandler,
) -> None:
    """
    Push events to Dynatrace in chunks (max 10MB per request).

    Failed chunks are cached and merged ahead of the next batch on the following call.

    Args:
        url: Security events ingest URL.
        events: Event dicts to send.
        security_events_interface: Authenticated HTTP client for POST.

    Returns:
        None.
    """
    logger.debug(f"push_events_to_dynatrace started: events_count={len(events)}, url={url}")
    if not events:
        return
    if security_events_interface is None:
        logger.warning("security_events_interface is None; skipping push.")
        return
    current_chunks = list(split_by_size(events, INGEST_CHUNK_MAX_BYTES))
    chunks_to_send = _failed_chunks_cache + current_chunks
    _failed_chunks_cache.clear()
    _cached = len(chunks_to_send) - len(current_chunks)
    logger.debug(
        f"push_events_to_dynatrace: current_chunks={len(current_chunks)}, "
        f"retried_from_cache={_cached}, total_chunks={len(chunks_to_send)}"
    )

    verify_ssl = not (
        url.startswith("https://localhost") or url.startswith("https://127.0.0.1")
    )
    logger.debug(f"push_events_to_dynatrace: verify_ssl={verify_ssl}")

    failed_chunks = []
    for chunk in chunks_to_send:
        try:
            security_events_interface.post_url(url=url, json=chunk, verify=verify_ssl)
            logger.info(f"Pushed {len(chunk)} event(s) to Dynatrace")
        except RequestException as err:
            failed_chunks.append(chunk)
            logger.warning(f"Failed POSTing events to Dynatrace: {err}")

    _failed_chunks_cache.extend(failed_chunks)
    logger.debug(f"push_events_to_dynatrace ended: failed_chunks={len(failed_chunks)}")
    if failed_chunks:
        logger.error(
            f"Failed ingest for {len(failed_chunks)} chunk(s). Will retry on the next run"
        )
