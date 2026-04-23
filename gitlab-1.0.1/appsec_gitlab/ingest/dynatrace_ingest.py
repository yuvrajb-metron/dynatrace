"""
Dynatrace security events ingest (``platform/ingest/v1/security.events``).

Responsibility:
    Chunk flat event dicts under a byte limit, POST each chunk with the configured token,
    persist failed chunks to disk for retry on the next run, and return counts for status reporting.
"""

from urllib.parse import urlparse

from requests.exceptions import RequestException

from ..clients.http_client import RestApiHandler
from ..storage.failed_ingest_store import FailedIngestChunkStore
from ..utils.helpers import split_by_size
from dynatrace_extension.sdk.extension import extension_logger as logger

_failed_chunk_store = FailedIngestChunkStore()


def push_security_events_to_dynatrace(
    url: str,
    events: list[dict],
    security_events_interface: RestApiHandler,
    chunk_max_bytes: int,
) -> tuple[int, int]:
    """
    Push security events to Dynatrace in size-limited batches.

    Splits the event list into chunks under chunk_max_bytes, then POSTs each chunk.
    Previously failed chunks are tried first, then current chunks. New failures
    are stored for the next run.

    Returns ``(successful_event_count, failed_chunk_count)``. If there is nothing to
    send (empty events or no interface), returns ``(0, 0)``.
    """
    if not events or security_events_interface is None:
        return (0, 0)
    current_chunks = list(split_by_size(events, chunk_max_bytes))
    chunks_to_send = _failed_chunk_store.pop_all() + current_chunks

    host = (urlparse(url).hostname or "").lower()
    verify_ssl = host not in ("localhost", "127.0.0.1")
    failed_chunks: list[list[dict]] = []
    successful_event_count = 0
    for chunk in chunks_to_send:
        try:
            security_events_interface.post_url(url=url, json=chunk, verify=verify_ssl)
            successful_event_count += len(chunk)
            logger.debug(f"POSTed security ingest chunk: {len(chunk)} event(s)")
        except RequestException as err:
            failed_chunks.append(chunk)
            logger.warning(f"Failed POSTing events to Dynatrace: {err}")
        except Exception as err:
            failed_chunks.append(chunk)
            logger.warning(f"Unexpected Dynatrace ingest failure: {err}")
    if failed_chunks:
        _failed_chunk_store.extend(failed_chunks)
        logger.error(f"Failed ingest for {len(failed_chunks)} chunk(s). Will retry on the next run")
    return (successful_event_count, len(failed_chunks))
