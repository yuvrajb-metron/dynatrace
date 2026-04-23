# ruff: noqa: B006
"""Chunk items by total size (e.g. for Dynatrace ingest payload limits)."""

import json
from typing import Any


def size_of_record(record: Any) -> int:
    """
    Return the size in bytes of a record when serialized as JSON (UTF-8).

    Args:
        record: Any JSON-serializable object.

    Returns:
        Byte length, or 0 if serialization fails.
    """
    try:
        return len(json.dumps(record, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        return 0


def split_by_size(items, max_size, get_size=size_of_record):
    """
    Split an iterable into chunks so each chunk's total serialized size is <= ``max_size``.

    Args:
        items: Iterable of records to chunk.
        max_size: Maximum total size in bytes per chunk.
        get_size: Callable returning byte size for one item (default JSON UTF-8 length).

    Yields:
        Lists of items forming each chunk.
    """
    buffer = []
    buffer_size = 0
    for item in items:
        item_size = get_size(item)
        if buffer_size + item_size <= max_size:
            buffer.append(item)
            buffer_size += item_size
        else:
            if buffer:
                yield buffer
            buffer = [item]
            buffer_size = item_size
    if buffer:
        yield buffer
