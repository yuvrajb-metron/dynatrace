# ruff: noqa: B006
"""Chunk items by total size (e.g. for Dynatrace ingest payload limits)."""

import json
from typing import Any


def size_of_record(record: Any) -> int:
    """Return size in bytes of a record when serialized as JSON (UTF-8)."""
    try:
        return len(json.dumps(record, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        return 0


def split_by_size(items, max_size, get_size=size_of_record):
    """
    Split items into chunks so each chunk's total size is <= max_size.
    Used to keep Dynatrace ingest payloads under the ~10MB limit.
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
