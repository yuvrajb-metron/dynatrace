"""
JSON file persistence for security ingest chunks that failed to POST to Dynatrace.

On the next successful poll, ``push_security_events_to_dynatrace`` prepends these chunks
so they are retried before new data.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class FailedIngestChunkStore:
    """
    Append-only file store of ``list[list[dict]]`` representing failed POST bodies.

    Responsibility:
        ``pop_all`` reads and deletes the file; ``extend`` appends failed chunks for retry.
    """

    def __init__(self, storage_path: str | Path = "failed_ingest_chunks.json") -> None:
        """
        Args:
            storage_path: Path to the JSON file (default in extension working directory).
        """
        self.storage_path = Path(storage_path)

    def pop_all(self) -> list[list[dict[str, Any]]]:
        """
        Returns:
            All stored chunks, then removes the file if it existed.
        """
        chunks = self._read()
        if self.storage_path.exists():
            self.storage_path.unlink()
        return chunks

    def extend(self, chunks: list[list[dict[str, Any]]]) -> None:
        """
        Args:
            chunks: New failed chunks to append to any existing file content.
        """
        existing = self._read()
        existing.extend(chunks)
        self.storage_path.write_text(json.dumps(existing, ensure_ascii=False))

    def _read(self) -> list[list[dict[str, Any]]]:
        if not self.storage_path.exists():
            return []
        try:
            data = json.loads(self.storage_path.read_text())
        except (OSError, json.JSONDecodeError):
            return []
        if not isinstance(data, list):
            return []
        return data
