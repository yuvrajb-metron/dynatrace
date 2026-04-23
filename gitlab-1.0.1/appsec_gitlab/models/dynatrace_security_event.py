"""
Thin wrapper around a flat security-event dict for Dynatrace ingest.

Provides a single place to copy the payload into the shape expected by the HTTP API.
"""

from __future__ import annotations


class DynatraceSecurityEvent:
    """
    Hold one security event payload (scan or finding) before POST.

    Responsibility:
        Store the finalized key/value map produced by event builders.
    """

    def __init__(self, payload: dict | None = None) -> None:
        """
        Args:
            payload: Flat Dynatrace security event fields (already filtered).
        """
        self.payload = payload or {}

    def to_ingest_dict(self) -> dict:
        """
        Returns:
            Shallow copy of ``payload`` for JSON serialization.
        """
        return {**self.payload}
