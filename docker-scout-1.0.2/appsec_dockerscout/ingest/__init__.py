"""Push security events to Dynatrace (chunked)."""

from .dynatrace import push_events_to_dynatrace

__all__ = ["push_events_to_dynatrace"]
