"""Core: Docker Hub discovery, Scout runner, polling."""

from .polling import run_discovery_and_ingest

__all__ = ["run_discovery_and_ingest"]
