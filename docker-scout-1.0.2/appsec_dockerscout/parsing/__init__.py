"""Parsing: Docker Scout CVES SARIF and SBOM JSON into models."""

from .cves_parser import parse_sarif
from .sbom_parser import parse_sbom

__all__ = ["parse_sarif", "parse_sbom"]
