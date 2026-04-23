"""
Data structures for Docker Scout CLI output (SARIF findings and SBOM image metadata).
Used by parsing modules and event builders.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SbomArtifactRecord:
    """One entry from SBOM top-level ``artifacts[]`` (name, version, paths, purl, type)."""

    pkg_type: str
    name: str
    version: str
    purl: str
    author: Optional[str]
    paths: List[str] = field(default_factory=list)


@dataclass
class ParsedFinding:
    """One vulnerability finding from SARIF (result joined with rule metadata)."""

    rule_id: str
    message: str
    artifact_path: str
    severity: str
    security_score: Optional[float]
    purls: List[str]
    affected_version: Optional[str]
    fixed_version: Optional[str]
    short_description: str
    help_text: str
    help_uri: Optional[str] = None
    sarif_version: Optional[str] = None
    sarif_schema: Optional[str] = None
    rule_raw: Dict[str, Any] = field(default_factory=dict)
    result_raw: Dict[str, Any] = field(default_factory=dict)
    tool_driver_full_name: Optional[str] = None


@dataclass
class ImageMetadata:
    """Image metadata extracted from SBOM source.image (distro, platform, digest, tags)."""

    name: str
    digest: str
    tags: List[str]
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    platform_os: Optional[str] = None
    architecture: Optional[str] = None
    attestation_reference: Optional[str] = None
    sbom_artifacts: List[SbomArtifactRecord] = field(default_factory=list)
    sbom_root: Optional[Dict[str, Any]] = None
