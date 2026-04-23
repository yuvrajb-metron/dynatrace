"""
Parse SBOM JSON from docker scout sbom --format json.

Extracts source.image: name, digest, tags, distro, platform.
Returns ImageMetadata or None.
"""

import json
from typing import Any, Dict, List, Optional, Set

from appsec_dockerscout.models import ImageMetadata, SbomArtifactRecord
from dynatrace_extension.sdk.extension import extension_logger as logger


def collect_sbom_artifact_paths(artifact: Dict[str, Any]) -> List[str]:
    """
    Collect filesystem paths from ``locations`` and ``files`` for one SBOM artifact.

    Args:
        artifact: One element of SBOM ``artifacts[]``.

    Returns:
        Deduped paths in encounter order (aligned with SARIF URI matching).
    """
    paths: List[str] = []
    seen: Set[str] = set()
    for loc in artifact.get("locations") or []:
        if not isinstance(loc, dict):
            continue
        raw = loc.get("path")
        if isinstance(raw, str) and raw.strip():
            p = raw.strip()
            if p not in seen:
                seen.add(p)
                paths.append(p)
    for f in artifact.get("files") or []:
        if not isinstance(f, dict):
            continue
        raw = f.get("path")
        if isinstance(raw, str) and raw.strip():
            p = raw.strip()
            if p not in seen:
                seen.add(p)
                paths.append(p)
    return paths


def _parse_sbom_artifacts(data: dict) -> List[SbomArtifactRecord]:
    """
    Build ``SbomArtifactRecord`` rows from SBOM ``artifacts[]``.

    Args:
        data: Parsed SBOM root object.

    Returns:
        Records with package metadata and paths for SARIF URI / purl matching.
    """
    out: List[SbomArtifactRecord] = []
    for a in data.get("artifacts") or []:
        if not isinstance(a, dict):
            continue
        paths = collect_sbom_artifact_paths(a)
        pt = a.get("type")
        pkg_type = pt.strip().lower() if isinstance(pt, str) else ""
        nm = a.get("name")
        ver = a.get("version")
        pu = a.get("purl")
        auth = a.get("author")
        out.append(
            SbomArtifactRecord(
                pkg_type=pkg_type,
                name=nm if isinstance(nm, str) else "",
                version=ver if isinstance(ver, str) else "",
                purl=pu if isinstance(pu, str) else "",
                author=auth if isinstance(auth, str) else None,
                paths=paths,
            )
        )
    return out


def parse_sbom(sbom_json: str) -> Optional[ImageMetadata]:
    """
    Parse SBOM JSON from docker scout sbom --format json.

    Args:
        sbom_json: Raw SBOM JSON string.

    Returns:
        ImageMetadata with name, digest, tags, os_name, os_version, platform_os,
        architecture from source.image (and distro/platform). None on decode error
        or if source.type is not "image".
    """
    n = len(sbom_json) if sbom_json else 0
    logger.debug(f"parse_sbom started: input_len={n}")
    try:
        data = json.loads(sbom_json)
    except json.JSONDecodeError as e:
        logger.warning(f"SBOM JSON decode error: {e}")
        return None
    source = data.get("source") or {}
    logger.debug(f"parse_sbom: source.type={source.get('type')}")
    if source.get("type") != "image":
        logger.debug("parse_sbom: skipping (source.type is not 'image').")
        return None
    image = source.get("image") or {}
    name = image.get("name") or ""
    digest = image.get("digest") or ""
    tags = image.get("tags") or []
    if not isinstance(tags, list):
        tags = []
    distro = image.get("distro") or {}
    os_name = distro.get("os_name")
    os_version = distro.get("os_version")
    platform = image.get("platform") or {}
    platform_os = platform.get("os")
    architecture = platform.get("architecture")
    attestation_reference = None
    for att in data.get("attestations") or []:
        if not isinstance(att, dict):
            continue
        ref = att.get("reference")
        if isinstance(ref, str) and ref.strip():
            attestation_reference = ref.strip()
            break
    digest_preview = (digest[:24] + "...") if digest and len(digest) > 24 else (digest or "")
    logger.debug(f"parse_sbom finished: name={name or '(empty)'}, digest={digest_preview}")
    sbom_artifacts = _parse_sbom_artifacts(data)
    logger.debug(f"parse_sbom: artifacts count={len(sbom_artifacts)}")
    return ImageMetadata(
        name=name,
        digest=digest,
        tags=tags,
        os_name=os_name,
        os_version=os_version,
        platform_os=platform_os,
        architecture=architecture,
        attestation_reference=attestation_reference,
        sbom_artifacts=sbom_artifacts,
        sbom_root=data,
    )
