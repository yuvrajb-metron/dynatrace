"""
Build one VULNERABILITY_SCAN event for Dynatrace security ingest.

One scan event per image; uses image ref, optional SBOM metadata, scan id/times.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from appsec_dockerscout.utils.constants import (
    EVENT_PROVIDER,
    EVENT_TYPE_VULNERABILITY_SCAN,
    OBJECT_TYPE_CONTAINER_IMAGE,
    PRODUCT_NAME,
    PRODUCT_VENDOR,
    SCAN_STATUS_COMPLETED,
)
from appsec_dockerscout.events.vul_finding import resolve_object_identity, sbom_reference_excerpt
from appsec_dockerscout.models import ImageRef, ImageMetadata
from dynatrace_extension.sdk.extension import extension_logger as logger


def make_scan_id(image_ref: ImageRef) -> str:
    """
    Build ``scan.id`` / ``scan.name`` as ``org/repo:<ISO8601 timestamp>``.

    Args:
        image_ref: Image reference (org, repo, tag).

    Returns:
        Unique scan identifier string for this invocation.
    """
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    scan_id = f"{image_ref.org}/{image_ref.repo}:{ts}"
    logger.debug(f"make_scan_id: image_ref={image_ref.full_name}, scan_id={scan_id}")
    return scan_id


def build_vulnerability_scan(
    image_ref: ImageRef,
    image_meta: Optional[ImageMetadata],
    scan_id: str,
    scan_started: str,
    scan_completed: str,
    finding_count: int = 0,
    product_name: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build one VULNERABILITY_SCAN event per image for Dynatrace security ingest.

    Args:
        image_ref: Image reference (org/repo:tag).
        image_meta: Optional SBOM image metadata.
        scan_id: Scan identifier.
        scan_started: ISO8601 scan start time.
        scan_completed: ISO8601 scan end time.
        finding_count: Number of findings for this scan.
        product_name: runs[0].tool.driver.fullName from SARIF when available.

    Returns:
        Single event dict for security.events ingest.
        ``event.original_content`` is JSON ``{"sbom": {...}}`` with the SBOM excerpt used for
        ``object.id`` / ``object.name`` (``source.image``, ``attestations``) when SBOM was parsed;
        otherwise ``"{}"``.
        ``container_image.*`` matches VULNERABILITY_FINDING (registry, repository, tags, digest).
    """
    logger.debug(
        f"build_vulnerability_scan: image_ref={image_ref.full_name}, "
        f"scan_id={scan_id}, finding_count={finding_count}"
    )
    object_id, object_name, repo_name = resolve_object_identity(image_ref, image_meta)
    pname = product_name or PRODUCT_NAME
    sbom_ex = sbom_reference_excerpt(image_meta)
    original_content = (
        json.dumps({"sbom": sbom_ex}, ensure_ascii=False) if sbom_ex else "{}"
    )

    event: Dict[str, Any] = {
        "event.provider": EVENT_PROVIDER,
        "event.type": EVENT_TYPE_VULNERABILITY_SCAN,
        "event.description": f"Scan completed for object {object_name} ({OBJECT_TYPE_CONTAINER_IMAGE})",
        "event.original_content": original_content,
        "product.vendor": PRODUCT_VENDOR,
        "product.name": pname,
        "object.type": OBJECT_TYPE_CONTAINER_IMAGE,
        "object.id": object_id,
        "object.name": object_name,
        "scan.id": scan_id,
        "scan.name": scan_id,
        "scan.status": SCAN_STATUS_COMPLETED,
        "scan.time.started": scan_started,
        "scan.time.completed": scan_completed,
        "container_image.registry": "docker.io",
        "container_image.repository": repo_name,
        "container_image.tags": image_meta.tags if image_meta else [image_ref.tag],
    }
    if image_meta and image_meta.digest:
        event["container_image.digest"] = image_meta.digest
    return event
