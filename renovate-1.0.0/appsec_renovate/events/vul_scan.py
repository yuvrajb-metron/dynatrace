"""Build Dynatrace VULNERABILITY_SCAN event from RepositoryScan."""

import uuid
from typing import Any

from ..models import RepositoryScan
from .constants import (
    EVENT_PROVIDER,
    EVENT_TYPE_VULNERABILITY_SCAN,
    OBJECT_TYPE_FOR_VULNERABILITY_SCAN,
    PRODUCT_NAME,
    PRODUCT_VENDOR,
)

class VulnerabilityScanEventBuilder:
    """Builds one VULNERABILITY_SCAN flat event dict from RepositoryScan."""

    def __init__(self, repository_scan: RepositoryScan) -> None:
        self.repository_scan = repository_scan

    def build(self) -> dict[str, Any]:
        """Build one VULNERABILITY_SCAN flat event dict."""
        repo_name = self.repository_scan.repository_name or ""
        original_content = self.repository_scan.original_content or ""
        return {
            "event.provider": EVENT_PROVIDER,
            "event.type": EVENT_TYPE_VULNERABILITY_SCAN,
            "event.description": f"Repository {repo_name} scan event",
            "event.id": str(uuid.uuid4()),
            "event.original_content": original_content,
            "object.type": OBJECT_TYPE_FOR_VULNERABILITY_SCAN,
            "object.id": repo_name,
            "object.name": repo_name,
            "product.vendor": PRODUCT_VENDOR,
            "product.name": PRODUCT_NAME,
            "scan.id": self.repository_scan.scan_id or "",
            "scan.name": self.repository_scan.scan_name or "",
            "scan.status": self.repository_scan.scan_status or "",
            "scan.time.started": self.repository_scan.scan_time_started or "",
            "scan.time.completed": self.repository_scan.scan_time_completed or "",
        }