import logging
from typing import Dict, Any
from datetime import datetime
from .harbor_object import HarborObject
from .shared import datetime_from_harbor_timestamp

default_log = logging.getLogger(__name__)


class AuditLogEntry(HarborObject):
    def _create_from_raw_data(self, raw_element: Dict[str, Any]):
        self.id: int = raw_element.get("id")
        self.op_time: datetime = datetime_from_harbor_timestamp(
            raw_element.get("op_time")
        )
        self.operation: str = raw_element.get("operation")
        self.resource: str = raw_element.get("resource")
        self.resource_type: str = raw_element.get("resource_type")
        self.username: str = raw_element.get("username")
        self.original_content: dict = raw_element
