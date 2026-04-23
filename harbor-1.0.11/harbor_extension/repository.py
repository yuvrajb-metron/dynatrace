import logging
from typing import Dict, Any, List, Optional
from .harbor_object import HarborObject

default_log = logging.getLogger(__name__)


class Repository(HarborObject):
    def _create_from_raw_data(self, raw_element: Dict[str, Any]):
        self.id: str = raw_element.get("id")
        self.project_id: str = raw_element.get("project_id")
        self.name: str = raw_element.get("name").split("/", 1)[
            1
        ]  # this is actually {project}/{name}
        self.description: str = raw_element.get("description")
