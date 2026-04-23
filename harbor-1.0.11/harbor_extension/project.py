import logging
from typing import Dict, Any, List, Optional
from .harbor_object import HarborObject

default_log = logging.getLogger(__name__)


class Project(HarborObject):
    def _create_from_raw_data(self, raw_element: Dict[str, Any]):
        self.project_id: int = raw_element.get("project_id")
        self.name: str = raw_element.get("name")
        self.repo_count: int = raw_element.get("repo_count")
