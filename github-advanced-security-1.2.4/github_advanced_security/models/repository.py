import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..github_object import GithubObject


class Repository(GithubObject):
    def _create_from_raw_data(self, raw_element: Dict[str, Any]):
        self.id: str = raw_element["id"]
        self.name: str = raw_element["name"]
        self.full_name: str = raw_element["full_name"]
