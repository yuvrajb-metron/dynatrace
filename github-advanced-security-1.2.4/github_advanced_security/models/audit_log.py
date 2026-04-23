from typing import Dict, List
from datetime import datetime

from ..github_object import GithubObject

class ActorLocation(GithubObject):
    def _create_from_raw_data(self, raw_element):
        self.country_code: str = raw_element.get("country_code")

class AuditLogEntry(GithubObject):
    def _create_from_raw_data(self, raw_element):
        self.timestamp: datetime = raw_element['@timestamp']
        self.action: str = raw_element.get("action")
        self.active: bool = raw_element.get("active")
        self.active_was: bool = raw_element.get("active_was")
        self.actor: str = raw_element.get("actor", "GitHub")
        self.actor_id: str = raw_element.get("actor_id")
        self.actor_location: ActorLocation = ActorLocation(raw_element=raw_element["actor_location"]) if raw_element.get("actor_location") else None
        self.org_id: int = raw_element.get("org_id")
        self.user_id: int = raw_element.get("user_id")
        self.business_id: int = raw_element.get("business_id")
        self.blocked_user: str = raw_element.get("blocked_user")
        self.business: str = raw_element.get("business")
        self.config: List[dict] = raw_element.get("config", [])
        self.config_was: List[dict] = raw_element.get("config_was", [])
        self.content_type: str = raw_element.get("content_type")
        self.operation_type: str = raw_element.get("operation_type")
        self.created_at: datetime = datetime.fromtimestamp(raw_element.get("created_at") / 1000)
        self.events: List[dict] = raw_element.get("events", [])
        self.events_were: List[dict] = raw_element.get("events_were", [])
        self.org: str = raw_element.get("org")
        self.repo: str = raw_element.get("repo")
        self.original_content: Dict = raw_element
