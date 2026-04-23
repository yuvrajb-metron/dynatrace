# Data Models Boilerplate
# Based on appsec_tenable models structure
# 
# This provides data model classes for your external API responses.
# Replace these with models specific to your API.

import json
from typing import Any


class BaseModel:
    """
    Base model class with common functionality.
    All your data models should inherit from this.
    """
    def __init__(self, data: dict[str, Any]):
        self.data = data
        self.original_data = json.dumps(data)  # Store original for debugging
    
    def __str__(self):
        return self.original_data
    
    def get(self, key: str, default=None):
        """Safe getter with default value."""
        return self.data.get(key, default)


class ExternalAPIEntity(BaseModel):
    """
    TODO: Replace this with your external API's main entity model.
    This represents the primary data structure from your external API.
    """
    def __init__(self, data: dict[str, Any]):
        super().__init__(data)
        
        # TODO: Replace these fields with your API's actual fields
        self.id = data.get("id")
        self.name = data.get("name")
        self.description = data.get("description")
        self.status = data.get("status")
        self.severity = data.get("severity")
        self.created_at = data.get("created_at")
        self.updated_at = data.get("updated_at")
        self.tags = data.get("tags", [])
        
        # TODO: Add nested objects if your API has them
        # self.metadata = ExternalAPIMetadata(data.get("metadata", {}))
        # self.location = ExternalAPILocation(data.get("location", {}))


class ExternalAPIMetadata(BaseModel):
    """
    TODO: Replace this with your API's metadata structure.
    Example nested object within your main entity.
    """
    def __init__(self, data: dict[str, Any]):
        super().__init__(data)
        
        # TODO: Replace with your metadata fields
        self.source = data.get("source")
        self.category = data.get("category")
        self.priority = data.get("priority")
        self.confidence = data.get("confidence")


class ExternalAPILocation(BaseModel):
    """
    TODO: Replace this with your API's location/geographic data.
    Example nested object for location information.
    """
    def __init__(self, data: dict[str, Any]):
        super().__init__(data)
        
        # TODO: Replace with your location fields
        self.country = data.get("country")
        self.region = data.get("region")
        self.city = data.get("city")
        self.coordinates = data.get("coordinates")


class ExternalAPIAsset(BaseModel):
    """
    TODO: Replace this with your API's asset/host information.
    Represents assets or hosts in your external system.
    """
    def __init__(self, data: dict[str, Any]):
        super().__init__(data)
        
        # TODO: Replace with your asset fields
        self.asset_id = data.get("asset_id")
        self.hostname = data.get("hostname")
        self.ip_address = data.get("ip_address")
        self.operating_system = data.get("operating_system")
        self.asset_type = data.get("asset_type")
        self.last_seen = data.get("last_seen")


class ExternalAPIScan(BaseModel):
    """
    TODO: Replace this with your API's scan information.
    Represents scan results or assessments from your external system.
    """
    def __init__(self, data: dict[str, Any]):
        super().__init__(data)
        
        # TODO: Replace with your scan fields
        self.scan_id = data.get("scan_id")
        self.scan_name = data.get("scan_name")
        self.scan_type = data.get("scan_type")
        self.status = data.get("status")
        self.started_at = data.get("started_at")
        self.completed_at = data.get("completed_at")
        self.scan_duration = data.get("scan_duration")


class ExternalAPIVulnerability(BaseModel):
    """
    TODO: Replace this with your API's vulnerability information.
    Represents security vulnerabilities or findings.
    """
    def __init__(self, data: dict[str, Any]):
        super().__init__(data)
        
        # TODO: Replace with your vulnerability fields
        self.vuln_id = data.get("vuln_id")
        self.title = data.get("title")
        self.description = data.get("description")
        self.severity = data.get("severity")
        self.cvss_score = data.get("cvss_score")
        self.cve_id = data.get("cve_id")
        self.affected_assets = data.get("affected_assets", [])
        self.first_found = data.get("first_found")
        self.last_found = data.get("last_found")


class ExternalAPIAuditLog(BaseModel):
    """
    TODO: Replace this with your API's audit log information.
    Represents audit trail or log entries from your external system.
    """
    def __init__(self, data: dict[str, Any]):
        super().__init__(data)
        
        # TODO: Replace with your audit log fields
        self.log_id = data.get("log_id")
        self.timestamp = data.get("timestamp")
        self.user = data.get("user")
        self.action = data.get("action")
        self.resource = data.get("resource")
        self.result = data.get("result")
        self.ip_address = data.get("ip_address")
        self.user_agent = data.get("user_agent")


# TODO: Add more model classes as needed for your specific API
# Examples:
# - ExternalAPIPolicy
# - ExternalAPIUser
# - ExternalAPIIntegration
# - ExternalAPINotification
