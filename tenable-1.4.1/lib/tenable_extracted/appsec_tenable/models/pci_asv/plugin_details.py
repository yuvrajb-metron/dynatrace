from typing import Any

# DTO in python

""" 
In Your Security Context
hashmap in python
The dict[str, Any] pattern is perfect for JSON API responses because:
JSON keys are always strings
JSON values can be anything (string, number, boolean, array, object)
Tenable API responses have mixed data types

{
  "id": 12345,
  "name": "SSL/TLS Certificate Expiry Check",
  "family_name": "Web Servers",
  "attributes": [
    {
      "attribute_name": "days_until_expiry",
      "attribute_value": "30"
    },
    {
      "attribute_name": "check_critical_certs",
      "attribute_value": "true"
    }
  ]
}
""" 

class Attribute:
    def __init__(self, data: dict[str, Any]):
        self.attribute_name: str = data.get("attribute_name")
        self.attribute_value: str = data.get("attribute_value")
        self.original_data: dict[str, Any] = data


class Plugin:
    def __init__(self, data: dict[str, Any]):
        self.id: int = data.get("id")
        self.name: str = data.get("name")
        self.family_name: str = data.get("family_name")
        self.attributes: list[Attribute] = [Attribute(attr) for attr in data.get("attributes", [])]
        self.original_data: dict[str, Any] = data
