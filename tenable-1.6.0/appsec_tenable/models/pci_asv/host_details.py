from typing import Any


class Info:
    def __init__(self, data: dict[str, Any]):
        self.mac_address: Any | None = data.get("mac-address")
        self.host_fqdn: str = data.get("host-fqdn")
        self.host_ip: str = data.get("host-ip")
        self.operating_system: list[str] = data.get("operating-system", [])
        self.host_end: str = data.get("host_end")
        self.host_start: str = data.get("host_start")
        self.original_data: dict[str, Any] = data


class Vulnerability:
    def __init__(self, data: dict[str, Any]):
        self.count: int = data.get("count")
        self.host_id: int = data.get("host_id")
        self.hostname: str = data.get("hostname")
        self.plugin_family: str = data.get("plugin_family")
        self.plugin_id: int = data.get("plugin_id")
        self.plugin_name: str = data.get("plugin_name")
        self.severity: int = data.get("severity")
        self.severity_index: int = data.get("severity_index")
        self.original_data: dict[str, Any] = data


class HostData:
    def __init__(self, data: dict[str, Any]):
        self.info: Info = Info(data.get("info", {}))
        self.vulnerabilities: list[Vulnerability] = [
            Vulnerability(vuln) for vuln in data.get("vulnerabilities", [])
        ]
        self.compliance: list[Vulnerability] = [Vulnerability(comp) for comp in data.get("compliance", [])]
        self.original_data: dict[str, Any] = data
