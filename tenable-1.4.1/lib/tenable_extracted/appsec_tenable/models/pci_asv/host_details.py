from typing import Any

# DTO in python
"""
PCI ASV Explained (name of folder why???)
    PCI ASV stands for Payment Card Industry Approved Scanning Vendor. This is a specific security compliance framework for organizations that handle credit card data.

What is PCI ASV?
PCI DSS (Payment Card Industry Data Security Standard) - The main security standard for credit card data
ASV (Approved Scanning Vendor) - Companies certified by PCI to perform vulnerability scans
Tenable is one of these approved vendors

Why This Naming?
The pci_asv folder structure suggests this Python application is specifically designed to:
Process Tenable scan results for PCI compliance
Extract vulnerability data that meets PCI ASV requirements
Format data for PCI compliance reporting
Handle specific PCI scanning workflows


lets say this JSON is coming from the Tenable API
    The Python code safely extracts each field, handling cases where:
    Keys might be missing
    Values might be null
    Arrays might be empty

{
  "info": {
    "mac-address": "00:11:22:33:44:55",
    "host-fqdn": "server1.company.com",
    "host-ip": "192.168.1.100",
    "operating-system": ["Windows Server 2019"],
    "host_start": "2024-01-01T00:00:00Z",
    "host_end": "2024-01-01T23:59:59Z"
  },
  "vulnerabilities": [
    {
      "plugin_id": 12345,
      "plugin_name": "SSL/TLS Certificate Expiry",
      "severity": 2,
      "count": 1
    }
  ],
  "compliance": []
}
"""
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
