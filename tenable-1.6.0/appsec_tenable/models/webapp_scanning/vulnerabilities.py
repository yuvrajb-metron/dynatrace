from typing import Any


class Request:
    def __init__(self, data: dict[str, Any]):
        self.headers: str = data.get("headers")
        self.body: str = data.get("body")
        self.original_data: dict[str, Any] = data


class Response:
    def __init__(self, data: dict[str, Any]):
        self.headers: str = data.get("headers")
        self.body: str = data.get("body")
        self.time: float = data.get("time")
        self.original_data: dict[str, Any] = data


class DetailedDetails:
    def __init__(self, data: dict[str, Any]):
        self.input_name: str | None = data.get("input_name")
        self.input_type: str | None = data.get("input_type")
        self.output: str = data.get("output")
        self.proof: str | None = data.get("proof")
        self.payload: str | None = data.get("payload")
        self.selector: str | None = data.get("selector")
        self.selector_url: str | None = data.get("selector_url")
        self.signature: str | None = data.get("signature")
        self.request: Request | None = Request(data.get("request", {})) if data.get("request") else None
        self.response: Response | None = Response(data.get("response", {})) if data.get("response") else None
        self.original_data: dict[str, Any] = data


class Attachment:
    def __init__(self, data: dict[str, Any]):
        self.attachment_id: str = data.get("attachment_id")
        self.created_at: str = data.get("created_at")
        self.attachment_name: str = data.get("attachment_name")
        self.md5: str = data.get("md5")
        self.file_type: str = data.get("file_type")
        self.size: int = data.get("size")
        self.original_data: dict[str, Any] = data


class VulnerabilityDetails:
    def __init__(self, data: dict[str, Any]):
        self.vuln_id: str = data.get("vuln_id")
        self.scan_id: str = data.get("scan_id")
        self.plugin_id: int = data.get("plugin_id")
        self.created_at: str = data.get("created_at")
        self.uri: str = data.get("uri")
        self.is_page: bool = data.get("is_page")
        self.details: DetailedDetails = DetailedDetails(data.get("details", {}))
        self.attachments: list[Attachment] = [Attachment(att) for att in data.get("attachments", [])]
        self.original_data: dict[str, Any] = data


class Details:
    def __init__(self, data: dict[str, Any]):
        self.input_name: Any | None = data.get("input_name")
        self.input_type: Any | None = data.get("input_type")
        self.output: str = data.get("output")
        self.proof: Any | None = data.get("proof")
        self.payload: Any | None = data.get("payload")
        self.selector: Any | None = data.get("selector")
        self.selector_url: Any | None = data.get("selector_url")
        self.signature: Any | None = data.get("signature")
        self.request: Any | None = data.get("request")
        self.response: Any | None = data.get("response")
        self.original_data: dict[str, Any] = data


class Vulnerability:
    def __init__(self, data: dict[str, Any]):
        self.vuln_id: str = data.get("vuln_id")
        self.scan_id: str = data.get("scan_id")
        self.plugin_id: int = data.get("plugin_id")
        self.created_at: str = data.get("created_at")
        self.uri: str = data.get("uri")
        self.is_page: bool = data.get("is_page")
        self.details: Details = Details(data.get("details", {}))
        self.attachments: list[Attachment] = [Attachment(att) for att in data.get("attachments", [])]
        self.original_data: dict[str, Any] = data


class VulnerabilityStore(dict):
    def add_vulnerability(
        self,
        vuln_id: str,
        scan_id: str,
        plugin_id: str,
        vulnerability_details: VulnerabilityDetails | None = None,
    ):
        self[vuln_id] = vulnerability_details
        self[(scan_id, plugin_id)] = vulnerability_details

    def get_vulnerability(self, scan_id: str, plugin_id: str) -> VulnerabilityDetails | None:
        return self.get((scan_id, plugin_id))
