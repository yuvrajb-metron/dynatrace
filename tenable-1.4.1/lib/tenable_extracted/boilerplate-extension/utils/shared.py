# Shared Utilities Boilerplate
# Based on appsec_tenable utils/shared.py
# 
# This provides common utility functions for data processing,
# API communication, and Dynatrace integration

import json
from typing import Protocol
from urllib import parse

from requests.models import Response

from .rest_interface import Header, RestApiHandler


def size_of_record(record):
    """Calculate the size of a record in bytes for chunking purposes."""
    return len(json.dumps(record).encode())


def split_by_size(items, max_size, get_size=size_of_record):
    """
    Split a list of items into chunks based on size limits.
    Useful for ensuring API payloads don't exceed size limits.
    """
    buffer = []
    buffer_size = 0
    for item in items:
        item_size = get_size(item)
        if buffer_size + item_size <= max_size:
            buffer.append(item)
            buffer_size += item_size
        else:
            yield buffer
            buffer = [item]
            buffer_size = item_size
    if buffer_size > 0:
        yield buffer


def format_with_in_clause(query, in_vals):
    """
    Format SQL query with IN clause for dynamic number of values.
    Useful for database queries with variable number of parameters.
    """
    return query + " IN ({})".format(",".join(["?"] * len(in_vals)))


def get_risk_score_from_level(risk_level: str) -> float:
    """
    Convert risk level string to numeric score.
    TODO: Customize this mapping based on your external API's risk levels.
    """
    risk_score = 0
    if risk_level == "CRITICAL":
        risk_score = 10
    elif risk_level == "HIGH":
        risk_score = 8.9
    elif risk_level == "MEDIUM":
        risk_score = 6.9
    elif risk_level == "LOW":
        risk_score = 3.9
    elif risk_level == "INFO":
        risk_score = 1.0

    return risk_score


def get_paged_endpoint(rest_interface: RestApiHandler, headers: None | list[Header], params: None | dict):
    """
    Handle paginated API endpoints automatically.
    Fetches all pages of data from a paginated API endpoint.
    """
    first_response = rest_interface.get_url(headers=headers, params=params)
    first_response_json = first_response.json()

    response_items: list = first_response_json.get("items")
    if first_response_json.get("pagination"):
        limit = first_response_json.get("pagination").get("limit")
        total = first_response_json.get("pagination").get("total")

        offset = limit
        while offset + limit < total:
            next_page_response = rest_interface.get_url(headers=headers, params={**params, "offset": offset})
            next_page_response_json = next_page_response.json()
            response_items.extend(next_page_response_json.get("items"))

            limit = next_page_response.get("pagination").get("limit")
            offset += limit

    return response_items


def parse_url(url_string: str) -> dict[str]:
    """
    Parse URL string into components.
    Useful for extracting domain, path, query parameters, etc.
    """
    unquoted_url = parse.unquote(url_string)
    parsed_url = parse.urlparse(unquoted_url)
    url_port = (
        parsed_url.port if parsed_url.port is not None else ("80" if parsed_url.scheme == "http" else "443")
    )

    return {
        "url_scheme": parsed_url.scheme if parsed_url.scheme != "" else None,
        "url_domain": parsed_url.netloc if parsed_url.netloc != "" else None,
        "url_port": url_port,
        "url_path": parsed_url.path if parsed_url.path != "" else None,
        "url_query": parsed_url.query if parsed_url.query != "" else None,
        "url_full": unquoted_url,
    }


class ApiCaller(Protocol):
    """
    Protocol for API calling functions.
    Used for type hints in paged_endpoint function.
    """
    def __call__(
        self, url: None | str = None, headers: list[Header] = [], params: None | dict = None
    ) -> Response:
        pass


def paged_endpoint(
    calling_function: ApiCaller,
    url: None | str = None,
    headers: None | list[Header] = None,
    params: None | dict = None,
    **kwargs,
):
    """
    Generic paginated endpoint handler.
    Works with any API calling function that returns paginated data.
    """
    if headers is None:
        headers = []

    first_response = calling_function(url=url, headers=headers, params=params, **kwargs)
    first_response_json = first_response.json()

    response_items: list = first_response_json.get("items")
    if first_response_json.get("pagination"):
        limit = first_response_json.get("pagination").get("limit")
        total = first_response_json.get("pagination").get("total")

        offset = limit
        while offset + limit <= total:
            next_page_response = calling_function(
                url=url, headers=headers, params={**params, "offset": offset}, **kwargs
            )
            next_page_response_json = next_page_response.json()
            response_items.extend(next_page_response_json.get("items"))

            limit = next_page_response_json.get("pagination").get("limit")
            offset += limit

    return response_items


def normalize_timestamp(timestamp_str: str) -> str:
    """
    Normalize timestamp string to ISO format.
    TODO: Customize based on your external API's timestamp format.
    """
    # Example implementation - customize based on your API
    try:
        # Handle various timestamp formats
        if timestamp_str.endswith('Z'):
            return timestamp_str.replace('Z', '+00:00')
        return timestamp_str
    except Exception:
        return timestamp_str


def map_external_severity_to_dynatrace(external_severity: str) -> str:
    """
    Map external API severity levels to Dynatrace severity levels.
    TODO: Customize this mapping based on your external API's severity levels.
    """
    severity_mapping = {
        # Common mappings - customize as needed
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM", 
        "moderate": "MEDIUM",
        "low": "LOW",
        "info": "INFO",
        "informational": "INFO",
        "debug": "INFO",
        "trace": "INFO",
    }
    
    return severity_mapping.get(external_severity.lower(), "UNKNOWN")


def create_dynatrace_event_base(extension_name: str, config_id: str, config_name: str) -> dict:
    """
    Create base Dynatrace event structure with common fields.
    Use this as a starting point for all your events.
    """
    return {
        "dt.extension.name": f"com.dynatrace.extension.{extension_name}",
        "dt.extension.config.id": config_id,
        "extension.config.name": config_name,
        "event.start_time": None,  # TODO: Set appropriate timestamp
        "event.end_time": None,    # TODO: Set appropriate timestamp
    }


def validate_required_fields(event: dict, required_fields: list[str]) -> bool:
    """
    Validate that required fields are present in the event.
    Useful for ensuring data quality before sending to Dynatrace.
    """
    for field in required_fields:
        if field not in event or event[field] is None:
            return False
    return True
