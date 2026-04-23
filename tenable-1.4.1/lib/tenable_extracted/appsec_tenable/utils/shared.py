# ruff: noqa: B006
import json
from typing import Protocol
from urllib import parse

from requests.models import Response

from ..rest_interface import Header, RestApiHandler


def size_of_record(record):
    return len(json.dumps(record).encode())


def split_by_size(items, max_size, get_size=size_of_record):
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
    # Interpolate the required number of placeholders
    return query + " IN ({})".format(",".join(["?"] * len(in_vals)))


def get_risk_score_from_level(risk_level: str) -> float:
    risk_score = 0
    if risk_level == "CRITICAL":
        risk_score = 10
    elif risk_level == "HIGH":
        risk_score = 8.9
    elif risk_level == "MEDIUM":
        risk_score = 6.9
    elif risk_level == "LOW":
        risk_score = 3.9

    return risk_score


def get_paged_endpoint(rest_interface: RestApiHandler, headers: None | list[Header], params: None | dict):
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
