from urllib.parse import urljoin

from ..rest_interface import Header, RestApiHandler


def get_audit_paged(
    snyk_interface: RestApiHandler,
    base_api_url: str,
    org_id: str,
    headers: list[Header] | None = None,
    params=None,
) -> list[dict]:
    if headers is None:
        headers = []

    first_page_response = snyk_interface.get_url(
        urljoin(base_api_url, f"rest/orgs/{org_id}/audit_logs/search"), headers, params
    )
    page_data = first_page_response.json()
    return_data: dict = page_data["data"]

    while page_data.get("links", {}).get("next"):
        # Process links to get the next url
        if "next" in page_data["links"]:
            # If the next url is the same as the current url, break out of the loop
            if "self" in page_data["links"] and page_data["links"]["next"] == page_data["links"]["self"]:
                break
            next_url = page_data.get("links", {}).get("next")
        else:
            # If there is no next url, break out of the loop
            break

        # The next url comes back fully formed
        # (i.e. with all the params already set, so no need to do it here)
        next_page_response = snyk_interface.get_url(urljoin(base_api_url, next_url), headers)
        page_data = next_page_response.json()

        # Verify that response contains data
        if "data" in page_data:
            # If the data is empty, break out of the loop
            if len(page_data["data"]) == 0:
                break
        # If response does not contain data, break out of the loop
        else:
            break

        # Append the data from the next page to the return data
        return_data.get("items").extend(page_data["data"].get("items"))
    return return_data.get("items")
