from urllib import parse

import requests

PAGE_SIZE = 100


def pages_for(url, headers, verify, entry, logger, proxies=None):
    page = 1
    next_page = 1
    current = -1
    total = 0
    entries = []

    while current < total:
        params = {"p": next_page, "ps": PAGE_SIZE}
        body = get(url, headers, params, verify, proxies)
        page = int(body["paging"]["pageIndex"])
        next_page = page + 1
        page_size = int(body["paging"]["pageSize"])
        current = page * page_size
        total = int(body["paging"]["total"])

        logger.debug(
            f"successfully queried {entry.upper()} page=({page}) with"
            f" pageSize=({page_size}) and total=({total}) elements"
        )
        entries.extend(body[entry])

    return entries


def get_page(url, headers, verify, entry, logger, context, proxies=None) -> tuple[list, dict]:
    entries = []

    params = {"p": context["next_page"], "ps": context["page_size"]}

    body = get(url, headers, params, verify, proxies)
    paging = body["paging"]
    context["page"] = int(paging["pageIndex"])
    context["next_page"] = context["page"] + 1
    context["page_size"] = int(paging["pageSize"])
    context["current"] = context["page"] * context["page_size"]
    context["total"] = int(paging["total"])

    logger.debug(
        f"successfully queried {entry.upper()} page=({context['page']}) with"
        f" pageSize=({context['page_size']}) and total=({context['total']}) elements"
    )

    for current in body[entry]:
        filtered = {prop: current[prop] for prop in context["selected_properties"] if prop in current}
        entries.append(filtered)

    return entries, context


def get(url, headers, params, verify, proxies=None):
    response = requests.get(
        f"{url}&{parse.urlencode(params)}", headers=headers, verify=verify, proxies=proxies
    )
    response.raise_for_status()
    return response.json()
