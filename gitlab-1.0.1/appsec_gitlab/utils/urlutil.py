"""
URL construction using :mod:`urllib.parse` (standard library).

Responsibility:
    Resolve base URLs with path segments via :func:`urllib.parse.urljoin` so slashes
    and path boundaries are handled consistently.
"""

from __future__ import annotations

from urllib.parse import quote, urljoin


def join_urls(base: str, *path_parts: str | int) -> str:
    """
    Append path segments to a base URL (RFC 3986 resolution).

    The base is normalized with a trailing slash so relative segments append under
    the base path instead of replacing its final component. Empty segments are skipped.

    Args:
        base: Scheme + authority, optionally with a path (e.g. GitLab root or project ``web_url``).
        *path_parts: Path segments; leading/trailing slashes on each part are stripped.

    Returns:
        Absolute URL without a trailing slash unless required by the last segment.
    """
    root = base.rstrip("/") + "/"
    if not path_parts:
        return root.rstrip("/")
    cleaned = [str(p).strip("/") for p in path_parts if str(p).strip("/")]
    if not cleaned:
        return root.rstrip("/")
    rel = "/".join(cleaned)
    return urljoin(root, rel)


def gitlab_rest_url(base_url: str, *path_parts: str | int) -> str:
    """Build a GitLab REST URL under ``/api/v4/...``."""
    return join_urls(base_url, "api", "v4", *path_parts)


def gitlab_graphql_url(base_url: str) -> str:
    """Build the GitLab GraphQL endpoint ``/api/graphql``."""
    return join_urls(base_url, "api", "graphql")


def quote_path_segment(segment: str | int) -> str:
    """Percent-encode a single URL path segment (e.g. container image tag)."""
    return quote(str(segment), safe="")
