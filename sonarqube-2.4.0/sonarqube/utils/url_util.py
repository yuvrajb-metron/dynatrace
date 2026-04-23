def ensure_trailing_slash(url: str) -> str:
    return url if url.endswith("/") else url + "/"
