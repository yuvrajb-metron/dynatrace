import socket
from ipaddress import ip_address
from typing import Union
from urllib.parse import urlparse
from datetime import datetime
import sys

from dynatrace_extension.sdk.extension import extension_logger as logger

def size_of_record(record):
    try:
        return sys.getsizeof(record["event.original_content"]) * 2
    except Exception:
        return sys.getsizeof(record)

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

def qualys_timestamp_from_datetime(dt: datetime):
    return datetime.strftime(dt, r"%Y-%m-%dT%H:%M:%SZ")

def convert_to_bytes(value: int, unit: Union[str|int]):
    value = int(value)
    if unit == "B":
        pass
    elif unit == "KB":
        value = value * 10**3
    elif unit == "MB":
        value = value * 10**6
    elif unit == "GB":
        value = value * 10**9
    elif unit == "TB":
        value = value * 10**12
    elif unit == "PB":
        value = value * 10**15
    elif unit == "EB":
        value = value * 10**18
    elif unit == "ZB":
        value = value * 10**21
    elif unit == "YB":
        value = value * 10**24
    else:
        pass

    return value

def convert_to_ip(url: str) -> str | None:
    parsed_url = urlparse(url)

    if parsed_url.netloc:
        addr = url_to_ip(parsed_url)
    else:
        addr = hostname_to_ip(url)

    return addr

def url_to_ip(url: str) -> str | None:

    try:
        return str(ip_address(url.hostname))
    except:
        try:
            return socket.gethostbyname(url.hostname)
        except Exception as e:
            logger.error(f"DEC:D6 Unable to resolve IP address for: {url.hostname}: {e}")

    return None

def hostname_to_ip(hostname: str) -> str | None:

    try:
        return str(ip_address(hostname))
    except:
        try:
            return socket.gethostbyname(hostname)
        except Exception as e:
            logger.error(f"DEC:D6 Unable to resolve IP address for: {hostname}: {e}")

    return None