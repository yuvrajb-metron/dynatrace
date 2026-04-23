from datetime import datetime, timezone, tzinfo
import json


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


def datetime_from_harbor_timestamp(timestamp: str):
    """
    2025-01-29T16:00:03.000Z
    """
    return datetime.strptime(timestamp.rstrip("Z"), r"%Y-%m-%dT%H:%M:%S.%f").replace(
        tzinfo=timezone.utc
    )


def datetime_to_harbor_timestamp(time_object: datetime):
    return time_object.strftime(r"%Y-%m-%dT%H:%M:%S.%f") + "Z"
