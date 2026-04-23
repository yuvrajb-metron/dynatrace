import json
import sys


def size_of_record(record):
    return sys.getsizeof(json.dumps(record))


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


def get_filename_from_path(path: str) -> str:
    return path.split("/")[-1]


def parse_repository_name(project_name: str) -> str:
    return project_name.split(":")[0]
