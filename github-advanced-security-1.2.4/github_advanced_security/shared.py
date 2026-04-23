from datetime import datetime, timezone, tzinfo
import re
import sys

from .github_object import GithubObject

SCHEMA_VERSION = "1.306"

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


def datetime_from_github_timestamp(timestamp: str):
    """
    2025-01-29T16:00:03.000Z
    """
    return datetime.strptime(timestamp.rstrip("Z"), r"%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)


def datetime_to_github_timestamp(time_object: datetime):
    return time_object.strftime(r"%Y-%m-%dT%H:%M:%S") + "Z"

class Location(GithubObject):
    def _create_from_raw_data(self, raw_element):

        self.type: str = None

        # commit
        self.path: str = raw_element.get("path")
        self.start_line: int = raw_element.get("start_line")
        self.end_line: int = raw_element.get("end_line")
        self.start_column: int = raw_element.get("start_column")
        self.end_column: int = raw_element.get("end_column")

        if self.path:
            self.type = "commit"

        '''
        Non-commit locations can be determined by a *_url field. When
        needed we can determine the 'type' from whatever comes before
        _url in whichever we found.
        '''
        if not self.type:
            for key in raw_element:
                if key.endswith("_url"):
                    match: re.Match = re.search(r"([a-z_]+)_url", key)
                    self.type = match.group(1)
                    self.url = raw_element[key]
                    break

class AdditionalLocation(Location):
    def _create_from_raw_data(self, raw_element):
        self.type: str = raw_element.get("type")
        self.location: Location = Location(raw_element=raw_element["details"])

class Repository(GithubObject):
    def _create_from_raw_data(self, raw_element):
        self.id: int = raw_element["id"]
        self.node_id: str = raw_element["node_id"]
        self.name: str = raw_element["name"]
        self.full_name: str = raw_element["full_name"]
        self.private: bool = raw_element["private"]
        self.description: str = raw_element["description"]
