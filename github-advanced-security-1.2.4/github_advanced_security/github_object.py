import pprint
from typing import Optional, Dict, Any


class GithubObject:
    def __init__(
        self,
        http_client=None,
        headers: Optional[Dict[str, str]] = None,
        raw_element: Optional[Dict[str, Any]] = None,
    ):
        if raw_element is None:
            raw_element = {}
        self._http_client = http_client
        self._headers = headers
        self._raw_element = raw_element
        self._create_from_raw_data(raw_element)

    def _create_from_raw_data(self, raw_element: Dict[str, Any]):
        pass

    def __repr__(self):
        return f"{self.__class__.__name__}({pprint.pformat(self._raw_element, width=130)})"
