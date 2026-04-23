from typing import Generic, TypeVar, Iterator, Optional
from urllib.parse import urlparse
import logging

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET

from .http_client import HttpClient


class PaginatedElementsList:
    def __init__(
        self,
        http_client: HttpClient,
        target_url: str,
        elements_path: str,
        target_params: Optional[dict] = None,
        headers: Optional[dict] = None,
    ):
        self.__elements = list()
        self.__http_client = http_client
        self.__target_url = target_url
        self.__target_params = target_params
        self.__headers = headers
        self.__elements_path = elements_path
        self._has_next_page = True

    def __getitem__(self, index):
        pass

    def __iter__(self) -> Iterator[ET.Element]:
        for element in self.__elements:
            yield element

        while self._has_next_page:
            try:
                new_elements = self._get_next_page()
                for element in new_elements:
                    yield element
            except Exception as e:
                raise e

    def _get_next_page(self):
        response = self.__http_client.make_request(
            self.__target_url, self.__target_params, self.__headers
        )
        tree = ET.ElementTree(ET.fromstring(response.text))
        root = tree.getroot()
        data = []

        # pagination info
        warning_element = root.find("RESPONSE/WARNING")
        if warning_element is not None:
            next_url = (
                warning_element.find("URL").text
                if warning_element.find("URL") is not None
                else None
            )
        else:
            next_url = None
        if next_url:
            self._has_next_page = True
            next_url = urlparse(next_url)  # url is full url, just need path and params
            self.__target_url = f"{next_url.path}?{next_url.query}"
            self.__target_params = None
        else:
            self._has_next_page = False

        data.extend(root.findall(self.__elements_path))
        return data
