from typing import Generic, TypeVar, Iterator, TYPE_CHECKING
import logging
import re

from .harbor_object import HarborObject
from .http_client import HttpClient

T = TypeVar("T", bound=HarborObject)

log = logging.getLogger(__name__)


class PaginatedList(Generic[T]):
    def __init__(
        self, target_class, http_client, target_url, target_params=None, headers=None
    ):
        self.__elements = list()
        self.__target_class = target_class
        self.__http_client: HttpClient = http_client
        self.__target_url = target_url
        self.__target_params = target_params
        self.__headers = headers
        self._has_next_page = True
        self.__total_count = None

    def __getitem__(self, index):
        pass

    def __iter__(self) -> Iterator[T]:
        for element in self.__elements:
            yield element

        while self._has_next_page:
            try:
                new_elements = self._get_next_page()
                for element in new_elements:
                    yield element
            except Exception as e:
                raise e

    def __len__(self):
        return self.__total_count or len(self.__elements)

    def _get_next_page(self):
        response = self.__http_client.make_request(
            self.__target_url, params=self.__target_params, headers=self.__headers
        )
        json_response = response.json()
        data = []
        if response.headers.get("link"):
            self.__target_url = self._parse_url_from_link_header(
                response.headers.get("link")
            )
            if self.__target_url:
                self._has_next_page = True
                self.__target_params = (
                    None  # for later calls, the params are in the url directly
                )
            else:
                self._has_next_page = False
        else:
            self._has_next_page = False
        if True:
            elements = json_response
            data = [
                self.__target_class(self.__http_client, response.headers, element)
                for element in elements
            ]
        return data

    @staticmethod
    def _parse_url_from_link_header(header: str):
        """
        Examples:
        </api/v2.0/security/vul?page=2&page_size=10>; rel="next"
        </api/v2.0/security/vul?page=1&page_size=10&tune_count=false&with_tag=false>; rel="prev" ,</api/v2.0/security/vul?page=3&page_size=10&tune_count=false&with_tag=false>; rel="next"
        """
        links = header.split(",")
        if len(links) == 2:
            link_text = links[1]
        else:
            link_text = links[0]
            if 'rel="prev"' in link_text:
                return None
        match = re.match(r"<\/api\/v2.0(\/[\:a-zA-Z\/\?\=\d&_]+)>", link_text.strip())
        if match:
            return match.group(1)
        else:
            return None
