from typing import Generic, TypeVar, Iterator, TYPE_CHECKING, Optional
import logging
import re
from datetime import datetime

from .github_object import GithubObject
from .http_client import HttpClient
from .shared import datetime_from_github_timestamp

T = TypeVar("T", bound=GithubObject)

log = logging.getLogger(__name__)


class PaginatedList(Generic[T]):
    def __init__(self, target_class, http_client, target_url, target_params=None, headers=None, list_item=None, oldest_allowed=None, time_field=None):
        self.__elements = list()
        self.__target_class = target_class
        self.__http_client: HttpClient = http_client
        self.__target_url = target_url
        self.__target_params = target_params
        self.__headers = headers
        self.__list_item = list_item
        self._has_next_page = True
        self.__total_count = None
        self._oldest_allowed: Optional[datetime] = oldest_allowed
        self._time_field: Optional[str] = time_field

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
            self.__target_url = self._parse_url_from_link_header(response.headers.get("link"))
            if self.__target_url:
                self._has_next_page = True
                self.__target_params = None  # for later calls, the params are in the url directly
            else:
                self._has_next_page = False
        else:
            self._has_next_page = False
        if self.__list_item and (self.__list_item in json_response):
            elements = json_response[self.__list_item]
        else:
            elements = json_response
        data = []
        for element in elements:
            if self._time_field:
                '''
                This is a way to avoid making too many calls for old records we don't care about.
                For it to work there must be a time field at the top level of each object
                and the results must be sorted from newest to oldest. GitHub typically
                does this by default.
                '''
                timestamp = datetime_from_github_timestamp(element[self._time_field])
                if timestamp < self._oldest_allowed:
                    self._has_next_page = False
                    break
            data.append(self.__target_class(self.__http_client, response.headers, element))
        return data

    @staticmethod
    def _parse_url_from_link_header(header: str):
        """
        Examples:
        <https://api.github.com/repositories/1300192/issues?page=2>; rel="prev", <https://api.github.com/repositories/1300192/issues?page=4>; rel="next", <https://api.github.com/repositories/1300192/issues?page=515>; rel="last", <https://api.github.com/repositories/1300192/issues?page=1>; rel="first"
        <https://api.github.com/repositories/1300192/issues?per_page=2&page=2>; rel="next", <https://api.github.com/repositories/1300192/issues?per_page=2&page=7715>; rel="last"
        <https://api.github.com/repositories/950020670/code-scanning/analyses?per_page=1&page=2>; rel="next", <https://api.github.com/repositories/950020670/code-scanning/analyses?per_page=1&page=177>; rel="last"
        """
        match = re.search(
            r"<https:\/\/[^\/]+(\/[^>]+)>; rel=\"next\"",
            header,
        )
        if match:
            return match.group(1)
        else:
            return None
