import logging
from collections.abc import Iterator
from typing import Generic, TypeVar

from dynatrace_extension.sdk.extension import extension_logger as logger
from snyk import SnykClient

T = TypeVar("T", bound=dict)

log = logging.getLogger(__name__)


class PaginationError(Exception):
    pass


class PaginatedList(Generic[T]):
    def __init__(self, snyk_client: SnykClient, target_url, target_params=None, headers=None):
        self.__elements = []
        self.__snyk_client: SnykClient = snyk_client
        self.__target_url = target_url
        self.__target_params = target_params
        self._headers = headers
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
                logger.error(f"DEC:D8 Exception when querying {self.__target_url} -- {e}.")
                raise PaginationError(f"API exception {e}.") from e

    def __len__(self):
        return self.__total_count or len(self.__elements)

    def _get_next_page(self):
        response = self.__snyk_client.get(
            self.__target_url,
            self.__target_params,
            exclude_version=bool(self.__target_params == {}),
        )
        json_response: dict = response.json()
        if json_response.get("links", {}).get("next"):
            if "next" in json_response["links"]:
                if (
                    "self" in json_response["links"]
                    and json_response["links"]["next"] == json_response["links"]["self"]
                ):
                    self._has_next_page = False
                else:
                    self._has_next_page = True
                    self.__target_params = {}
                    self.__target_url = json_response.get("links", {}).get("next")
            else:
                self._has_next_page = False
        else:
            self._has_next_page = False
        return json_response["data"]
