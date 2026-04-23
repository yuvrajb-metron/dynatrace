import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from ..pagination import PaginatedList
from ..http_client import HttpClient
from ..github_object import GithubObject
from ..models.repository import Repository

TIME_FORMAT = r"%Y-%m-%dT%H:%M:%S"
DEFAULT_PAGE_SIZE = 100

class Token:
    def __init__(self, body: dict):
        self.token: str = body['token']
        self.expires_at: datetime = datetime.strptime(body['expires_at'].replace("Z", ""), TIME_FORMAT).replace(tzinfo=timezone.utc)
        self.permissions: dict = body['permissions']
        self.respository_selection: str = body['repository_selection']


class Account(GithubObject):
    def _create_from_raw_data(self, raw_element: Dict[str, Any]):
        self.login: str = raw_element["login"]
        self.id: str = raw_element["id"]


class AppInstallation(GithubObject):
    def _create_from_raw_data(self, raw_element: Dict[str, Any]):
        self.id: str = raw_element["id"]
        self.client_id: str = raw_element["client_id"]
        self.account: Account = Account(raw_element=raw_element["account"])
        self.repositories_url: str = raw_element["repositories_url"]
        self.access_tokens_url: str = raw_element["access_tokens_url"]
        self.permissions: Dict[str, str] = raw_element["permissions"]
        self.target_type: str = raw_element["target_type"]
        self.access_token: Token = None
        self.log: logging.Logger = None
        self.http_client: HttpClient = None
        self.repositories: List[Repository] = []

    def get_file_hash(self, owner: str, path: str):
        try:
            self.log.info(f"Getting hash for {owner}/{path}")
            resp = self.http_client.make_request(f"repos/{owner}/contents/{path}")
            resp.raise_for_status()
            hash = resp.json()["sha"]
            return hash
        except Exception as e:
            self.log.error(f"Unable to get hash of file {owner}/{path}: {e}")
            return None

    def set_repositories(self):
        self.repositories = list(PaginatedList(Repository, self.http_client, target_url="installation/repositories", target_params={"per_page": DEFAULT_PAGE_SIZE}, list_item="repositories"))


    def set_http_client(self, host: str, proxies: Optional[dict] = {}, verify: bool = True, log = logging.Logger):
        self.http_client = HttpClient(
            host=host,
            proxies=proxies,
            verify=verify
        )

    def set_access_token(self, jwt: str):
        self.log.info(f"Updating installation access token for installation {self.id} ({self.account.login})...")
        try:
            response = self.http_client.make_request(
                f"app/installations/{self.id}/access_tokens",
                headers={"Authorization": f"Bearer {jwt}"},
                method="POST",
            )
            self.access_token: Token = Token(response.json())
            self.http_client.token = self.access_token.token
        except Exception as e:
            self.log.error(f"Error updating access token: {e}", stack_info=True)
