import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from ..github_object import GithubObject


class Package(GithubObject):
    def _create_from_raw_data(self, raw_element):
        self.name: str = raw_element["name"]
        self.id: str = raw_element["SPDXID"]
        self.version_info: str = raw_element.get("versionInfo")
        self.dependencies: List[Package] = []
        self.depends_on: List[Package] = []


class DependencyGraph(GithubObject):
    def _create_from_raw_data(self, raw_element: Dict[str, Any]):
        sbom: Dict = raw_element["sbom"]
        self.packages: Dict[str, Package] = {}
        for package in sbom["packages"]:
            p = Package(raw_element=package)
            self.packages.update({p.id: p})

        for dependency in sbom["relationships"]:
            if dependency["relationshipType"] == "DEPENDS_ON":
                self.packages[dependency["spdxElementId"]].dependencies.append(
                    self.packages[dependency["relatedSpdxElement"]]
                )
                self.packages[dependency["relatedSpdxElement"]].depends_on.append(
                    self.packages[dependency["spdxElementId"]]
                )
