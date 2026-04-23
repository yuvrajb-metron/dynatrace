"""
Data structures for Docker Hub API discovery (orgs, repos, image refs).
Used when listing organizations, repositories, and tags to scan with Docker Scout.
"""

from dataclasses import dataclass


@dataclass
class Org:
    """Docker Hub organization (namespace)."""

    name: str
    org_id: str = ""


@dataclass
class Repo:
    """Repository within a namespace."""

    name: str
    namespace: str
    repo_id: str = ""


@dataclass
class ImageRef:
    """
    Image reference: org/repo:tag for scanning.
    Used to build registry URIs for docker scout cves and docker scout sbom.
    """

    org: str
    repo: str
    tag: str

    @property
    def full_name(self) -> str:
        """
        Full image reference string ``org/repo:tag``.

        Returns:
            Combined org, repo, and tag.
        """
        return f"{self.org}/{self.repo}:{self.tag}"

    def registry_uri(self) -> str:
        """
        URI form passed to ``docker scout`` for this image.

        Returns:
            String ``registry://org/repo:tag``.
        """
        return f"registry://{self.full_name}"
