# Models for renovate (OSV enrichment, repository scan, etc.)

from .vulnerability_details import DependencyDetails, OsvEnrichedInfo
from .repository_scan import RepositoryScan

__all__ = ["DependencyDetails", "OsvEnrichedInfo", "RepositoryScan"]
