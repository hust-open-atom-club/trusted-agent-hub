from dataclasses import dataclass
from enum import StrEnum


class DependencySourceUsage(StrEnum):
    """How a dependency source URL is used by the installer."""

    REGISTRY_API = "registry_api"
    RESOLVED_DOWNLOAD = "resolved_download"


@dataclass(frozen=True)
class DependencyRecord:
    name: str
    version: str | None
    ecosystem: str
    direct: bool
    source_file: str
    registry: str | None = None
    integrity: str | None = None
    registry_usage: DependencySourceUsage | None = None


@dataclass(frozen=True)
class DependencySourceObservation:
    ecosystem: str
    url: str
    usage: DependencySourceUsage
    source_file: str
    dependency_name: str | None = None
