from dataclasses import dataclass
from enum import StrEnum
from typing import Literal


class DependencySourceUsage(StrEnum):
    """How a dependency source URL is used by the installer."""

    REGISTRY_API = "registry_api"
    RESOLVED_DOWNLOAD = "resolved_download"


DependencyScope = Literal["runtime", "dev", "test", "optional", "mixed", "unknown"]


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
    scope: DependencyScope = "unknown"
    source_ref: str | None = None
    line: int | None = None


@dataclass(frozen=True)
class DependencySourceObservation:
    ecosystem: str
    url: str
    usage: DependencySourceUsage
    source_file: str
    dependency_name: str | None = None
    dependency_version: str | None = None
    integrity: str | None = None
    scope: DependencyScope = "unknown"
    source_ref: str | None = None
    line: int | None = None
