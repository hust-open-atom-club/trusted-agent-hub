from dataclasses import dataclass
from enum import StrEnum
from typing import Literal


class DependencySourceUsage(StrEnum):
    """How a dependency source URL is used by the installer."""

    REGISTRY_API = "registry_api"
    RESOLVED_DOWNLOAD = "resolved_download"


DependencyScope = Literal[
    "runtime",
    "dev",
    "test",
    "optional",
    "peer",
    "bundled",
    "mixed",
    "unknown",
]

DEPENDENCY_SCOPE_VALUES: tuple[str, ...] = (
    "runtime",
    "dev",
    "test",
    "optional",
    "peer",
    "bundled",
    "mixed",
    "unknown",
)


def is_local_npm_reference(value: str | None) -> bool:
    """Local npm sources are inventory, not public registry coordinates."""
    return isinstance(value, str) and value.casefold().startswith(("workspace:", "link:", "file:"))


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
    # Keep the installer path explicit.  A coordinate can occur through both
    # direct and transitive paths, so this is intentionally a collection.
    reachability: tuple[str, ...] = ()
    # Preserve the package's declared version separately from a local source.
    # This also prevents local and registry packages sharing name/version from
    # collapsing into one OSV query group.
    local_reference: str | None = None


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
    reachability: tuple[str, ...] = ()
    direct: bool | None = None
    # Conflicting installer context must not use an unrelated ecosystem's approval.
    ecosystem_ambiguous: bool = False
