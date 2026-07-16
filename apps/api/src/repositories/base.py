"""Repository contracts for package and version data."""

from typing import Protocol, Sequence

from src.models.packages import PackageSummary, VersionDetail


class RepositoryDataError(RuntimeError):
    """Raised when repository data cannot be loaded or is inconsistent."""


class PackageRepository(Protocol):
    """Read-only access to package and version records."""

    def list_packages(self) -> Sequence[PackageSummary]: ...

    def get_package(self, name: str) -> PackageSummary | None: ...

    def list_versions(self, name: str) -> Sequence[VersionDetail]: ...

    def get_version(self, name: str, version: str) -> VersionDetail | None: ...

    def get_version_by_id(self, version_id: str) -> VersionDetail | None: ...
