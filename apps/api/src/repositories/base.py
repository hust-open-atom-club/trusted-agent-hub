"""Repository contracts for package and version data."""

from typing import Protocol, Sequence, TypeGuard, TypeVar

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


class ConsumerPersistenceRepository(PackageRepository, Protocol):
    """Package repository with the Consumer API's persistence operations."""

    def record_install(
        self,
        *,
        package_name: str,
        version: str,
        version_id: str,
        user_id: str,
        client: str,
        install_path: str,
        integrity_verified: bool,
    ) -> tuple[dict[str, object], bool]: ...

    def upsert_feedback(
        self,
        *,
        package_name: str,
        package_id: str,
        user_id: str,
        level: str,
        comment: str | None,
    ) -> tuple[dict[str, object], bool]: ...

    def list_feedback(
        self,
        *,
        package_name: str,
        package_id: str,
        page: int,
        page_size: int,
    ) -> dict[str, object]: ...

    def get_trust_level(self, version_id: str) -> dict[str, object] | None: ...


_RepositoryType = TypeVar("_RepositoryType")
_consumer_persistence_repository_types: set[type[object]] = set()


def register_consumer_persistence_repository(
    repository_type: type[_RepositoryType],
) -> type[_RepositoryType]:
    """Explicitly register a concrete Consumer persistence repository type."""
    _consumer_persistence_repository_types.add(repository_type)
    return repository_type


def is_consumer_persistence_repository(
    repository: PackageRepository,
) -> TypeGuard[ConsumerPersistenceRepository]:
    """Return whether a package repository supports Consumer persistence."""
    return any(
        repository_type in _consumer_persistence_repository_types
        for repository_type in type(repository).__mro__
    )
