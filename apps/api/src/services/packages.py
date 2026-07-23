"""Published-only package and version queries for the Consumer API."""

import math
from datetime import datetime, timezone

from src.models.common import PackageListQuery, SortField, SortOrder
from src.models.packages import (
    Grade,
    PackageDetail,
    PackagePage,
    PackageStats,
    PackageSummary,
    TrustScore,
    VersionDetail,
    VersionSummary,
)
from src.repositories.base import PackageRepository, RepositoryDataError

from .errors import (
    PackageNotFoundError,
    TrustScoreNotFoundError,
    VersionNotFoundError,
)

_GRADE_NUMERIC: dict[Grade, int] = {
    Grade.A: 5,
    Grade.B: 4,
    Grade.C: 3,
    Grade.D: 2,
    Grade.E: 1,
}


def _grade_order(grade: Grade | None) -> int | None:
    if grade is None:
        return None
    return _GRADE_NUMERIC[grade]


class PackageService:
    """Apply public visibility and query semantics to repository records."""

    def __init__(self, repository: PackageRepository) -> None:
        self.repository = repository

    def list_packages(self, query: PackageListQuery) -> PackagePage:
        items = [
            package
            for package in self.repository.list_packages()
            if package.status == "published"
        ]
        for package in items:
            self._get_public_latest(package)
            self._enrich_grade(package)

        if query.q:
            needle = query.q.casefold()
            items = [
                package
                for package in items
                if needle in package.name.casefold()
                or needle in package.description.casefold()
                or any(
                    needle in keyword.casefold() for keyword in package.keywords
                )
            ]
        if query.type:
            items = [package for package in items if package.type == query.type]
        if query.category:
            items = [
                package for package in items if package.category == query.category
            ]
        if query.client:
            items = [
                package
                for package in items
                if self._supports_client(package, query.client)
            ]

        items = self._sort(items, query.sort_by, query.order)
        total = len(items)
        start = (query.page - 1) * query.page_size
        page_items = items[start : start + query.page_size]
        total_pages = math.ceil(total / query.page_size) if total else 0
        return PackagePage(
            items=page_items,
            total=total,
            page=query.page,
            page_size=query.page_size,
            total_pages=total_pages,
        )

    def _supports_client(self, package: PackageSummary, client: str) -> bool:
        return any(
            version.status == "published" and client in version.compatibility
            for version in self.repository.list_versions(package.name)
        )

    def _sort(
        self,
        items: list[PackageSummary],
        field: SortField,
        order: SortOrder,
    ) -> list[PackageSummary]:
        items = sorted(items, key=lambda item: item.name.casefold())

        def raw_value(item: PackageSummary):
            if field is SortField.NAME:
                return item.name.casefold()
            if field is SortField.UPDATED_AT:
                return self._parse_updated_at(item)
            if field is SortField.GRADE:
                return _grade_order(item.grade)
            return getattr(item, field.value)

        keyed_items = [(item, raw_value(item)) for item in items]
        present = [pair for pair in keyed_items if pair[1] is not None]
        missing = [pair for pair in keyed_items if pair[1] is None]
        present.sort(key=lambda pair: pair[1], reverse=order is SortOrder.DESC)
        return [item for item, _value in present + missing]

    @staticmethod
    def _parse_updated_at(package: PackageSummary) -> datetime | None:
        if package.updated_at is None:
            return None
        try:
            parsed = datetime.fromisoformat(
                package.updated_at.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise RepositoryDataError(
                f"Package {package.name} has invalid updated_at "
                f"{package.updated_at!r}"
            ) from exc
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def get_public_package(self, name: str) -> PackageSummary:
        package = self.repository.get_package(name)
        if package is None or package.status != "published":
            raise PackageNotFoundError(name)
        self._enrich_grade(package)
        return package

    def _enrich_grade(self, package: PackageSummary) -> None:
        """Populate PackageSummary.grade from the latest published version's trust_score.

        When the repository does not already provide grade at the package level,
        this reads the latest version's trust_score.risk_summary.grade and copies
        it to the package summary so that API responses and frontend cards can
        display it without loading the full version detail.
        """
        if package.grade is not None:
            return  # already populated by repository
        try:
            version = self._get_public_latest(package)
        except RepositoryDataError:
            return  # no valid latest version
        if version.trust_score is not None and version.trust_score.risk_summary is not None:
            rs_grade = version.trust_score.risk_summary.grade
            if rs_grade is not None:
                package.grade = rs_grade

    def get_public_version(self, name: str, version: str) -> VersionDetail:
        self.get_public_package(name)
        record = self.repository.get_version(name, version)
        if record is None or record.status != "published":
            raise VersionNotFoundError(f"{name}@{version}")
        return record

    def get_package_detail(self, name: str) -> PackageDetail:
        package = self.get_public_package(name)
        version = self._get_public_latest(package)
        return PackageDetail(
            **package.model_dump(),
            latest_version_detail=self._version_summary(version),
        )

    def _get_public_latest(self, package: PackageSummary) -> VersionDetail:
        version = self.repository.get_version(package.name, package.latest_version)
        if version is None or version.status != "published":
            raise RepositoryDataError(
                f"Package {package.name} has invalid latest_version "
                f"{package.latest_version}"
            )
        return version

    def list_public_versions(self, name: str) -> list[VersionSummary]:
        self.get_public_package(name)
        versions = sorted(
            (
                version
                for version in self.repository.list_versions(name)
                if version.status == "published"
            ),
            key=lambda version: version.version,
            reverse=True,
        )
        return [self._version_summary(version) for version in versions]

    def get_public_version_by_id(self, version_id: str) -> VersionDetail:
        version = self.repository.get_version_by_id(version_id)
        if version is None or version.status != "published":
            raise VersionNotFoundError(version_id)
        package = next(
            (
                package
                for package in self.repository.list_packages()
                if package.id == version.package_id
            ),
            None,
        )
        if package is None or package.status != "published":
            raise VersionNotFoundError(version_id)
        return version

    def get_trust_score(self, version_id: str) -> TrustScore:
        version = self.get_public_version_by_id(version_id)
        if version.trust_score is None:
            raise TrustScoreNotFoundError(version_id)
        return version.trust_score

    def get_stats(self, name: str) -> PackageStats:
        package = self.get_public_package(name)
        self._get_public_latest(package)
        if hasattr(self.repository, "get_package_stats"):
            stats = self.repository.get_package_stats(name)
            if stats is not None:
                return stats
        versions = [
            version
            for version in self.repository.list_versions(name)
            if version.status == "published"
        ]
        return PackageStats(
            package_name=package.name,
            install_count=package.install_count,
            avg_rating=package.avg_rating,
            total_versions=len(versions),
            latest_version=package.latest_version,
            status=package.status,
        )

    @staticmethod
    def _version_summary(version: VersionDetail) -> VersionSummary:
        return VersionSummary(
            id=version.id,
            version=version.version,
            status=version.status,
            submitted_at=version.submitted_at,
            created_at=version.created_at,
        )
