"""Published-only package and version queries for the Consumer API."""

import logging
import math
import time as _time
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

from src.models.common import PackageListQuery, SortField, SortOrder
from src.models.packages import (
    Grade,
    PackageDetail,
    PackagePage,
    PackageStats,
    PackageSummary,
    PublicInstallation,
    PublicInstallTarget,
    PublicPermissionSummary,
    PublicTrustSummary,
    PublicVersionDetail,
    TrustHistoryPoint,
    VersionDetail,
    VersionSummary,
)
from src.repositories.base import PackageRepository, RepositoryDataError

from schema.constants import GRADE_TO_RECOMMENDATION, GRADE_TO_RISK_LEVEL

from .errors import (
    PackageNotFoundError,
    TrustScoreNotFoundError,
    VersionNotFoundError,
)

_GRADE_NUMERIC: dict[Grade | None, int] = {
    Grade.A: 5,
    Grade.B: 4,
    Grade.C: 3,
    Grade.D: 2,
    Grade.E: 1,
    None: 0,
}

# Representative score per grade used only when a stored numeric score is
# unavailable (e.g. legacy rows). Mirrors the documented 0-100 grade bands:
# A >= 90, B >= 80, C >= 60, D >= 40, E < 20.
_GRADE_MIDPOINT: dict[Grade, float] = {
    Grade.A: 95.0,
    Grade.B: 85.0,
    Grade.C: 70.0,
    Grade.D: 50.0,
    Grade.E: 10.0,
}


def _grade_order(grade: Grade | None) -> int:
    return _GRADE_NUMERIC.get(grade, 0)


_STATS_CACHE: dict[str, tuple[float, Any]] = {}
_STATS_CACHE_TTL = 180  # 3 minutes


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
        valid_items: list[PackageSummary] = []
        for package in items:
            try:
                self._get_public_latest(package)
            except RepositoryDataError:
                logger.warning("Skipping package %s: latest_version is not published", package.name)
                continue
            self._enrich_grade(package)
            valid_items.append(package)
        items = valid_items

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
        if query.tag:
            needle = query.tag.casefold()
            items = [
                package
                for package in items
                if any(needle in keyword.casefold() for keyword in package.keywords)
            ]
        if query.min_grade:
            min_order = _grade_order(Grade(query.min_grade))
            items = [
                package
                for package in items
                if package.grade is not None
                and _grade_order(package.grade) >= min_order
            ]
        if query.min_score is not None or query.max_score is not None:
            items = [
                package
                for package in items
                if self._matches_score_range(package, query.min_score, query.max_score)
            ]
        if query.updated_since is not None:
            items = [
                package
                for package in items
                if self._updated_since_matches(package, query.updated_since)
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

    def _matches_score_range(
        self,
        package: PackageSummary,
        min_score: float | None,
        max_score: float | None,
    ) -> bool:
        score = self._effective_numeric_score(package)
        if score is None:
            return False
        if min_score is not None and score < min_score:
            return False
        if max_score is not None and score > max_score:
            return False
        return True

    def _effective_numeric_score(self, package: PackageSummary) -> float | None:
        """Best-effort 0-100 numeric score for the latest published version.

        Prefers the stored engine score; falls back to a representative
        midpoint derived from the effective grade so the filter keeps working
        for legacy rows that predate numeric-score persistence.
        """
        try:
            version = self._get_public_latest(package)
        except RepositoryDataError:
            return None
        trust_score = version.trust_score
        if trust_score is None:
            return _GRADE_MIDPOINT.get(package.grade) if package.grade else None
        raw = getattr(trust_score, "score", None)
        if raw is None and trust_score.model_extra:
            raw = trust_score.model_extra.get("score")
        if isinstance(raw, (int, float)):
            return float(raw)
        effective = version.effective_grade
        if effective is None:
            effective = package.grade
        if effective is not None and effective in _GRADE_MIDPOINT:
            return _GRADE_MIDPOINT[effective]
        return None

    @staticmethod
    def _updated_since_matches(
        package: PackageSummary,
        since: datetime,
    ) -> bool:
        updated = PackageService._parse_updated_at(package)
        if updated is None:
            return False
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        return updated >= since.astimezone(timezone.utc)

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
                return _grade_order(item.grade) if item.grade is not None else None
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
        """Populate package grade and risk_level from effective_grade of latest version.

        Uses effective_grade (manual_grade or auto_grade) as the single source
        of truth for both grade and risk_level on the package summary.
        Only overwrites if not already set by the repository.
        """
        try:
            version = self._get_public_latest(package)
        except RepositoryDataError:
            return  # no valid latest version

        effective = version.effective_grade or (
            version.trust_score.risk_summary.grade
            if version.trust_score and version.trust_score.risk_summary
            else None
        )

        if package.grade is None and effective is not None:
            package.grade = effective
        if package.risk_level is None and effective is not None:
            package.risk_level = GRADE_TO_RISK_LEVEL.get(
                str(effective), "medium_risk"
            )

    def get_published_version(self, name: str, version: str) -> VersionDetail:
        """Return the full record for trusted server-side consumers only."""

        self.get_public_package(name)
        record = self.repository.get_version(name, version)
        if record is None or record.status != "published":
            raise VersionNotFoundError(f"{name}@{version}")
        return record

    def get_public_version(self, name: str, version: str) -> PublicVersionDetail:
        """Return only fields intended for an unauthenticated package page."""

        package = self.get_public_package(name)
        record = self.get_published_version(name, version)
        return self._public_version_projection(package.name, record)

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

    def get_trust_history(self, name: str) -> list[TrustHistoryPoint]:
        """Published-version grade history without numeric scoring details."""
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
        points: list[TrustHistoryPoint] = []
        for version in versions:
            grade = self.resolve_effective_grade(version)
            calculated_at: str | None = None
            if version.trust_score is not None:
                calculated_at = version.trust_score.calculated_at
            points.append(
                TrustHistoryPoint(
                    version=version.version,
                    grade=grade,
                    calculated_at=calculated_at,
                )
            )
        return points

    def get_published_version_by_id(self, version_id: str) -> VersionDetail:
        """Return a full published record after enforcing package visibility."""

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

    @staticmethod
    def resolve_effective_grade(version: VersionDetail) -> Grade | None:
        if version.effective_grade is not None:
            return version.effective_grade
        if version.manual_grade is not None:
            return version.manual_grade
        if version.trust_score and version.trust_score.risk_summary:
            summary = version.trust_score.risk_summary
            return summary.effective_grade or summary.manual_grade or summary.grade
        return None

    @staticmethod
    def _permission_summary(version: VersionDetail) -> PublicPermissionSummary | None:
        permissions = version.permissions
        if permissions is None:
            return None
        filesystem = permissions.filesystem
        environment = permissions.environment
        credentials = permissions.credentials
        return PublicPermissionSummary(
            filesystem_read_count=len(filesystem.read) if filesystem else 0,
            filesystem_write_count=len(filesystem.write) if filesystem else 0,
            filesystem_delete=filesystem.delete if filesystem else False,
            shell_allowed=permissions.shell.allowed if permissions.shell else False,
            network_allowed=permissions.network.allowed if permissions.network else False,
            environment_read_count=len(environment.read) if environment else 0,
            environment_write_count=len(environment.write) if environment else 0,
            credentials_access_count=len(credentials.access) if credentials else 0,
            database_declared=bool(permissions.database),
            browser_declared=bool(permissions.browser),
            external_services_count=len(permissions.external_services or []),
        )

    @staticmethod
    def _public_installation(version: VersionDetail) -> PublicInstallation | None:
        installation = version.installation
        if installation is None:
            return None
        targets = (
            [
                PublicInstallTarget(
                    client=target.client,
                    destination=target.destination,
                )
                for target in installation.targets
            ]
            if installation.targets is not None
            else None
        )
        return PublicInstallation(
            method=installation.method,
            package=installation.package,
            targets=targets,
            target_client=installation.target_client,
            pre_install_message=installation.pre_install_message,
            post_install_message=installation.post_install_message,
        )

    def _public_version_projection(
        self,
        package_name: str,
        version: VersionDetail,
    ) -> PublicVersionDetail:
        grade = self.resolve_effective_grade(version)
        return PublicVersionDetail(
            name=package_name,
            version=version.version,
            compatibility=version.compatibility,
            permission_summary=self._permission_summary(version),
            installation=self._public_installation(version),
            effective_grade=grade,
            risk_level=(
                GRADE_TO_RISK_LEVEL.get(str(grade)) if grade is not None else None
            ),
            install_recommendation=(
                GRADE_TO_RECOMMENDATION.get(str(grade)) if grade is not None else None
            ),
        )

    def get_public_trust_summary(self, version_id: str) -> PublicTrustSummary:
        version = self.get_published_version_by_id(version_id)
        grade = self.resolve_effective_grade(version)
        if version.trust_score is None or grade is None:
            raise TrustScoreNotFoundError(version_id)
        return PublicTrustSummary(
            effective_grade=grade,
            level=GRADE_TO_RISK_LEVEL[str(grade)],
            install_recommendation=GRADE_TO_RECOMMENDATION[str(grade)],
        )

    def get_stats(self, name: str) -> PackageStats:
        now = _time.time()
        if name in _STATS_CACHE:
            ts, val = _STATS_CACHE[name]
            if now - ts < _STATS_CACHE_TTL:
                return val

        package = self.get_public_package(name)
        self._get_public_latest(package)
        if hasattr(self.repository, "get_package_stats"):
            stats = self.repository.get_package_stats(name)
            if stats is not None:
                _STATS_CACHE[name] = (now, stats)
                return stats
        versions = [
            version
            for version in self.repository.list_versions(name)
            if version.status == "published"
        ]
        result = PackageStats(
            package_name=package.name,
            install_count=package.install_count,
            avg_rating=package.avg_rating,
            total_versions=len(versions),
            latest_version=package.latest_version,
            status=package.status,
        )
        _STATS_CACHE[name] = (now, result)
        return result

    @staticmethod
    def _version_summary(version: VersionDetail) -> VersionSummary:
        return VersionSummary(
            id=version.id,
            version=version.version,
            status=version.status,
            submitted_at=version.submitted_at,
            created_at=version.created_at,
        )
