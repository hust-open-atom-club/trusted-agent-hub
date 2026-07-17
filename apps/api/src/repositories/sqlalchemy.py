"""SQLAlchemy-backed repository for Consumer package data and feedback."""

from __future__ import annotations

import sqlite3
import math
from uuid import uuid4
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.models.packages import PackageStats, PackageSummary, VersionDetail

from .base import (
    PackageRepository,
    RepositoryDataError,
    register_consumer_persistence_repository,
)
from .orm import (
    FeedbackRecordRow,
    InstallRecordRow,
    PackageRow,
    PackageVersionRow,
    TrustLevelRow,
    utc_now,
)


TrustLevelName = Literal[
    "trusted",
    "low_risk",
    "medium_risk",
    "high_risk",
    "untrusted",
]


@register_consumer_persistence_repository
class SqlAlchemyPackageRepository(PackageRepository):
    """Repository backed by SQLAlchemy sessions."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self.session_factory = session_factory

    def list_packages(self) -> Sequence[PackageSummary]:
        with self.session_factory() as session:
            rows = session.scalars(
                select(PackageRow).order_by(PackageRow.name)
            ).all()
            return tuple(_package_from_row(row) for row in rows)

    def get_package(self, name: str) -> PackageSummary | None:
        with self.session_factory() as session:
            row = session.scalar(
                select(PackageRow).where(PackageRow.name == name)
            )
            return None if row is None else _package_from_row(row)

    def list_versions(self, name: str) -> Sequence[VersionDetail]:
        with self.session_factory() as session:
            package = session.scalar(
                select(PackageRow).where(PackageRow.name == name)
            )
            if package is None:
                return ()
            rows = session.scalars(
                select(PackageVersionRow)
                .where(PackageVersionRow.package_id == package.id)
                .order_by(PackageVersionRow.version)
            ).all()
            return tuple(_version_from_row(row) for row in rows)

    def get_version(self, name: str, version: str) -> VersionDetail | None:
        with self.session_factory() as session:
            row = session.scalar(
                select(PackageVersionRow)
                .join(PackageRow)
                .where(PackageRow.name == name)
                .where(PackageVersionRow.version == version)
            )
            return None if row is None else _version_from_row(row)

    def get_version_by_id(self, version_id: str) -> VersionDetail | None:
        with self.session_factory() as session:
            row = session.get(PackageVersionRow, version_id)
            return None if row is None else _version_from_row(row)

    def upsert_package(self, package: PackageSummary) -> None:
        with self.session_factory() as session:
            _upsert_package(session, package)
            session.commit()

    def upsert_version(self, version: VersionDetail) -> None:
        with self.session_factory() as session:
            _upsert_version(session, version)
            session.commit()

    def upsert_trust_level(
        self,
        *,
        version_id: str,
        level: TrustLevelName,
        install_recommendation: str,
        top_risks: list[str],
        explanation: str | None,
        model_version: str,
    ) -> None:
        with self.session_factory() as session:
            if session.get(PackageVersionRow, version_id) is None:
                raise RepositoryDataError(
                    f"Trust level references unknown version {version_id}"
                )
            row = session.get(TrustLevelRow, version_id)
            now = utc_now()
            if row is None:
                session.add(
                    TrustLevelRow(
                        version_id=version_id,
                        level=level,
                        install_recommendation=install_recommendation,
                        top_risks=top_risks,
                        explanation=explanation,
                        model_version=model_version,
                        calculated_at=now,
                    )
                )
            else:
                row.level = level
                row.install_recommendation = install_recommendation
                row.top_risks = top_risks
                row.explanation = explanation
                row.model_version = model_version
                row.calculated_at = now
            session.commit()

    def get_trust_level(self, version_id: str) -> dict[str, object] | None:
        with self.session_factory() as session:
            row = session.get(TrustLevelRow, version_id)
            if row is None:
                return None
            return {
                "version_id": row.version_id,
                "level": row.level,
                "install_recommendation": row.install_recommendation,
                "top_risks": row.top_risks,
                "explanation": row.explanation,
                "model_version": row.model_version,
                "calculated_at": _serialize_datetime(row.calculated_at),
            }

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
    ) -> tuple[dict[str, object], bool]:
        with self.session_factory() as session:
            row = session.scalar(
                select(InstallRecordRow)
                .where(InstallRecordRow.version_id == version_id)
                .where(InstallRecordRow.user_id == user_id)
                .where(InstallRecordRow.client == client)
                .where(InstallRecordRow.install_path == install_path)
            )
            created = row is None
            if row is None:
                row = InstallRecordRow(
                    id=f"inst-{uuid4().hex}",
                    version_id=version_id,
                    user_id=user_id,
                    client=client,
                    install_path=install_path,
                    integrity_verified=integrity_verified,
                    installed_at=utc_now(),
                )
                session.add(row)
                try:
                    session.commit()
                except IntegrityError as error:
                    if not _is_target_unique_violation(
                        error,
                        constraint_name="uq_install_idempotency",
                        sqlite_columns=(
                            "install_records.version_id",
                            "install_records.user_id",
                            "install_records.client",
                            "install_records.install_path",
                        ),
                    ):
                        raise
                    session.rollback()
                    row = session.scalar(
                        select(InstallRecordRow)
                        .where(InstallRecordRow.version_id == version_id)
                        .where(InstallRecordRow.user_id == user_id)
                        .where(InstallRecordRow.client == client)
                        .where(InstallRecordRow.install_path == install_path)
                    )
                    if row is None:
                        raise
                    created = False
            payload = {
                "id": row.id,
                "package_name": package_name,
                "version": version,
                "version_id": row.version_id,
                "user_id": row.user_id,
                "client": row.client,
                "install_path": row.install_path,
                "integrity_verified": row.integrity_verified,
                "installed_at": _serialize_datetime(row.installed_at),
            }
            return payload, created

    def upsert_feedback(
        self,
        *,
        package_name: str,
        package_id: str,
        user_id: str,
        level: str,
        comment: str | None,
    ) -> tuple[dict[str, object], bool]:
        with self.session_factory() as session:
            row = session.scalar(
                select(FeedbackRecordRow)
                .where(FeedbackRecordRow.package_id == package_id)
                .where(FeedbackRecordRow.user_id == user_id)
            )
            created = row is None
            now = utc_now()
            if row is None:
                row = FeedbackRecordRow(
                    id=f"fb-{uuid4().hex}",
                    package_id=package_id,
                    user_id=user_id,
                    level=level,
                    comment=comment,
                    created_at=now,
                    updated_at=now,
                )
                session.add(row)
            else:
                row.level = level
                row.comment = comment
                row.updated_at = now
            try:
                session.commit()
            except IntegrityError as error:
                if not created:
                    raise
                if not _is_target_unique_violation(
                    error,
                    constraint_name="uq_feedback_user_package",
                    sqlite_columns=(
                        "feedback_records.package_id",
                        "feedback_records.user_id",
                    ),
                ):
                    raise
                session.rollback()
                row = session.scalar(
                    select(FeedbackRecordRow)
                    .where(FeedbackRecordRow.package_id == package_id)
                    .where(FeedbackRecordRow.user_id == user_id)
                )
                if row is None:
                    raise
                created = False
            return _feedback_payload(row, package_name), created

    def list_feedback(
        self,
        *,
        package_name: str,
        package_id: str,
        page: int,
        page_size: int,
    ) -> dict[str, object]:
        with self.session_factory() as session:
            total = session.scalar(
                select(func.count())
                .select_from(FeedbackRecordRow)
                .where(FeedbackRecordRow.package_id == package_id)
            )
            total = 0 if total is None else int(total)
            rows = session.scalars(
                select(FeedbackRecordRow)
                .where(FeedbackRecordRow.package_id == package_id)
                .order_by(FeedbackRecordRow.updated_at.desc(), FeedbackRecordRow.id)
                .offset((page - 1) * page_size)
                .limit(page_size)
            ).all()
            counts = {"positive": 0, "neutral": 0, "negative": 0}
            for level, count in session.execute(
                select(FeedbackRecordRow.level, func.count())
                .where(FeedbackRecordRow.package_id == package_id)
                .group_by(FeedbackRecordRow.level)
            ):
                counts[str(level)] = int(count)
            return {
                "items": [
                    _feedback_payload(row, package_name) for row in rows
                ],
                "total": total,
                "page": page,
                "page_size": page_size,
                "total_pages": math.ceil(total / page_size) if total else 0,
                "level_counts": counts,
            }

    def get_package_stats(self, name: str) -> PackageStats | None:
        with self.session_factory() as session:
            package = session.scalar(
                select(PackageRow).where(PackageRow.name == name)
            )
            if package is None:
                return None
            total_versions = session.scalar(
                select(func.count())
                .select_from(PackageVersionRow)
                .where(PackageVersionRow.package_id == package.id)
                .where(PackageVersionRow.status == "published")
            )
            install_count = session.scalar(
                select(func.count())
                .select_from(InstallRecordRow)
                .join(PackageVersionRow)
                .where(PackageVersionRow.package_id == package.id)
                .where(PackageVersionRow.status == "published")
            )
            return PackageStats(
                package_name=package.name,
                install_count=0 if install_count is None else int(install_count),
                avg_rating=None,
                total_versions=(
                    0 if total_versions is None else int(total_versions)
                ),
                latest_version=package.latest_version,
                status=package.status,
            )


def seed_sqlalchemy_repository(
    repository: SqlAlchemyPackageRepository,
    source_repository: PackageRepository,
) -> None:
    """Copy package and version records from another repository."""
    packages = tuple(source_repository.list_packages())
    with repository.session_factory() as session, session.begin():
        for package in packages:
            _upsert_package(session, package)
        session.flush()
        for package in packages:
            for version in source_repository.list_versions(package.name):
                _upsert_version(session, version)


def _upsert_package(session: Session, package: PackageSummary) -> None:
    row = session.get(PackageRow, package.id)
    data = package.model_dump(mode="json")
    if row is None:
        session.add(
            PackageRow(
                id=package.id,
                name=package.name,
                status=package.status,
                latest_version=package.latest_version,
                data=data,
            )
        )
    else:
        row.name = package.name
        row.status = package.status
        row.latest_version = package.latest_version
        row.data = data


def _upsert_version(session: Session, version: VersionDetail) -> None:
    if session.get(PackageRow, version.package_id) is None:
        raise RepositoryDataError(
            f"Version {version.id} references unknown package {version.package_id}"
        )
    row = session.get(PackageVersionRow, version.id)
    data = version.model_dump(mode="json")
    if row is None:
        session.add(
            PackageVersionRow(
                id=version.id,
                package_id=version.package_id,
                version=version.version,
                status=version.status,
                data=data,
            )
        )
    else:
        row.package_id = version.package_id
        row.version = version.version
        row.status = version.status
        row.data = data


def _package_from_row(row: PackageRow) -> PackageSummary:
    return PackageSummary.model_validate(row.data)


def _version_from_row(row: PackageVersionRow) -> VersionDetail:
    return VersionDetail.model_validate(row.data)


def _serialize_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def _is_target_unique_violation(
    error: IntegrityError,
    *,
    constraint_name: str,
    sqlite_columns: tuple[str, ...],
) -> bool:
    original = error.orig
    if isinstance(original, sqlite3.IntegrityError):
        expected = "UNIQUE constraint failed: " + ", ".join(sqlite_columns)
        return expected in str(original)

    sqlstate = getattr(original, "sqlstate", None) or getattr(
        original,
        "pgcode",
        None,
    )
    diagnostics = getattr(original, "diag", None)
    return (
        sqlstate == "23505"
        and diagnostics is not None
        and getattr(diagnostics, "constraint_name", None) == constraint_name
    )


def _feedback_payload(
    row: FeedbackRecordRow,
    package_name: str,
) -> dict[str, object]:
    return {
        "id": row.id,
        "package_name": package_name,
        "level": row.level,
        "comment": row.comment,
        "created_at": _serialize_datetime(row.created_at),
        "updated_at": _serialize_datetime(row.updated_at),
    }
