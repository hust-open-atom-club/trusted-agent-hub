"""Regression tests for the admin dashboard's version-level counters."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.orm import Session

from src.database import Base, create_engine_from_url, create_session_factory
from src.repositories.orm import PackageRow, PackageVersionRow
from src.repositories.producer_sqlalchemy import ProducerRepository


@pytest.fixture
def dashboard_repository() -> Iterator[
    tuple[ProducerRepository, Callable[[], Session]]
]:
    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)
    yield ProducerRepository(session_factory), session_factory
    engine.dispose()


def _add_package(
    session_factory: Callable[[], Session],
    *,
    package_id: str,
    package_status: str = "draft",
) -> None:
    with session_factory() as session:
        session.add(
            PackageRow(
                id=package_id,
                name=package_id,
                status=package_status,
                latest_version="0.0.0",
                data={
                    "id": package_id,
                    "name": package_id,
                    "status": package_status,
                },
            )
        )
        session.commit()


def _add_version(
    session_factory: Callable[[], Session],
    *,
    package_id: str,
    version_id: str,
    version: str,
    status: str,
    submitted_at: datetime | None = None,
) -> None:
    data: dict[str, object] = {
        "id": version_id,
        "package_id": package_id,
        "version": version,
        "status": status,
    }
    if submitted_at is not None:
        data["submitted_at"] = submitted_at.isoformat()

    with session_factory() as session:
        session.add(
            PackageVersionRow(
                id=version_id,
                package_id=package_id,
                version=version,
                status=status,
                data=data,
            )
        )
        session.commit()


def test_dashboard_workflow_counts_follow_version_statuses(
    dashboard_repository: tuple[ProducerRepository, Callable[[], Session]],
) -> None:
    repository, session_factory = dashboard_repository
    _add_package(session_factory, package_id="pkg-draft", package_status="draft")

    for index, status in enumerate(
        ("pending_review", "approved", "published", "rejected", "yanked"),
        start=1,
    ):
        _add_version(
            session_factory,
            package_id="pkg-draft",
            version_id=f"ver-{status}",
            version=f"1.0.{index}",
            status=status,
        )

    stats = repository.get_dashboard_stats()

    assert stats["total_packages"] == 1
    assert stats["total_versions"] == 5
    assert stats["pending_review"] == 1
    assert stats["approved"] == 1
    assert stats["published"] == 1
    assert stats["rejected"] == 1
    assert stats["yanked"] == 1


def test_dashboard_today_submissions_counts_versions_not_distinct_packages(
    dashboard_repository: tuple[ProducerRepository, Callable[[], Session]],
) -> None:
    repository, session_factory = dashboard_repository
    _add_package(session_factory, package_id="pkg-multiple-versions")
    now = datetime.now(timezone.utc)

    _add_version(
        session_factory,
        package_id="pkg-multiple-versions",
        version_id="ver-today-1",
        version="1.0.0",
        status="pending_review",
        submitted_at=now,
    )
    _add_version(
        session_factory,
        package_id="pkg-multiple-versions",
        version_id="ver-today-2",
        version="1.1.0",
        status="pending_review",
        submitted_at=now,
    )
    _add_version(
        session_factory,
        package_id="pkg-multiple-versions",
        version_id="ver-yesterday",
        version="0.9.0",
        status="rejected",
        submitted_at=now - timedelta(days=2),
    )

    stats = repository.get_dashboard_stats()

    assert stats["today_submissions"] == 2
