"""Regression tests for the admin dashboard's version-level counters."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.orm import Session

from src.database import Base, create_engine_from_url, create_session_factory
from src.repositories.orm import PackageRow, PackageVersionRow
from src.repositories.orm_producer import AuditLogRow, UserRow
from src.repositories.producer_sqlalchemy import ProducerRepository
from src.services.producer import ProducerService


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


def test_today_submission_listing_accepts_browser_utc_boundary_format(
    dashboard_repository: tuple[ProducerRepository, Callable[[], Session]],
) -> None:
    repository, session_factory = dashboard_repository
    today_start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    _add_package(session_factory, package_id="pkg-midnight")
    _add_version(
        session_factory,
        package_id="pkg-midnight",
        version_id="ver-midnight",
        version="1.0.0",
        status="pending_review",
        submitted_at=today_start,
    )

    # The browser sends an ISO string with millisecond precision and a Z
    # suffix, while persisted values use datetime.isoformat() with +00:00.
    browser_boundary = today_start.strftime("%Y-%m-%dT00:00:00.000Z")
    items = repository.list_versions_by_status(since=browser_boundary)

    assert repository.get_dashboard_stats()["today_submissions"] == 1
    assert [item["version_id"] for item in items] == ["ver-midnight"]


def test_version_status_listing_honors_pagination(
    dashboard_repository: tuple[ProducerRepository, Callable[[], Session]],
) -> None:
    repository, session_factory = dashboard_repository
    _add_package(session_factory, package_id="pkg-paginated")
    for index in range(3):
        _add_version(
            session_factory,
            package_id="pkg-paginated",
            version_id=f"ver-paginated-{index}",
            version=f"1.0.{index}",
            status="approved",
            submitted_at=datetime.now(timezone.utc) - timedelta(seconds=index),
        )

    page = repository.list_versions_by_status(
        status="approved", limit=1, offset=1
    )

    assert len(page) == 1
    assert page[0]["version_id"] == "ver-paginated-1"


def test_version_status_service_forwards_pagination(
    dashboard_repository: tuple[ProducerRepository, Callable[[], Session]],
) -> None:
    repository, _ = dashboard_repository
    calls: list[dict[str, object]] = []

    original = repository.list_versions_by_status

    def record_call(**kwargs: object) -> list[dict[str, object]]:
        calls.append(kwargs)
        return original(**kwargs)  # type: ignore[arg-type]

    repository.list_versions_by_status = record_call  # type: ignore[method-assign]
    ProducerService(repository).list_versions_by_status(
        status="approved", limit=7, offset=14
    )

    assert calls == [{
        "status": "approved",
        "grade": None,
        "since": None,
        "until": None,
        "limit": 7,
        "offset": 14,
    }]


def test_dashboard_approved_count_matches_publish_page_package_deduplication(
    dashboard_repository: tuple[ProducerRepository, Callable[[], Session]],
) -> None:
    repository, session_factory = dashboard_repository
    _add_package(session_factory, package_id="pkg-multiple-approved")
    _add_version(
        session_factory,
        package_id="pkg-multiple-approved",
        version_id="ver-approved-1",
        version="1.0.0",
        status="approved",
    )
    _add_version(
        session_factory,
        package_id="pkg-multiple-approved",
        version_id="ver-approved-2",
        version="1.1.0",
        status="approved",
    )

    stats = repository.get_dashboard_stats()

    # The publish page renders the newest approved version once per package.
    assert stats["approved"] == 1


def test_dashboard_user_count_includes_disabled_accounts(
    dashboard_repository: tuple[ProducerRepository, Callable[[], Session]],
) -> None:
    repository, session_factory = dashboard_repository
    with session_factory() as session:
        session.add_all([
            UserRow(
                id="user-active",
                email="active@example.com",
                password_hash="hash",
                role="user",
                display_name="Active",
                is_active=True,
            ),
            UserRow(
                id="user-disabled",
                email="disabled@example.com",
                password_hash="hash",
                role="user",
                display_name="Disabled",
                is_active=False,
            ),
        ])
        session.commit()

    stats = repository.get_dashboard_stats()

    assert stats["total_users"] == 2


def test_dashboard_audit_count_matches_unfiltered_audit_page(
    dashboard_repository: tuple[ProducerRepository, Callable[[], Session]],
) -> None:
    repository, session_factory = dashboard_repository
    now = datetime.now(timezone.utc)
    with session_factory() as session:
        session.add_all([
            AuditLogRow(
                id="audit-today",
                action="submit",
                target_type="version",
                target_id="ver-today",
                operator_id="user",
                timestamp=now,
            ),
            AuditLogRow(
                id="audit-history",
                action="submit",
                target_type="version",
                target_id="ver-history",
                operator_id="user",
                timestamp=now - timedelta(days=2),
            ),
        ])
        session.commit()

    stats = repository.get_dashboard_stats()

    assert stats["total_audit_logs"] == 2
    assert stats["today_audit_actions"] == 1
