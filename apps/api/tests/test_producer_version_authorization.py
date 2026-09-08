"""Regression tests for producer version-list authorization."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import datetime, timezone

import pytest
from sqlalchemy.orm import Session

from src.database import Base, create_engine_from_url, create_session_factory
from src.dependencies import CurrentUser
from src.repositories.orm import PackageRow, PackageVersionRow
from src.repositories.producer_sqlalchemy import ProducerRepository
from src.routers import producer as producer_router
from src.services.producer import ProducerService


@pytest.fixture
def producer_repository() -> Iterator[ProducerRepository]:
    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield ProducerRepository(create_session_factory(engine))
    engine.dispose()


def _seed_version(
    repository: ProducerRepository,
    *,
    package_id: str,
    version_id: str,
    submitter_id: str,
) -> None:
    session_factory: Callable[[], Session] = repository.session_factory
    with session_factory() as session:
        session.add(
            PackageRow(
                id=package_id,
                name=package_id,
                status="draft",
                latest_version="1.0.0",
                data={
                    "id": package_id,
                    "name": package_id,
                    "submitter_id": submitter_id,
                },
            )
        )
        session.add(
            PackageVersionRow(
                id=version_id,
                package_id=package_id,
                version="1.0.0",
                status="published",
                data={
                    "id": version_id,
                    "package_id": package_id,
                    "version": "1.0.0",
                    "status": "published",
                    "submitter_id": submitter_id,
                    "submitted_at": datetime.now(timezone.utc).isoformat(),
                },
            )
        )
        session.commit()


def _list_versions(
    user: CurrentUser,
    *,
    submitter_id: str | None = None,
    status: str | None = None,
) -> list[dict[str, object]]:
    return producer_router.list_versions(
        submitter_id=submitter_id,
        status=status,
        grade=None,
        since=None,
        until=None,
        limit=50,
        offset=0,
        _user=user,
    )


def test_submitter_without_submitter_filter_sees_only_own_versions(
    producer_repository: ProducerRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_version(
        producer_repository,
        package_id="pkg-owner",
        version_id="ver-owner",
        submitter_id="submitter-owner",
    )
    _seed_version(
        producer_repository,
        package_id="pkg-other",
        version_id="ver-other",
        submitter_id="submitter-other",
    )
    monkeypatch.setattr(
        producer_router,
        "_get_producer_repository",
        lambda: producer_repository,
    )
    monkeypatch.setattr(ProducerService, "cleanup_orphan_artifacts", lambda self: 0)

    rows = _list_versions(
        CurrentUser(id="submitter-owner", role="submitter"),
    )

    assert [row["version_id"] for row in rows] == ["ver-owner"]


def test_submitter_cannot_expand_scope_with_filters_or_another_submitter_id(
    producer_repository: ProducerRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_version(
        producer_repository,
        package_id="pkg-owner-filtered",
        version_id="ver-owner-filtered",
        submitter_id="submitter-owner",
    )
    _seed_version(
        producer_repository,
        package_id="pkg-other-filtered",
        version_id="ver-other-filtered",
        submitter_id="submitter-other",
    )
    monkeypatch.setattr(
        producer_router,
        "_get_producer_repository",
        lambda: producer_repository,
    )
    monkeypatch.setattr(ProducerService, "cleanup_orphan_artifacts", lambda self: 0)

    rows = _list_versions(
        CurrentUser(id="submitter-owner", role="submitter"),
        submitter_id="submitter-other",
        status="published",
    )

    assert [row["version_id"] for row in rows] == ["ver-owner-filtered"]


def test_reviewer_can_still_read_global_version_queue(
    producer_repository: ProducerRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_version(
        producer_repository,
        package_id="pkg-review-owner",
        version_id="ver-review-owner",
        submitter_id="submitter-owner",
    )
    _seed_version(
        producer_repository,
        package_id="pkg-review-other",
        version_id="ver-review-other",
        submitter_id="submitter-other",
    )
    monkeypatch.setattr(
        producer_router,
        "_get_producer_repository",
        lambda: producer_repository,
    )
    monkeypatch.setattr(ProducerService, "cleanup_orphan_artifacts", lambda self: 0)

    rows = _list_versions(CurrentUser(id="reviewer", role="reviewer"))

    assert {row["version_id"] for row in rows} == {
        "ver-review-owner",
        "ver-review-other",
    }
