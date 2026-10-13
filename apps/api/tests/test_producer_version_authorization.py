"""Regression tests for producer version-list authorization."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.database import Base, create_engine_from_url, create_session_factory
from src.dependencies import CurrentUser
from src.auth import get_current_user
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


@pytest.mark.parametrize("role", ["submitter", "reviewer", "admin"])
def test_all_roles_can_filter_their_own_versions(producer_repository, monkeypatch, role):
    _seed_version(producer_repository, package_id="mine", version_id="my-version", submitter_id="owner")
    _seed_version(producer_repository, package_id="other", version_id="other-version", submitter_id="other")
    monkeypatch.setattr(producer_router, "_get_producer_repository", lambda: producer_repository)
    monkeypatch.setattr(ProducerService, "cleanup_orphan_artifacts", lambda self: 0)
    rows = _list_versions(CurrentUser(id="owner", role=role), submitter_id="owner")
    assert [row["version_id"] for row in rows] == ["my-version"]


@pytest.mark.parametrize("role,user_id,expected_status", [
    ("submitter", "owner", 200), ("reviewer", "reviewer", 200),
    ("admin", "admin", 200), ("submitter", "other", 403),
])
def test_exact_name_lookup_resolves_private_versions_and_respects_access(
    producer_repository, monkeypatch, role, user_id, expected_status,
):
    _seed_version(producer_repository, package_id="existing-tool", version_id="ver-existing", submitter_id="owner")
    with producer_repository.session_factory() as session:
        version = session.get(PackageVersionRow, "ver-existing")
        version.status = "changes_requested"
        version.data = {**version.data, "status": "changes_requested", "internal_notes": "not public"}
        session.commit()
    monkeypatch.setattr(producer_router, "_get_producer_repository", lambda: producer_repository)
    app = FastAPI()
    app.include_router(producer_router.router)
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(id=user_id, role=role)
    with TestClient(app) as client:
        response = client.get("/api/v0/producer/packages/lookup", params={"name": "existing-tool"})
    assert response.status_code == expected_status
    if expected_status == 200:
        result = response.json()
        assert result["package_id"] == "existing-tool"
        assert result["versions"][0]["status"] == "changes_requested"
        assert set(result["versions"][0]) == {"id", "version", "status", "submitted_at"}
        assert "not public" not in response.text
    assert producer_repository.get_version("ver-existing")["status"] == "changes_requested"


def test_name_lookup_returns_none_for_an_available_name(producer_repository, monkeypatch):
    monkeypatch.setattr(producer_router, "_get_producer_repository", lambda: producer_repository)
    assert producer_router.lookup_package(name="unused", _user=CurrentUser(id="owner", role="submitter")) is None
