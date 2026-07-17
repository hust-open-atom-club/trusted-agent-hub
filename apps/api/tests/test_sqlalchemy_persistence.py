"""Focused persistence tests for transaction and concurrency behavior."""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import delete, event, func, select
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from src.database import Base, create_engine_from_url, create_session_factory
from src.models.packages import PackageSummary, VersionDetail
from src.repositories import base as repository_contracts
from src.repositories.mock import JsonPackageRepository
from src.repositories.orm import (
    FeedbackRecordRow,
    InstallRecordRow,
    PackageRow,
    PackageVersionRow,
)
from src.repositories.sqlalchemy import (
    SqlAlchemyPackageRepository,
    seed_sqlalchemy_repository,
)


ROOT = Path(__file__).resolve().parents[3]
MOCK = ROOT / "packages" / "schema" / "mock"


@pytest.fixture
def repository() -> tuple[SqlAlchemyPackageRepository, Callable[[], Session]]:
    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)
    repository = SqlAlchemyPackageRepository(session_factory)
    seed_sqlalchemy_repository(
        repository,
        JsonPackageRepository(MOCK / "packages.json", MOCK / "versions"),
    )
    return repository, session_factory


def test_consumer_persistence_repository_is_runtime_checkable(
    repository: tuple[SqlAlchemyPackageRepository, Callable[[], Session]],
) -> None:
    sqlalchemy_repository, _ = repository
    json_repository = JsonPackageRepository(
        MOCK / "packages.json",
        MOCK / "versions",
    )

    type_guard = getattr(
        repository_contracts,
        "is_consumer_persistence_repository",
        lambda _: False,
    )
    assert type_guard(sqlalchemy_repository)
    assert not type_guard(json_repository)


def test_consumer_persistence_type_guard_does_not_execute_dynamic_attributes(
) -> None:
    class DynamicAttributes:
        def __getattr__(self, name: str) -> object:
            raise AssertionError(f"dynamic attribute was evaluated: {name}")

    assert not repository_contracts.is_consumer_persistence_repository(
        DynamicAttributes()  # type: ignore[arg-type]
    )


def test_consumer_persistence_type_guard_rejects_accidental_method_names() -> None:
    class AccidentalMethodNames:
        list_packages = get_package = list_versions = lambda self, *args: ()
        get_version = get_version_by_id = lambda self, *args: None
        record_install = upsert_feedback = lambda self, **kwargs: ({}, False)
        list_feedback = lambda self, **kwargs: {}
        get_trust_level = lambda self, version_id: None

    assert not repository_contracts.is_consumer_persistence_repository(
        AccidentalMethodNames()  # type: ignore[arg-type]
    )


def test_record_install_loads_concurrent_winner_after_unique_conflict(
    repository: tuple[SqlAlchemyPackageRepository, Callable[[], Session]],
) -> None:
    sqlalchemy_repository, session_factory = repository
    winner = InstallRecordRow(
        id="inst-winner",
        version_id="ver-001",
        user_id="user-race",
        client="claude-code",
        install_path="~/.claude/skills/code-review-skill",
        integrity_verified=True,
        installed_at=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )
    sqlalchemy_repository.session_factory = _race_on_commit_factory(
        session_factory,
        winner,
    )

    payload, created = sqlalchemy_repository.record_install(
        package_name="code-review-skill",
        version="1.0.0",
        version_id="ver-001",
        user_id="user-race",
        client="claude-code",
        install_path="~/.claude/skills/code-review-skill",
        integrity_verified=False,
    )

    assert created is False
    assert payload["id"] == "inst-winner"
    assert payload["integrity_verified"] is True


def test_upsert_feedback_loads_concurrent_winner_after_unique_conflict(
    repository: tuple[SqlAlchemyPackageRepository, Callable[[], Session]],
) -> None:
    sqlalchemy_repository, session_factory = repository
    now = datetime(2026, 7, 16, tzinfo=timezone.utc)
    winner = FeedbackRecordRow(
        id="fb-winner",
        package_id="pkg-001",
        user_id="user-race",
        level="neutral",
        comment="winner",
        created_at=now,
        updated_at=now,
    )
    sqlalchemy_repository.session_factory = _race_on_commit_factory(
        session_factory,
        winner,
    )

    payload, created = sqlalchemy_repository.upsert_feedback(
        package_name="code-review-skill",
        package_id="pkg-001",
        user_id="user-race",
        level="positive",
        comment="loser",
    )

    assert created is False
    assert payload["id"] == "fb-winner"
    assert payload["level"] == "neutral"
    assert payload["comment"] == "winner"


def test_record_install_reraises_non_idempotency_integrity_error(
    repository: tuple[SqlAlchemyPackageRepository, Callable[[], Session]],
) -> None:
    sqlalchemy_repository, session_factory = repository
    winner = InstallRecordRow(
        id="inst-winner",
        version_id="ver-001",
        user_id="user-race",
        client="claude-code",
        install_path="~/.claude/skills/code-review-skill",
        integrity_verified=True,
        installed_at=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )
    unrelated_error = IntegrityError(
        "INSERT INTO install_records ...",
        {},
        sqlite3.IntegrityError("CHECK constraint failed: unrelated_constraint"),
    )
    sqlalchemy_repository.session_factory = _race_on_commit_factory(
        session_factory,
        winner,
        error=unrelated_error,
    )

    with pytest.raises(IntegrityError) as raised:
        sqlalchemy_repository.record_install(
            package_name="code-review-skill",
            version="1.0.0",
            version_id="ver-001",
            user_id="user-race",
            client="claude-code",
            install_path="~/.claude/skills/code-review-skill",
            integrity_verified=False,
        )

    assert raised.value is unrelated_error


@pytest.mark.skipif(
    not os.environ.get("TEST_DATABASE_URL")
    or make_url(os.environ.get("TEST_DATABASE_URL", "sqlite://")).get_backend_name()
    != "postgresql",
    reason="TEST_DATABASE_URL is not configured for PostgreSQL",
)
def test_postgresql_concurrent_install_and_feedback_are_idempotent() -> None:
    database_url = os.environ["TEST_DATABASE_URL"]
    engine = create_engine_from_url(database_url)
    Base.metadata.create_all(engine)
    package_id = f"pkg-race-{uuid4().hex}"
    version_id = f"ver-race-{uuid4().hex}"
    user_id = f"user-race-{uuid4().hex}"
    package_name = f"race-{uuid4().hex}"
    source = JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")
    package = source.get_package("code-review-skill")
    version = source.get_version("code-review-skill", "1.0.0")
    assert package is not None and version is not None
    setup_factory = create_session_factory(engine)
    with setup_factory() as session:
        session.add(
            PackageRow(
                id=package_id,
                name=package_name,
                status="published",
                latest_version="1.0.0",
                data=package.model_copy(
                    update={"id": package_id, "name": package_name}
                ).model_dump(mode="json"),
            )
        )
        session.add(
            PackageVersionRow(
                id=version_id,
                package_id=package_id,
                version="1.0.0",
                status="published",
                data=version.model_copy(
                    update={"id": version_id, "package_id": package_id}
                ).model_dump(mode="json"),
            )
        )
        session.commit()

    barriers = {"install_records": Barrier(2), "feedback_records": Barrier(2)}

    class ConcurrentSession(Session):
        def scalar(self, statement: object, *args: object, **kwargs: object) -> object:
            result = super().scalar(statement, *args, **kwargs)
            sql = str(statement)
            for table_name, barrier in barriers.items():
                marker = f"waited_for_{table_name}"
                if table_name in sql and not getattr(self, marker, False):
                    setattr(self, marker, True)
                    barrier.wait(timeout=10)
            return result

    concurrent_factory = sessionmaker(
        bind=engine,
        class_=ConcurrentSession,
        autoflush=False,
        expire_on_commit=False,
    )
    repository = SqlAlchemyPackageRepository(concurrent_factory)

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            install_results = list(
                executor.map(
                    lambda _: repository.record_install(
                        package_name=package_name,
                        version="1.0.0",
                        version_id=version_id,
                        user_id=user_id,
                        client="claude-code",
                        install_path="/tmp/concurrent-install",
                        integrity_verified=True,
                    ),
                    range(2),
                )
            )
        assert sorted(created for _, created in install_results) == [False, True]
        assert len({payload["id"] for payload, _ in install_results}) == 1

        with ThreadPoolExecutor(max_workers=2) as executor:
            feedback_results = list(
                executor.map(
                    lambda _: repository.upsert_feedback(
                        package_name=package_name,
                        package_id=package_id,
                        user_id=user_id,
                        level="positive",
                        comment="concurrent",
                    ),
                    range(2),
                )
            )
        assert sorted(created for _, created in feedback_results) == [False, True]
        assert len({payload["id"] for payload, _ in feedback_results}) == 1
    finally:
        with setup_factory() as session:
            session.execute(delete(PackageRow).where(PackageRow.id == package_id))
            session.commit()
        engine.dispose()



def test_seed_repository_commits_all_rows_in_one_transaction() -> None:
    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)
    repository = SqlAlchemyPackageRepository(session_factory)
    commits = 0

    @event.listens_for(Session, "after_commit")
    def count_commit(_: Session) -> None:
        nonlocal commits
        commits += 1

    try:
        seed_sqlalchemy_repository(
            repository,
            JsonPackageRepository(MOCK / "packages.json", MOCK / "versions"),
        )
    finally:
        event.remove(Session, "after_commit", count_commit)

    assert commits == 1


def test_seed_repository_rolls_back_all_rows_when_a_version_is_invalid() -> None:
    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)
    repository = SqlAlchemyPackageRepository(session_factory)
    source = _InvalidVersionSource(
        JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")
    )

    with pytest.raises(Exception, match="unknown package"):
        seed_sqlalchemy_repository(repository, source)

    with session_factory() as session:
        assert session.scalar(select(func.count()).select_from(PackageRow)) == 0


def _race_on_commit_factory(
    session_factory: Callable[[], Session],
    winner: InstallRecordRow | FeedbackRecordRow,
    *,
    error: IntegrityError | None = None,
) -> Callable[[], Session]:
    armed = True

    def create_session() -> Session:
        nonlocal armed
        session = session_factory()
        original_commit = session.commit

        def commit() -> None:
            nonlocal armed
            if armed:
                armed = False
                with session_factory() as competing_session:
                    competing_session.add(winner)
                    competing_session.commit()
                if error is not None:
                    session.rollback()
                    raise error
            original_commit()

        session.commit = commit  # type: ignore[method-assign]
        return session

    return create_session


class _InvalidVersionSource:
    def __init__(self, source: JsonPackageRepository) -> None:
        self.source = source

    def list_packages(self) -> tuple[PackageSummary, ...]:
        package = self.source.get_package("code-review-skill")
        assert package is not None
        return (package,)

    def list_versions(self, name: str) -> tuple[VersionDetail, ...]:
        version = self.source.get_version(name, "1.0.0")
        assert version is not None
        return (version.model_copy(update={"package_id": "pkg-missing"}),)
