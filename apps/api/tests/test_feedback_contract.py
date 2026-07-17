"""Consumer persistence contract tests for installs, feedback, and levels."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from src.database import Base, create_engine_from_url, create_session_factory
from src.dependencies import clear_runtime_dependencies, get_package_repository
from src.main import create_app
from src.models import (
    FeedbackLevel,
    FeedbackListQuery,
    FeedbackPage,
    FeedbackRecord,
    FeedbackRequest,
    InstallRecord,
    InstallReportRequest,
    TrustLevelName,
    TrustLevelResponse,
)
from src.repositories.mock import JsonPackageRepository
from src.repositories.sqlalchemy import (
    SqlAlchemyPackageRepository,
    seed_sqlalchemy_repository,
)
from src.services.feedback import FeedbackService


ROOT = Path(__file__).resolve().parents[3]
MOCK = ROOT / "packages" / "schema" / "mock"
API_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def db_repository() -> Iterator[SqlAlchemyPackageRepository]:
    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    try:
        Base.metadata.create_all(engine)
        session_factory = create_session_factory(engine)
        repository = SqlAlchemyPackageRepository(session_factory)
        seed_sqlalchemy_repository(
            repository,
            JsonPackageRepository(MOCK / "packages.json", MOCK / "versions"),
        )
        yield repository
    finally:
        engine.dispose()


@pytest.fixture
def db_client(
    db_repository: SqlAlchemyPackageRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[TestClient]:
    monkeypatch.setenv("CONSUMER_ALLOW_INSECURE_USER_HEADER", "true")
    clear_runtime_dependencies()
    app = create_app()
    app.dependency_overrides[get_package_repository] = lambda: db_repository
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    clear_runtime_dependencies()


def test_install_report_requires_authenticated_user(
    db_client: TestClient,
) -> None:
    response = db_client.post(
        "/api/v0/installs",
        json={
            "package_name": "code-review-skill",
            "version": "1.0.0",
            "client": "claude-code",
            "install_path": "~/.claude/skills/code-review-skill",
            "integrity_verified": True,
        },
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_required"


def test_install_report_is_idempotent_and_updates_database_stats(
    db_client: TestClient,
) -> None:
    payload = {
        "package_name": "code-review-skill",
        "version": "1.0.0",
        "client": "claude-code",
        "install_path": "~/.claude/skills/code-review-skill",
        "integrity_verified": True,
    }

    first = db_client.post(
        "/api/v0/installs",
        json=payload,
        headers={"X-User-Id": "user-1"},
    )
    second = db_client.post(
        "/api/v0/installs",
        json=payload,
        headers={"X-User-Id": "user-1"},
    )
    stats = db_client.get("/api/v0/stats/packages/code-review-skill")

    assert first.status_code == 201
    assert second.status_code == 200
    assert first.json()["id"] == second.json()["id"]
    assert stats.status_code == 200
    assert stats.json()["install_count"] == 1
    assert stats.json()["avg_rating"] is None


def test_non_public_package_cannot_create_install_record(
    db_client: TestClient,
) -> None:
    response = db_client.post(
        "/api/v0/installs",
        json={
            "package_name": "risky-executor",
            "version": "0.1.0",
            "client": "claude-code",
            "install_path": "~/.claude/skills/risky-executor",
            "integrity_verified": True,
        },
        headers={"X-User-Id": "user-1"},
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "package_not_found"


def test_feedback_uses_levels_instead_of_numeric_scores(
    db_client: TestClient,
) -> None:
    created = db_client.post(
        "/api/v0/packages/code-review-skill/feedback",
        json={
            "level": "positive",
            "comment": "Installed cleanly and the manifest was easy to inspect.",
        },
        headers={"X-User-Id": "user-1"},
    )
    listed = db_client.get("/api/v0/packages/code-review-skill/feedback")

    assert created.status_code == 201
    assert "score" not in created.json()
    assert "user_id" not in created.json()
    assert created.json()["level"] == "positive"
    assert listed.status_code == 200
    assert listed.json()["level_counts"] == {
        "positive": 1,
        "neutral": 0,
        "negative": 0,
    }
    assert listed.json()["items"][0]["comment"] == (
        "Installed cleanly and the manifest was easy to inspect."
    )
    assert "user_id" not in listed.json()["items"][0]


def test_feedback_requires_authenticated_user(db_client: TestClient) -> None:
    response = db_client.post(
        "/api/v0/packages/code-review-skill/feedback",
        json={"level": "positive"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_required"


def test_feedback_rejects_numeric_score(db_client: TestClient) -> None:
    response = db_client.post(
        "/api/v0/packages/code-review-skill/feedback",
        json={"level": "positive", "score": 5},
        headers={"X-User-Id": "user-1"},
    )

    assert response.status_code == 422


def test_install_report_rejects_unknown_query_parameters_before_service(
    db_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("record_install service must not be called")

    monkeypatch.setattr(FeedbackService, "record_install", fail_if_called)

    response = db_client.post(
        "/api/v0/installs?score=5",
        json={
            "package_name": "code-review-skill",
            "version": "1.0.0",
            "client": "claude-code",
            "install_path": "~/.claude/skills/code-review-skill",
            "integrity_verified": True,
        },
        headers={"X-User-Id": "user-1"},
    )

    assert response.status_code == 422


def test_feedback_post_rejects_unknown_query_parameters_before_service(
    db_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("upsert_feedback service must not be called")

    monkeypatch.setattr(FeedbackService, "upsert_feedback", fail_if_called)

    response = db_client.post(
        "/api/v0/packages/code-review-skill/feedback?score=5",
        json={"level": "positive"},
        headers={"X-User-Id": "user-1"},
    )

    assert response.status_code == 422


def test_feedback_list_rejects_unknown_query_parameters(
    db_client: TestClient,
) -> None:
    response = db_client.get(
        "/api/v0/packages/code-review-skill/feedback?score=5"
    )

    assert response.status_code == 422


def test_trust_level_rejects_unknown_query_parameters(
    db_client: TestClient,
) -> None:
    response = db_client.get("/api/v0/versions/ver-001/trust-level?score=5")

    assert response.status_code == 422


def test_user_feedback_level_is_updated_per_package_and_user(
    db_client: TestClient,
) -> None:
    headers = {"X-User-Id": "user-1"}

    first = db_client.post(
        "/api/v0/packages/code-review-skill/feedback",
        json={"level": "neutral", "comment": "Needs clearer docs."},
        headers=headers,
    )
    second = db_client.post(
        "/api/v0/packages/code-review-skill/feedback",
        json={"level": "negative", "comment": "Install failed locally."},
        headers=headers,
    )
    listed = db_client.get("/api/v0/packages/code-review-skill/feedback")

    assert first.status_code == 201
    assert second.status_code == 200
    assert first.json()["id"] == second.json()["id"]
    assert listed.json()["total"] == 1
    assert listed.json()["level_counts"]["negative"] == 1
    assert listed.json()["items"][0]["comment"] == "Install failed locally."


def test_persisted_trust_level_exposes_no_numeric_score(
    db_client: TestClient,
    db_repository: SqlAlchemyPackageRepository,
) -> None:
    version = db_repository.get_version("code-review-skill", "1.0.0")
    assert version is not None
    db_repository.upsert_trust_level(
        version_id=version.id,
        level="low_risk",
        install_recommendation="review_recommended",
        top_risks=["Requests shell access"],
        explanation="Review the requested shell permissions before install.",
        model_version="trust-level-v1",
    )

    response = db_client.get(f"/api/v0/versions/{version.id}/trust-level")

    assert response.status_code == 200
    assert response.json()["level"] == "low_risk"
    assert "score" not in response.json()
    assert response.json()["top_risks"] == ["Requests shell access"]


@pytest.mark.parametrize("version_id", ["missing-version", "ver-005"])
def test_unavailable_version_uses_trust_level_not_found_semantics(
    db_client: TestClient,
    version_id: str,
) -> None:
    response = db_client.get(f"/api/v0/versions/{version_id}/trust-level")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "trust_level_not_found"


def test_public_version_without_level_uses_trust_level_not_found_semantics(
    db_client: TestClient,
) -> None:
    response = db_client.get("/api/v0/versions/ver-001/trust-level")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "trust_level_not_found"


def test_database_configured_default_app_persists_feedback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    database_url = f"sqlite+pysqlite:///{(tmp_path / 'consumer.db').as_posix()}"
    config = Config(str(API_ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    monkeypatch.setenv("DATABASE_URL", database_url)
    monkeypatch.setenv("CONSUMER_ALLOW_INSECURE_USER_HEADER", "true")
    clear_runtime_dependencies()
    repository = get_package_repository()
    assert isinstance(repository, SqlAlchemyPackageRepository)
    seed_sqlalchemy_repository(
        repository,
        JsonPackageRepository(MOCK / "packages.json", MOCK / "versions"),
    )

    app = create_app()
    assert not app.dependency_overrides
    with TestClient(app) as client:
        created = client.post(
            "/api/v0/packages/code-review-skill/feedback",
            json={"level": "positive", "comment": "Persisted by default app."},
            headers={"X-User-Id": "runtime-user"},
        )
        listed = client.get("/api/v0/packages/code-review-skill/feedback")

    assert created.status_code == 201
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert "user_id" not in created.json()
    assert "user_id" not in listed.json()["items"][0]


def test_feedback_models_are_exported_from_canonical_models_package() -> None:
    assert FeedbackLevel.POSITIVE == "positive"
    assert TrustLevelName.LOW_RISK == "low_risk"
    assert FeedbackRequest.model_fields
    assert FeedbackRecord.model_fields
    assert "user_id" not in FeedbackRecord.model_fields
    assert FeedbackPage.model_fields
    assert FeedbackListQuery.model_fields
    assert InstallReportRequest.model_fields
    assert InstallRecord.model_fields
    assert TrustLevelResponse.model_fields
