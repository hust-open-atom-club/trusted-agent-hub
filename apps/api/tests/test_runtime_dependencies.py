"""Runtime repository and Consumer identity dependency tests."""

from __future__ import annotations

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import threading
import time

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool


@pytest.fixture(autouse=True)
def reset_runtime_dependencies() -> Iterator[None]:
    from src.dependencies import clear_runtime_dependencies

    clear_runtime_dependencies()
    yield
    clear_runtime_dependencies()


def test_repository_uses_json_mock_without_database_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.dependencies import get_package_repository
    from src.repositories.mock import JsonPackageRepository

    monkeypatch.delenv("DATABASE_URL", raising=False)

    assert isinstance(get_package_repository(), JsonPackageRepository)


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [
        ("true", True),
        (" TRUE ", True),
        ("1", False),
        ("yes", False),
        ("on", False),
        ("false", False),
        ("", False),
    ],
)
def test_insecure_user_header_flag_accepts_only_literal_true(
    monkeypatch: pytest.MonkeyPatch,
    raw_value: str,
    expected: bool,
) -> None:
    from src.settings import Settings

    monkeypatch.setenv("CONSUMER_ALLOW_INSECURE_USER_HEADER", raw_value)

    assert Settings.from_environment().allow_insecure_user_header is expected


def test_database_url_selects_process_wide_sqlalchemy_repository(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from src.dependencies import get_package_repository
    from src.repositories.sqlalchemy import SqlAlchemyPackageRepository

    database_url = f"sqlite+pysqlite:///{tmp_path / 'consumer.db'}"
    monkeypatch.setenv("DATABASE_URL", database_url)

    first = get_package_repository()
    second = get_package_repository()

    assert isinstance(first, SqlAlchemyPackageRepository)
    assert second is first


def test_clearing_runtime_dependencies_disposes_cached_engine(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from src.database import get_runtime_engine
    from src.dependencies import (
        clear_runtime_dependencies,
        get_package_repository,
    )

    database_url = f"sqlite+pysqlite:///{tmp_path / 'consumer.db'}"
    monkeypatch.setenv("DATABASE_URL", database_url)
    get_package_repository()
    engine = get_runtime_engine(database_url)
    disposed = False

    def mark_disposed() -> None:
        nonlocal disposed
        disposed = True

    monkeypatch.setattr(engine, "dispose", mark_disposed)

    clear_runtime_dependencies()

    assert disposed is True
    assert get_runtime_engine(database_url) is not engine


def test_runtime_engine_is_created_once_during_concurrent_first_access(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from src import database

    database_url = f"sqlite+pysqlite:///{tmp_path / 'consumer.db'}"
    original_create_engine = database.create_engine_from_url
    start = threading.Barrier(8)
    create_count = 0
    count_lock = threading.Lock()

    def slow_create_engine(url: str):
        nonlocal create_count
        with count_lock:
            create_count += 1
        time.sleep(0.05)
        return original_create_engine(url)

    def get_engine_after_shared_start():
        start.wait()
        return database.get_runtime_engine(database_url)

    monkeypatch.setattr(database, "create_engine_from_url", slow_create_engine)

    with ThreadPoolExecutor(max_workers=8) as executor:
        engines = tuple(executor.map(lambda _index: get_engine_after_shared_start(), range(8)))

    assert create_count == 1
    assert all(engine is engines[0] for engine in engines)


@pytest.mark.parametrize(
    "database_url",
    [
        "sqlite://",
        "sqlite+pysqlite:///:memory:",
        "sqlite+pysqlite:///:memory:?cache=shared",
    ],
)
def test_sqlite_memory_url_variants_use_static_pool(database_url: str) -> None:
    from src.database import create_engine_from_url

    engine = create_engine_from_url(database_url)
    try:
        assert isinstance(engine.pool, StaticPool)
    finally:
        engine.dispose()


def test_insecure_user_header_is_rejected_without_explicit_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.main import create_app

    monkeypatch.delenv("CONSUMER_ALLOW_INSECURE_USER_HEADER", raising=False)

    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v0/installs",
            headers={"X-User-Id": "spoofed-user"},
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


def test_default_bearer_verifier_rejects_tokens_with_canonical_401() -> None:
    from src.main import create_app

    with TestClient(create_app()) as client:
        response = client.post(
            "/api/v0/installs",
            headers={"Authorization": "Bearer invalid-token"},
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
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_invalid_bearer_contract_is_translated_to_canonical_401() -> None:
    from src.dependencies import (
        BearerTokenInvalid,
        get_bearer_token_verifier,
        get_current_user,
    )
    from src.main import create_app

    app = create_app()

    def reject_token(_token: str):
        raise BearerTokenInvalid("expired token")

    app.dependency_overrides[get_bearer_token_verifier] = lambda: reject_token

    @app.get("/_test/current-user")
    def current_user(current_user=Depends(get_current_user)) -> dict[str, str]:
        return {"id": current_user.id}

    with TestClient(app) as client:
        response = client.get(
            "/_test/current-user",
            headers={"Authorization": "Bearer expired-token"},
        )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "authentication_required"
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_unexpected_bearer_verifier_error_remains_internal_error() -> None:
    from src.dependencies import get_bearer_token_verifier, get_current_user
    from src.main import create_app

    app = create_app()

    def fail_verification(_token: str):
        raise RuntimeError("identity provider unavailable")

    app.dependency_overrides[get_bearer_token_verifier] = (
        lambda: fail_verification
    )

    @app.get("/_test/current-user")
    def current_user(current_user=Depends(get_current_user)) -> dict[str, str]:
        return {"id": current_user.id}

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get(
            "/_test/current-user",
            headers={"Authorization": "Bearer any-token"},
        )

    assert response.status_code == 500


def test_bearer_token_verifier_dependency_can_be_overridden() -> None:
    from src.dependencies import (
        CurrentUser,
        get_bearer_token_verifier,
        get_current_user,
    )
    from src.main import create_app

    app = create_app()

    def verify_token(token: str) -> CurrentUser:
        assert token == "valid-token"
        return CurrentUser(id="bearer-user")

    app.dependency_overrides[get_bearer_token_verifier] = lambda: verify_token

    @app.get("/_test/current-user")
    def current_user(
        current_user=Depends(get_current_user),
    ) -> dict[str, str]:
        return {"id": current_user.id}

    with TestClient(app) as client:
        response = client.get(
            "/_test/current-user",
            headers={"Authorization": "Bearer valid-token"},
        )

    assert response.status_code == 200
    assert response.json() == {"id": "bearer-user"}


def test_insecure_user_header_is_allowed_only_with_explicit_flag() -> None:
    from src.dependencies import get_current_user
    from src.errors import ConsumerAPIError
    from src.settings import Settings

    rejected = Settings(allow_insecure_user_header=False)
    allowed = Settings(allow_insecure_user_header=True)

    with pytest.raises(ConsumerAPIError) as error:
        get_current_user(
            credentials=None,
            verifier=lambda _token: None,
            x_user_id="development-user",
            settings=rejected,
        )

    assert getattr(error.value, "status_code", None) == 401
    assert get_current_user(
        credentials=None,
        verifier=lambda _token: None,
        x_user_id="development-user",
        settings=allowed,
    ).id == "development-user"


def test_current_user_dependency_can_be_overridden_for_authenticated_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.dependencies import CurrentUser, get_current_user
    from src.main import create_app

    monkeypatch.delenv("CONSUMER_ALLOW_INSECURE_USER_HEADER", raising=False)
    app = create_app()
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(
        id="test-user"
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/v0/installs",
            json={
                "package_name": "code-review-skill",
                "version": "1.0.0",
                "client": "claude-code",
                "install_path": "~/.claude/skills/code-review-skill",
                "integrity_verified": True,
            },
        )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "persistence_unavailable"
