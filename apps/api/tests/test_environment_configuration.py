from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import unquote

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select
from sqlalchemy.engine import make_url

from src.database import create_engine_from_url, create_session_factory
from src.repositories.orm_producer import UserRow
from src.scripts.bootstrap_admin import bootstrap_initial_admin
from src.scripts.seed_producer import _configured_seed_users
from src.settings import (
    DEFAULT_ARTIFACTS_ROOT,
    ENV_FILE,
    REPOSITORY_ROOT,
    Settings,
    _find_repository_root,
)


_DATABASE_KEYS = (
    "DATABASE_URL",
    "DATABASE_DRIVER",
    "DATABASE_HOST",
    "DATABASE_PORT",
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
    "POSTGRES_DB",
)


def _clear_database_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _DATABASE_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_repository_root_env_file_is_the_single_local_source() -> None:
    assert ENV_FILE == REPOSITORY_ROOT / ".env"
    assert (REPOSITORY_ROOT / "docker-compose.yml").is_file()


def test_repository_root_discovery_supports_shallow_container_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app_root = tmp_path / "app"
    app_root.mkdir()
    source_path = (
        Path(tmp_path.anchor)
        / "trusted-agent-hub-shallow-container"
        / "app"
        / "src"
        / "settings.py"
    )
    monkeypatch.chdir(app_root)

    assert _find_repository_root(source_path) == app_root.resolve()


def test_explicit_database_url_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_database_environment(monkeypatch)
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///explicit.db")
    monkeypatch.setenv("POSTGRES_USER", "ignored")
    monkeypatch.setenv("POSTGRES_PASSWORD", "ignored")
    monkeypatch.setenv("POSTGRES_DB", "ignored")

    assert Settings.from_environment().database_url == "sqlite+pysqlite:///explicit.db"


def test_database_url_is_built_from_components_and_escapes_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_database_environment(monkeypatch)
    monkeypatch.setenv("POSTGRES_USER", "app-user")
    monkeypatch.setenv("POSTGRES_PASSWORD", "p@ss:/ word")
    monkeypatch.setenv("POSTGRES_DB", "trusted hub")
    monkeypatch.setenv("DATABASE_HOST", "db")
    monkeypatch.setenv("DATABASE_PORT", "5544")

    url = make_url(Settings.from_environment().database_url or "")

    assert url.username == "app-user"
    assert url.password == "p@ss:/ word"
    assert unquote(url.database or "") == "trusted hub"
    assert url.host == "db"
    assert url.port == 5544


def test_partial_database_credentials_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_database_environment(monkeypatch)
    monkeypatch.setenv("POSTGRES_USER", "app")

    with pytest.raises(ValueError, match="must be set together"):
        Settings.from_environment()


def test_public_and_security_settings_are_parsed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "CORS_ALLOWED_ORIGINS",
        "https://hub.example.com/, https://admin.example.com",
    )
    monkeypatch.setenv("TAH_ALLOW_INSECURE_HTTP", "true")
    monkeypatch.setenv("API_PORT", "9000")
    monkeypatch.setenv("PUBLIC_API_BASE_URL", "https://hub.example.com/")

    settings = Settings.from_environment()

    assert settings.cors_allowed_origins == (
        "https://hub.example.com",
        "https://admin.example.com",
    )
    assert settings.allow_insecure_http is True
    assert settings.api_port == 9000
    assert settings.public_api_base_url == "https://hub.example.com"


@pytest.mark.parametrize(
    "value",
    [
        "hub.example.com",
        "ftp://hub.example.com",
        "https://hub.example.com/api",
        "https://hub.example.com?api=1",
        "https://hub.example.com#api",
    ],
)
def test_public_api_base_url_rejects_invalid_values(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("PUBLIC_API_BASE_URL", value)

    with pytest.raises(ValueError, match="PUBLIC_API_BASE_URL"):
        Settings.from_environment()


def test_public_api_base_url_rejects_non_local_http_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PUBLIC_API_BASE_URL", "http://hub.example.com")

    with pytest.raises(ValueError, match="TAH_ALLOW_INSECURE_HTTP"):
        Settings.from_environment()


def test_public_api_base_url_allows_non_local_http_when_opted_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TAH_ALLOW_INSECURE_HTTP", "true")
    monkeypatch.setenv("PUBLIC_API_BASE_URL", "http://140.143.119.142:8000/")

    settings = Settings.from_environment()

    assert settings.public_api_base_url == "http://140.143.119.142:8000"


def test_blank_container_overrides_use_safe_local_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key in ("API_HOST", "API_RELOAD", "ARTIFACTS_ROOT"):
        monkeypatch.setenv(key, "")

    settings = Settings.from_environment()

    assert settings.api_host == "127.0.0.1"
    assert settings.api_reload is True
    assert settings.artifacts_root == str(DEFAULT_ARTIFACTS_ROOT)


def test_environment_template_keeps_context_specific_values_blank() -> None:
    values: dict[str, str] = {}
    for raw_line in (REPOSITORY_ROOT / ".env.example").read_text(
        encoding="utf-8"
    ).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value

    assert values["DATABASE_HOST"] == ""
    assert values["API_HOST"] == ""
    assert values["API_RELOAD"] == ""
    assert values["ARTIFACTS_ROOT"] == ""
    assert values["SOURCE_SNAPSHOT_DIR"] == ""
    assert values["FASTEMBED_CACHE_PATH"] == ""
    assert values["TEST_DATABASE_URL"] == ""
    assert "FASTEMBED_CACHE_HOST_PATH" not in values
    for sensitive_key in (
        "POSTGRES_PASSWORD",
        "JWT_SECRET",
        "INITIAL_ADMIN_PASSWORD",
        "GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "NEXT_PUBLIC_DEMO_ACCOUNT_PASSWORD",
        "TRUSTED_AGENT_HUB_TOKEN",
        "SEED_ADMIN_PASSWORD",
        "SEED_REVIEWER_PASSWORD",
        "SEED_SUBMITTER_PASSWORD",
    ):
        assert values[sensitive_key] == ""


def test_all_user_facing_environment_variables_are_in_the_root_template() -> None:
    template_keys = {
        line.split("=", 1)[0]
        for line in (REPOSITORY_ROOT / ".env.example").read_text(
            encoding="utf-8"
        ).splitlines()
        if re.fullmatch(r"[A-Z][A-Z0-9_]*=.*", line)
    }
    configuration_sources = (
        REPOSITORY_ROOT / "docker-compose.yml",
        REPOSITORY_ROOT / "apps" / "api" / "Dockerfile",
        REPOSITORY_ROOT / "apps" / "api" / "src" / "settings.py",
        REPOSITORY_ROOT / "apps" / "api" / "tests" / "conftest.py",
        REPOSITORY_ROOT / "apps" / "cli" / "src" / "api-client.ts",
        REPOSITORY_ROOT / "apps" / "cli" / "src" / "network-policy.ts",
        REPOSITORY_ROOT / "apps" / "web" / "next.config.js",
        REPOSITORY_ROOT / "apps" / "web" / "scripts" / "render-install-guide.cjs",
        REPOSITORY_ROOT / "apps" / "web" / "src" / "lib" / "runtime-config.ts",
        REPOSITORY_ROOT / "scanners" / "risk_scanner" / "llm_reviewer.py",
        REPOSITORY_ROOT
        / "scanners"
        / "risk_scanner"
        / "rules"
        / "mcp_security.py",
    )
    runtime_patterns = (
        re.compile(r"process\.env\.([A-Z][A-Z0-9_]*)"),
        re.compile(
            r"(?:os\.getenv|os\.environ\.get|_optional|_boolean|_literal_true|"
            r"_integer|_environment_value)\(\s*[\"']([A-Z][A-Z0-9_]*)"
        ),
    )
    referenced_keys: set[str] = set()
    for source in configuration_sources:
        content = source.read_text(encoding="utf-8")
        for pattern in runtime_patterns:
            referenced_keys.update(pattern.findall(content))
        if source.name in {"docker-compose.yml", "Dockerfile"}:
            referenced_keys.update(
                re.findall(r"\$\{([A-Z][A-Z0-9_]*)", content)
            )

    internal_runtime_keys = {"NODE_ENV", "TRUSTED_AGENT_HUB_SKIP_DOTENV"}
    assert referenced_keys - template_keys - internal_runtime_keys == set()
    assert template_keys - referenced_keys == set()


def test_compose_and_dockerfiles_keep_context_specific_configuration_aligned() -> None:
    compose = (REPOSITORY_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    api_dockerfile = (REPOSITORY_ROOT / "apps" / "api" / "Dockerfile").read_text(
        encoding="utf-8"
    )
    web_dockerfile = (REPOSITORY_ROOT / "apps" / "web" / "Dockerfile").read_text(
        encoding="utf-8"
    )

    assert "DATABASE_HOST: ${DATABASE_HOST:-db}" in compose
    assert "ARTIFACTS_ROOT: ${ARTIFACTS_ROOT:-/artifacts}" in compose
    assert "SOURCE_SNAPSHOT_DIR: ${SOURCE_SNAPSHOT_DIR:-/source-snapshots}" in compose
    assert "FASTEMBED_CACHE_HOST_PATH" not in compose
    assert "FASTEMBED_CACHE_PATH: ${FASTEMBED_CACHE_PATH:-/fastembed-cache}" in compose
    assert "API_RELOAD:" not in compose
    assert "ARG FASTEMBED_CACHE_PATH=/fastembed-cache" in api_dockerfile
    assert "ENV FASTEMBED_CACHE_PATH=$FASTEMBED_CACHE_PATH" in api_dockerfile
    assert "cache_dir=os.environ['FASTEMBED_CACHE_PATH']" in api_dockerfile
    assert "--reload" not in api_dockerfile
    assert "TAH_ALLOW_INSECURE_HTTP" not in web_dockerfile


def test_initial_admin_bootstrap_is_idempotent(tmp_path: Path) -> None:
    database_url = f"sqlite+pysqlite:///{(tmp_path / 'bootstrap.db').as_posix()}"
    config = Config(str(REPOSITORY_ROOT / "apps" / "api" / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    settings = Settings(
        database_url=database_url,
        initial_admin_email="Admin@Example.com",
        initial_admin_password="a-secure-password",
        initial_admin_display_name="Site Admin",
    )

    assert bootstrap_initial_admin(settings) is True
    assert bootstrap_initial_admin(settings) is False

    engine = create_engine_from_url(database_url)
    session = create_session_factory(engine)()
    try:
        users = session.scalars(select(UserRow)).all()
        assert len(users) == 1
        assert users[0].email == "admin@example.com"
        assert users[0].role == "admin"
        assert users[0].display_name == "Site Admin"
        assert users[0].password_hash != "a-secure-password"
    finally:
        session.close()
        engine.dispose()


def test_initial_admin_configuration_requires_a_complete_secure_pair() -> None:
    with pytest.raises(RuntimeError, match="must be set together"):
        bootstrap_initial_admin(Settings(initial_admin_email="admin@example.com"))

    with pytest.raises(RuntimeError, match="at least 12"):
        bootstrap_initial_admin(
            Settings(
                initial_admin_email="admin@example.com",
                initial_admin_password="too-short",
            )
        )


def test_seed_accounts_require_explicit_complete_pairs() -> None:
    assert _configured_seed_users(Settings()) == []

    with pytest.raises(RuntimeError, match="SEED_ADMIN_EMAIL.*must be set together"):
        _configured_seed_users(Settings(seed_admin_email="admin@example.com"))

    assert _configured_seed_users(
        Settings(
            seed_reviewer_email="Reviewer@Example.com",
            seed_reviewer_password="reviewer-password",
        )
    ) == [
        (
            "reviewer@example.com",
            "reviewer-password",
            "reviewer",
            "reviewer",
        )
    ]
