"""Environment-backed runtime settings for TrustedAgentHub.

Local development reads the repository-root ``.env`` file. Values already
present in the process environment always win, which lets Docker, CI, and
secret managers inject configuration without copying secret files into an
image.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
import os
from urllib.parse import quote

from dotenv import load_dotenv


def _find_repository_root(source_path: Path | None = None) -> Path:
    """Find a source checkout without assuming a fixed installation depth.

    Docker copies this module to ``/app/src/settings.py`` while a source
    checkout keeps it under ``apps/api/src``.  Installed wheels can live at
    yet another depth, so fall back to the process working directory when no
    checkout markers are present.
    """

    source_path = (source_path or Path(__file__)).resolve()
    for candidate in source_path.parents:
        has_project_layout = (candidate / "apps" / "api").is_dir()
        has_root_marker = (
            (candidate / ".env.example").is_file()
            or (candidate / "docker-compose.yml").is_file()
        )
        if has_project_layout and has_root_marker:
            return candidate
    return Path.cwd().resolve()


REPOSITORY_ROOT = _find_repository_root()
ENV_FILE = REPOSITORY_ROOT / ".env"
DEFAULT_ARTIFACTS_ROOT = (
    Path(__file__).resolve().parents[1] / "data" / "artifacts"
)

# Load once at import time. Docker/CI-provided values are never overwritten.
if os.getenv("TRUSTED_AGENT_HUB_SKIP_DOTENV", "").strip().lower() != "true":
    load_dotenv(ENV_FILE, override=False)


def _optional(name: str) -> str | None:
    value = os.getenv(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _boolean(name: str, default: bool = False) -> bool:
    value = _optional(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _literal_true(name: str) -> bool:
    """Enable security-sensitive exceptions only with the literal true."""

    value = _optional(name)
    return value is not None and value.lower() == "true"


def _integer(name: str, default: int, *, minimum: int = 1) -> int:
    value = _optional(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if parsed < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return parsed


def _database_url_from_environment() -> str | None:
    explicit = _optional("DATABASE_URL")
    if explicit:
        return explicit

    user = _optional("POSTGRES_USER")
    password = _optional("POSTGRES_PASSWORD")
    database = _optional("POSTGRES_DB")
    if not any((user, password, database)):
        return None
    if not all((user, password, database)):
        raise ValueError(
            "POSTGRES_USER, POSTGRES_PASSWORD, and POSTGRES_DB must be set together"
        )

    host = _optional("DATABASE_HOST") or "127.0.0.1"
    port = _integer("DATABASE_PORT", 5432)
    driver = _optional("DATABASE_DRIVER") or "postgresql"
    return (
        f"{driver}://{quote(user, safe='')}:{quote(password, safe='')}"
        f"@{host}:{port}/{quote(database, safe='')}"
    )


def _origins() -> tuple[str, ...]:
    raw = _optional("CORS_ALLOWED_ORIGINS") or "*"
    origins = tuple(
        value.strip().rstrip("/") for value in raw.split(",") if value.strip()
    )
    return origins or ("*",)


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable application configuration."""

    database_url: str | None = None
    allow_insecure_user_header: bool = False
    allow_insecure_http: bool = False
    jwt_secret: str | None = None
    github_token: str | None = None
    cors_allowed_origins: tuple[str, ...] = ("*",)
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_reload: bool = True
    artifacts_root: str = str(DEFAULT_ARTIFACTS_ROOT)
    source_snapshot_dir: str | None = None
    source_snapshot_ttl_seconds: int = 604800
    initial_admin_email: str | None = None
    initial_admin_password: str | None = None
    initial_admin_display_name: str = "Administrator"
    seed_admin_email: str | None = None
    seed_admin_password: str | None = None
    seed_reviewer_email: str | None = None
    seed_reviewer_password: str | None = None
    seed_submitter_email: str | None = None
    seed_submitter_password: str | None = None

    @classmethod
    def from_environment(cls) -> "Settings":
        return cls(
            database_url=_database_url_from_environment(),
            allow_insecure_user_header=_literal_true(
                "CONSUMER_ALLOW_INSECURE_USER_HEADER"
            ),
            allow_insecure_http=_literal_true("TAH_ALLOW_INSECURE_HTTP"),
            jwt_secret=_optional("JWT_SECRET"),
            github_token=_optional("GITHUB_TOKEN"),
            cors_allowed_origins=_origins(),
            api_host=_optional("API_HOST") or "127.0.0.1",
            api_port=_integer("API_PORT", 8000),
            api_reload=_boolean("API_RELOAD", True),
            artifacts_root=(
                _optional("ARTIFACTS_ROOT") or str(DEFAULT_ARTIFACTS_ROOT)
            ),
            source_snapshot_dir=_optional("SOURCE_SNAPSHOT_DIR"),
            source_snapshot_ttl_seconds=_integer(
                "SOURCE_SNAPSHOT_TTL_SECONDS", 604800
            ),
            initial_admin_email=_optional("INITIAL_ADMIN_EMAIL"),
            initial_admin_password=_optional("INITIAL_ADMIN_PASSWORD"),
            initial_admin_display_name=(
                _optional("INITIAL_ADMIN_DISPLAY_NAME") or "Administrator"
            ),
            seed_admin_email=_optional("SEED_ADMIN_EMAIL"),
            seed_admin_password=_optional("SEED_ADMIN_PASSWORD"),
            seed_reviewer_email=_optional("SEED_REVIEWER_EMAIL"),
            seed_reviewer_password=_optional("SEED_REVIEWER_PASSWORD"),
            seed_submitter_email=_optional("SEED_SUBMITTER_EMAIL"),
            seed_submitter_password=_optional("SEED_SUBMITTER_PASSWORD"),
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return process-wide settings."""

    return Settings.from_environment()


def clear_settings_cache() -> None:
    """Forget cached settings (primarily for tests)."""

    get_settings.cache_clear()
