"""Environment-backed runtime settings for the Consumer API."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import os


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable settings loaded from the process environment."""

    database_url: str | None = None
    allow_insecure_user_header: bool = False

    @classmethod
    def from_environment(cls) -> "Settings":
        database_url = os.getenv("DATABASE_URL")
        if database_url is not None:
            database_url = database_url.strip() or None
        allow_header = os.getenv(
            "CONSUMER_ALLOW_INSECURE_USER_HEADER", ""
        ).strip().lower()
        return cls(
            database_url=database_url,
            allow_insecure_user_header=allow_header == "true",
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return process-wide settings."""
    return Settings.from_environment()


def clear_settings_cache() -> None:
    """Forget cached environment settings (primarily for tests)."""
    get_settings.cache_clear()
