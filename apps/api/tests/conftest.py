"""Shared API contract-test fixtures backed by test-owned JSON data."""

from collections.abc import Iterator
import os
from pathlib import Path

import pytest
from dotenv import dotenv_values
from fastapi.testclient import TestClient


def _configured_test_database_url() -> str:
    """Read only the dedicated test URL, never the normal DATABASE_URL."""
    explicit_value = os.environ.get("TEST_DATABASE_URL", "").strip()
    if explicit_value:
        return explicit_value

    for parent in Path(__file__).resolve().parents:
        if (parent / ".env.example").is_file():
            value = dotenv_values(parent / ".env").get("TEST_DATABASE_URL")
            return str(value or "").strip()
    return ""


# Tests must never inherit development or production database configuration.
# PostgreSQL integration tests opt in only through TEST_DATABASE_URL.
_TEST_DATABASE_URL = _configured_test_database_url()
os.environ["TRUSTED_AGENT_HUB_SKIP_DOTENV"] = "true"
for _database_key in (
    "DATABASE_URL",
    "DATABASE_DRIVER",
    "DATABASE_HOST",
    "DATABASE_PORT",
    "POSTGRES_USER",
    "POSTGRES_PASSWORD",
    "POSTGRES_DB",
):
    os.environ[_database_key] = ""
if _TEST_DATABASE_URL:
    os.environ["DATABASE_URL"] = _TEST_DATABASE_URL

from src.dependencies import get_package_repository
from src.main import create_app
from src.repositories.mock import JsonPackageRepository

MOCK = Path(__file__).resolve().parent / "fixtures" / "mock"


@pytest.fixture
def repository() -> JsonPackageRepository:
    """Return an isolated repository loaded from test-owned fixtures."""
    return JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")


@pytest.fixture(autouse=True)
def _clear_stats_cache():
    """get_stats 的模块级缓存跨测试会污染结果，每次测试前清空。"""
    from src.services.packages import _STATS_CACHE

    _STATS_CACHE.clear()
    yield
    _STATS_CACHE.clear()


@pytest.fixture
def client(repository: JsonPackageRepository) -> Iterator[TestClient]:
    """Return a TestClient with the fixture repository overridden."""
    app = create_app()
    app.dependency_overrides[get_package_repository] = lambda: repository
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
