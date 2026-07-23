"""Shared API contract-test fixtures backed by test-owned JSON data."""

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.dependencies import get_package_repository
from src.main import create_app
from src.repositories.mock import JsonPackageRepository

MOCK = Path(__file__).resolve().parent / "fixtures" / "mock"


@pytest.fixture
def repository() -> JsonPackageRepository:
    """Return an isolated repository loaded from test-owned fixtures."""
    return JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")


@pytest.fixture
def client(repository: JsonPackageRepository) -> Iterator[TestClient]:
    """Return a TestClient with the fixture repository overridden."""
    app = create_app()
    app.dependency_overrides[get_package_repository] = lambda: repository
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
