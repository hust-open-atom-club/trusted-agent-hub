from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.dependencies import get_package_repository
from src.main import create_app
from src.repositories.mock import JsonPackageRepository


ROOT = Path(__file__).resolve().parents[3]
MOCK = ROOT / "packages" / "schema" / "mock"


@pytest.fixture
def repository() -> JsonPackageRepository:
    return JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")


@pytest.fixture
def client(repository: JsonPackageRepository) -> Iterator[TestClient]:
    app = create_app()
    app.dependency_overrides[get_package_repository] = lambda: repository
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
