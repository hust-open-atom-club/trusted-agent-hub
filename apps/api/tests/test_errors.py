"""Tests for the canonical Consumer API error envelope."""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.errors import ConsumerAPIError, install_error_handlers
from src.repositories.base import RepositoryDataError
from src.services.errors import PackageNotFoundError


def test_consumer_api_error_uses_canonical_envelope() -> None:
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/boom")
    def boom() -> None:
        raise ConsumerAPIError(
            status_code=404,
            code="package_not_found",
            message="Package 'missing' was not found.",
        )

    response = TestClient(app).get("/boom")

    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "code": "package_not_found",
            "message": "Package 'missing' was not found.",
            "details": {},
        }
    }


def test_repository_data_error_uses_controlled_500() -> None:
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/broken-data")
    def broken_data() -> None:
        raise RepositoryDataError("latest_version relationship is invalid")

    response = TestClient(app, raise_server_exceptions=False).get("/broken-data")

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "repository_data_invalid",
            "message": "The package repository contains invalid data.",
            "details": {"reason": "latest_version relationship is invalid"},
        }
    }


def test_service_not_found_error_uses_canonical_404_envelope() -> None:
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/missing-package")
    def missing_package() -> None:
        raise PackageNotFoundError("missing")

    response = TestClient(app).get("/missing-package")

    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "code": "package_not_found",
            "message": "Package 'missing' was not found.",
            "details": {},
        }
    }
