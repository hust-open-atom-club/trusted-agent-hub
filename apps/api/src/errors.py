"""Canonical errors exposed by the Consumer API."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.repositories.base import RepositoryDataError
from src.services.errors import ServiceNotFoundError


class ConsumerAPIError(Exception):
    """An error returned to Consumer API clients."""

    def __init__(
        self,
        *,
        status_code: int,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = {} if details is None else details


def install_error_handlers(app: FastAPI) -> None:
    """Install handlers for canonical Consumer API errors."""

    @app.exception_handler(ServiceNotFoundError)
    async def service_not_found_error_handler(
        _request: Request, error: ServiceNotFoundError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                }
            },
        )

    @app.exception_handler(ConsumerAPIError)
    async def consumer_api_error_handler(
        _request: Request, error: ConsumerAPIError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=error.status_code,
            content={
                "error": {
                    "code": error.code,
                    "message": error.message,
                    "details": error.details,
                }
            },
        )

    @app.exception_handler(RepositoryDataError)
    async def repository_data_error_handler(
        _request: Request, error: RepositoryDataError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "repository_data_invalid",
                    "message": "The package repository contains invalid data.",
                    "details": {"reason": str(error)},
                }
            },
        )
