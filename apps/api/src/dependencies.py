"""FastAPI dependencies for canonical Consumer API services."""

from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import Depends, Header, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.database import (
    create_session_factory,
    dispose_runtime_engines,
    get_runtime_engine,
)
from src.errors import ConsumerAPIError
from src.repositories.base import PackageRepository
from src.repositories.mock import JsonPackageRepository
from src.repositories.sqlalchemy import SqlAlchemyPackageRepository
from src.settings import Settings, clear_settings_cache, get_settings


ROOT = Path(__file__).resolve().parents[3]
MOCK = ROOT / "packages" / "schema" / "mock"


@lru_cache
def get_package_repository() -> PackageRepository:
    """Return the process-wide configured package repository."""
    settings = get_settings()
    if settings.database_url is not None:
        engine = get_runtime_engine(settings.database_url)
        return SqlAlchemyPackageRepository(create_session_factory(engine))
    return JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")


def clear_runtime_dependencies() -> None:
    """Clear dependency caches and dispose owned database resources."""
    get_package_repository.cache_clear()
    clear_settings_cache()
    dispose_runtime_engines()


@dataclass(frozen=True, slots=True)
class CurrentUser:
    """Authenticated Consumer identity exposed to route handlers."""

    id: str


BearerTokenVerifier = Callable[[str], CurrentUser]


class BearerTokenInvalid(Exception):
    """Raised by a bearer verifier when a presented token is invalid."""


def _authentication_required() -> ConsumerAPIError:
    return ConsumerAPIError(
        status_code=401,
        code="authentication_required",
        message="An authenticated user is required to write Consumer records.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _reject_unconfigured_bearer_token(_token: str) -> CurrentUser:
    raise BearerTokenInvalid("No bearer-token verifier is configured.")


def get_bearer_token_verifier() -> BearerTokenVerifier:
    """Return the configured bearer-token verifier integration boundary."""
    return _reject_unconfigured_bearer_token


_bearer_auth = HTTPBearer(auto_error=False, scheme_name="bearerAuth")


def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Security(_bearer_auth),
    ],
    verifier: Annotated[
        BearerTokenVerifier,
        Depends(get_bearer_token_verifier),
    ],
    x_user_id: Annotated[
        str | None,
        Header(alias="X-User-Id", include_in_schema=False),
    ] = None,
    settings: Settings = Depends(get_settings),
) -> CurrentUser:
    """Resolve a bearer identity or an explicitly enabled development header."""
    if credentials is not None:
        try:
            return verifier(credentials.credentials)
        except BearerTokenInvalid:
            raise _authentication_required() from None
    if settings.allow_insecure_user_header and x_user_id is not None:
        user_id = x_user_id.strip()
        if user_id:
            return CurrentUser(id=user_id)
    raise _authentication_required()


RepositoryDependency = Annotated[
    PackageRepository, Depends(get_package_repository)
]

CurrentUserDependency = Annotated[CurrentUser, Depends(get_current_user)]
