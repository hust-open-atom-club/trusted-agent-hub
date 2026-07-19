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
from src.repositories.sqlalchemy import SqlAlchemyPackageRepository
from src.settings import Settings, clear_settings_cache, get_settings


@lru_cache
def get_package_repository() -> PackageRepository:
    """Return the process-wide configured package repository."""
    settings = get_settings()
    if settings.database_url is None:
        raise RuntimeError("DATABASE_URL environment variable is required. PostgreSQL must be running.")
    engine = get_runtime_engine(settings.database_url)
    return SqlAlchemyPackageRepository(create_session_factory(engine))


def clear_runtime_dependencies() -> None:
    """Clear dependency caches and dispose owned database resources."""
    get_package_repository.cache_clear()
    clear_settings_cache()
    dispose_runtime_engines()


@dataclass(frozen=True, slots=True)
class CurrentUser:
    """Authenticated user identity exposed to route handlers."""

    id: str
    role: str = "user"


BearerTokenVerifier = Callable[[str], CurrentUser]
_bearer_token_verifier: BearerTokenVerifier | None = None


class BearerTokenInvalid(Exception):
    """Raised by a bearer verifier when a presented token is invalid."""


def set_bearer_token_verifier(verifier: BearerTokenVerifier) -> None:
    """注入真实的 Bearer Token 验证函数（由 auth 模块在启动时调用）。

    替换默认的占位实现，使 JWT 认证生效。
    """
    global _bearer_token_verifier
    _bearer_token_verifier = verifier


def _authentication_required() -> ConsumerAPIError:
    return ConsumerAPIError(
        status_code=401,
        code="authentication_required",
        message="An authenticated user is required to write Consumer records.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _reject_unconfigured_bearer_token(_token: str) -> CurrentUser:
    """占位 verifier，当认证模块未安装时拒绝所有 token。"""
    raise BearerTokenInvalid("No bearer-token verifier is configured.")


def _default_verifier() -> BearerTokenVerifier:
    return _reject_unconfigured_bearer_token


_bearer_auth = HTTPBearer(auto_error=False, scheme_name="bearerAuth")


def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Security(_bearer_auth),
    ],
    x_user_id: Annotated[
        str | None,
        Header(alias="X-User-Id", include_in_schema=False),
    ] = None,
    settings: Settings = Depends(get_settings),
) -> CurrentUser:
    """Resolve a bearer identity or an explicitly enabled development header."""
    if credentials is not None:
        verifier = _bearer_token_verifier or _default_verifier()
        try:
            return verifier(credentials.credentials)
        except BearerTokenInvalid:
            raise _authentication_required() from None
    if settings.allow_insecure_user_header and x_user_id is not None:
        user_id = x_user_id.strip()
        if user_id:
            return CurrentUser(id=user_id, role="admin")
    raise _authentication_required()


RepositoryDependency = Annotated[
    PackageRepository, Depends(get_package_repository)
]

CurrentUserDependency = Annotated[CurrentUser, Depends(get_current_user)]
