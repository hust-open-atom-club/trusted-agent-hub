"""FastAPI dependencies for canonical Consumer API services."""

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from fastapi import Depends

from src.repositories.base import PackageRepository
from src.repositories.mock import JsonPackageRepository


ROOT = Path(__file__).resolve().parents[3]
MOCK = ROOT / "packages" / "schema" / "mock"


@lru_cache
def get_package_repository() -> PackageRepository:
    """Return the process-wide read-only package repository."""
    return JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")


RepositoryDependency = Annotated[
    PackageRepository, Depends(get_package_repository)
]
