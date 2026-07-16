"""Canonical public package and version HTTP routes."""

from typing import Annotated

from fastapi import APIRouter, Query

from src.dependencies import RepositoryDependency
from src.models.common import ErrorEnvelope, PackageListQuery
from src.models.packages import (
    PackageDetail,
    PackagePage,
    VersionDetail,
    VersionSummary,
)
from src.services.packages import PackageService


router = APIRouter(tags=["packages"])


@router.get("/packages", response_model=PackagePage)
def list_packages(
    query: Annotated[PackageListQuery, Query()],
    repository: RepositoryDependency,
) -> PackagePage:
    return PackageService(repository).list_packages(query)


@router.get(
    "/packages/{name}",
    response_model=PackageDetail,
    responses={404: {"model": ErrorEnvelope}},
)
def get_package(
    name: str,
    repository: RepositoryDependency,
) -> PackageDetail:
    return PackageService(repository).get_package_detail(name)


@router.get(
    "/packages/{name}/versions",
    response_model=list[VersionSummary],
    responses={404: {"model": ErrorEnvelope}},
)
def list_package_versions(
    name: str,
    repository: RepositoryDependency,
) -> list[VersionSummary]:
    return PackageService(repository).list_public_versions(name)


@router.get(
    "/packages/{name}/versions/{version}",
    response_model=VersionDetail,
    responses={404: {"model": ErrorEnvelope}},
)
def get_package_version(
    name: str,
    version: str,
    repository: RepositoryDependency,
) -> VersionDetail:
    return PackageService(repository).get_public_version(name, version)
