"""Canonical published package-statistics HTTP route."""

from typing import Annotated

from fastapi import APIRouter, Query

from src.dependencies import RepositoryDependency
from src.models.common import ErrorEnvelope, StrictContractModel
from src.models.packages import PackageStats
from src.services.packages import PackageService


class NoQueryParameters(StrictContractModel):
    """Reject undeclared query parameters on the statistics route."""


router = APIRouter(tags=["stats"])


@router.get(
    "/stats/packages/{name}",
    response_model=PackageStats,
    responses={404: {"model": ErrorEnvelope}},
)
def get_package_stats(
    name: str,
    query: Annotated[NoQueryParameters, Query()],
    repository: RepositoryDependency,
) -> PackageStats:
    return PackageService(repository).get_stats(name)
