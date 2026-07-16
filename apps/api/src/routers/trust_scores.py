"""Canonical published trust-score HTTP route."""

from typing import Annotated

from fastapi import APIRouter, Query

from src.dependencies import RepositoryDependency
from src.models.common import ErrorEnvelope, StrictContractModel
from src.models.packages import TrustScore
from src.services.errors import TrustScoreNotFoundError, VersionNotFoundError
from src.services.packages import PackageService


class NoQueryParameters(StrictContractModel):
    """Reject undeclared query parameters on the trust-score route."""


router = APIRouter(tags=["trust-scores"])


@router.get(
    "/versions/{version_id}/trust-score",
    response_model=TrustScore,
    responses={404: {"model": ErrorEnvelope}},
)
def get_trust_score(
    version_id: str,
    query: Annotated[NoQueryParameters, Query()],
    repository: RepositoryDependency,
) -> TrustScore:
    try:
        return PackageService(repository).get_trust_score(version_id)
    except VersionNotFoundError as error:
        raise TrustScoreNotFoundError(version_id) from error
