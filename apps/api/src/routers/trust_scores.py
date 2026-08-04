"""Canonical published trust-score HTTP route."""

import logging
from typing import Annotated

from fastapi import APIRouter, Query

from src.dependencies import RepositoryDependency
from src.models.common import ErrorEnvelope, StrictContractModel
from src.models.packages import TrustScore
from src.services.errors import TrustScoreNotFoundError, VersionNotFoundError
from src.services.packages import PackageService

logger = logging.getLogger(__name__)


class NoQueryParameters(StrictContractModel):
    """Reject undeclared query parameters on the trust-score route."""


router = APIRouter(tags=["trust-scores"])


def _lazy_refresh_trust_score(version_id: str, repository) -> None:
    """读取前用最新平台信号惰性重算评分；任何失败都不影响读取。"""
    try:
        from src.database import create_session_factory, get_runtime_engine
        from src.repositories.producer_sqlalchemy import ProducerRepository
        from src.settings import get_settings
        from src.services.trust_refresh import TrustScoreRefreshService

        settings = get_settings()
        if not settings.database_url:
            return
        engine = get_runtime_engine(settings.database_url)
        producer_repo = ProducerRepository(create_session_factory(engine))
        TrustScoreRefreshService(
            producer_repo,
            consumer_repository=repository,
        ).refresh(version_id)
    except Exception:
        logger.exception("lazy trust-score refresh failed for %s", version_id)


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
    _lazy_refresh_trust_score(version_id, repository)
    try:
        return PackageService(repository).get_trust_score(version_id)
    except VersionNotFoundError as error:
        raise TrustScoreNotFoundError(version_id) from error
