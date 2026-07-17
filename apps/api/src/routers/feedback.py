"""Consumer install, feedback, and trust-level HTTP routes."""

from typing import Annotated

from fastapi import APIRouter, Query, Response, status

from src.dependencies import CurrentUserDependency, RepositoryDependency
from src.models.common import ErrorEnvelope
from src.models.feedback import (
    FeedbackListQuery,
    FeedbackPage,
    FeedbackRecord,
    FeedbackRequest,
    InstallRecord,
    InstallReportRequest,
    NoQueryParameters,
    TrustLevelResponse,
)
from src.services.feedback import FeedbackService


router = APIRouter(tags=["feedback"])


@router.post(
    "/installs",
    response_model=InstallRecord,
    status_code=status.HTTP_201_CREATED,
    responses={
        200: {"model": InstallRecord, "description": "Existing install record"},
        401: {"model": ErrorEnvelope},
        404: {"model": ErrorEnvelope},
        503: {"model": ErrorEnvelope},
    },
)
def record_install(
    request: InstallReportRequest,
    response: Response,
    query: Annotated[NoQueryParameters, Query()],
    repository: RepositoryDependency,
    current_user: CurrentUserDependency,
) -> InstallRecord:
    record, created = FeedbackService(repository).record_install(
        request,
        current_user.id,
    )
    if not created:
        response.status_code = status.HTTP_200_OK
    return record


@router.post(
    "/packages/{name}/feedback",
    response_model=FeedbackRecord,
    status_code=status.HTTP_201_CREATED,
    responses={
        200: {"model": FeedbackRecord, "description": "Updated feedback"},
        401: {"model": ErrorEnvelope},
        404: {"model": ErrorEnvelope},
        503: {"model": ErrorEnvelope},
    },
)
def upsert_feedback(
    name: str,
    request: FeedbackRequest,
    response: Response,
    query: Annotated[NoQueryParameters, Query()],
    repository: RepositoryDependency,
    current_user: CurrentUserDependency,
) -> FeedbackRecord:
    record, created = FeedbackService(repository).upsert_feedback(
        name,
        request,
        current_user.id,
    )
    if not created:
        response.status_code = status.HTTP_200_OK
    return record


@router.get(
    "/packages/{name}/feedback",
    response_model=FeedbackPage,
    responses={404: {"model": ErrorEnvelope}, 503: {"model": ErrorEnvelope}},
)
def list_feedback(
    name: str,
    query: Annotated[FeedbackListQuery, Query()],
    repository: RepositoryDependency,
) -> FeedbackPage:
    return FeedbackService(repository).list_feedback(name, query)


@router.get(
    "/versions/{version_id}/trust-level",
    response_model=TrustLevelResponse,
    responses={404: {"model": ErrorEnvelope}, 503: {"model": ErrorEnvelope}},
)
def get_trust_level(
    version_id: str,
    query: Annotated[NoQueryParameters, Query()],
    repository: RepositoryDependency,
) -> TrustLevelResponse:
    return FeedbackService(repository).get_trust_level(version_id)
