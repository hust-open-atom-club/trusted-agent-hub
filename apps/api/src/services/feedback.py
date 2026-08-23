"""Consumer write-side services for installs, feedback, and trust levels."""

from datetime import datetime, timezone

from schema.constants import GRADE_TO_RECOMMENDATION, GRADE_TO_RISK_LEVEL
from src.errors import ConsumerAPIError
from src.models.feedback import (
    FeedbackListQuery,
    FeedbackPage,
    FeedbackRecord,
    FeedbackRequest,
    InstallRecord,
    InstallReportRequest,
    TrustLevelResponse,
)
from src.repositories.base import (
    PackageRepository,
    is_consumer_persistence_repository,
)

from .packages import PackageService
from .errors import VersionNotFoundError


class FeedbackService:
    """Apply public visibility and persistence rules for Consumer writes."""

    def __init__(self, repository: PackageRepository) -> None:
        self.repository = repository
        self.packages = PackageService(repository)

    def record_install(
        self,
        request: InstallReportRequest,
        user_id: str | None,
    ) -> tuple[InstallRecord, bool]:
        version = self.packages.get_public_version(
            request.package_name,
            request.version,
        )
        if not is_consumer_persistence_repository(self.repository):
            raise _persistence_unavailable()
        # Anonymous users must not upload local install path
        install_path = request.install_path if user_id else None
        payload, created = self.repository.record_install(
            package_name=request.package_name,
            version=version.version,
            version_id=version.id,
            user_id=user_id,
            client=request.client,
            event_id=request.event_id,
            install_path=install_path,
            integrity_verified=request.integrity_verified,
        )
        return InstallRecord.model_validate(payload), created

    def upsert_feedback(
        self,
        name: str,
        request: FeedbackRequest,
        user_id: str,
    ) -> tuple[FeedbackRecord, bool]:
        package = self.packages.get_public_package(name)
        if not is_consumer_persistence_repository(self.repository):
            raise _persistence_unavailable()
        payload, created = self.repository.upsert_feedback(
            package_name=package.name,
            package_id=package.id,
            user_id=user_id,
            level=request.level.value,
            comment=request.comment,
        )
        return FeedbackRecord.model_validate(payload), created

    def list_feedback(
        self,
        name: str,
        query: FeedbackListQuery,
    ) -> FeedbackPage:
        package = self.packages.get_public_package(name)
        if not is_consumer_persistence_repository(self.repository):
            raise _persistence_unavailable()
        payload = self.repository.list_feedback(
            package_name=package.name,
            package_id=package.id,
            page=query.page,
            page_size=query.page_size,
        )
        return FeedbackPage.model_validate(payload)

    def get_trust_level(self, version_id: str) -> TrustLevelResponse:
        try:
            version = self.packages.get_public_version_by_id(version_id)
        except VersionNotFoundError as error:
            raise _trust_level_not_found(version_id) from error
        if not is_consumer_persistence_repository(self.repository):
            raise _persistence_unavailable()

        payload = self.repository.get_trust_level(version_id)
        if payload is not None:
            return TrustLevelResponse.model_validate(payload)

        # No trust_level row yet — compute from effective_grade and backfill
        effective = version.effective_grade
        if effective is None and version.trust_score is not None:
            rs = version.trust_score.risk_summary
            if rs is not None:
                effective = rs.grade

        if effective is None:
            raise _trust_level_not_found(version_id)

        level = GRADE_TO_RISK_LEVEL.get(str(effective), "medium_risk")
        recommendation = GRADE_TO_RECOMMENDATION.get(str(effective), "caution")
        top_risks: list[str] = []
        explanation: str | None = None
        model_version = "0.3.0"
        if version.trust_score is not None:
            rs = version.trust_score.risk_summary
            if rs is not None:
                top_risks = rs.top_risks
            if version.trust_score.explanations:
                explanation = "; ".join(
                    e.message for e in version.trust_score.explanations
                )
            model_version = version.trust_score.model_version or model_version

        # Backfill the trust_levels row for future requests
        self.repository.upsert_trust_level(
            version_id=version_id,
            level=level,
            install_recommendation=recommendation,
            top_risks=top_risks,
            explanation=explanation,
            model_version=model_version,
        )

        return TrustLevelResponse(
            version_id=version_id,
            level=level,
            install_recommendation=recommendation,
            top_risks=top_risks,
            explanation=explanation,
            model_version=model_version,
            calculated_at=datetime.now(timezone.utc).isoformat(),
        )


def _persistence_unavailable() -> ConsumerAPIError:
    return ConsumerAPIError(
        status_code=503,
        code="persistence_unavailable",
        message="Consumer persistence is not configured for this repository.",
    )


def _trust_level_not_found(version_id: str) -> ConsumerAPIError:
    return ConsumerAPIError(
        status_code=404,
        code="trust_level_not_found",
        message=f"Trust level for version '{version_id}' was not found.",
    )
