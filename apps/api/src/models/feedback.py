"""Models for Consumer install reports, feedback, and trust levels."""

from enum import StrEnum

from pydantic import Field

from .common import Client, Page, StrictContractModel
from .packages import Grade


class FeedbackLevel(StrEnum):
    POSITIVE = "positive"
    NEUTRAL = "neutral"
    NEGATIVE = "negative"


class TrustLevelName(StrEnum):
    TRUSTED = "trusted"
    LOW_RISK = "low_risk"
    MEDIUM_RISK = "medium_risk"
    HIGH_RISK = "high_risk"
    UNTRUSTED = "untrusted"


class InstallReportRequest(StrictContractModel):
    package_name: str
    version: str
    client: Client
    event_id: str = Field(min_length=1, description="Client-generated unique idempotency key")
    install_path: str | None = Field(default=None, description="Omitted for anonymous installs")
    integrity_verified: bool = False


class InstallRecord(StrictContractModel):
    id: str
    package_name: str
    version: str
    version_id: str
    user_id: str | None = None
    client: Client
    event_id: str
    install_path: str | None = None
    integrity_verified: bool
    installed_at: str


class FeedbackRequest(StrictContractModel):
    level: FeedbackLevel
    comment: str | None = Field(default=None, max_length=1000)


class FeedbackRecord(StrictContractModel):
    id: str
    package_name: str
    level: FeedbackLevel
    comment: str | None = None
    created_at: str
    updated_at: str


class FeedbackPage(Page[FeedbackRecord]):
    level_counts: dict[FeedbackLevel, int]


class FeedbackListQuery(StrictContractModel):
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class NoQueryParameters(StrictContractModel):
    """Reject undeclared query parameters on parameterless routes."""


class TrustLevelResponse(StrictContractModel):
    version_id: str
    effective_grade: Grade
    level: TrustLevelName
    install_recommendation: str
