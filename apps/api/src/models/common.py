"""Shared models for the Consumer API contract."""

from datetime import datetime
from enum import StrEnum
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator


class PackageType(StrEnum):
    SKILL = "skill"
    MCP_SERVER = "mcp_server"
    PLUGIN = "plugin"
    SUBAGENT = "subagent"
    COMMAND = "command"
    PROMPT = "prompt"


class StrictContractModel(BaseModel):
    """Base for repository contracts that reject undeclared fields."""

    model_config = ConfigDict(extra="forbid")


class SortField(StrEnum):
    UPDATED_AT = "updated_at"
    INSTALL_COUNT = "install_count"
    AVG_RATING = "avg_rating"
    NAME = "name"
    GRADE = "grade"


class SortOrder(StrEnum):
    ASC = "asc"
    DESC = "desc"


class PackageListQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    q: str | None = None
    type: PackageType | None = None
    client: str | None = None
    category: str | None = None
    tag: str | None = None
    min_grade: Literal["A", "B", "C", "D", "E"] | None = None
    min_score: float | None = Field(default=None, ge=0, le=100)
    max_score: float | None = Field(default=None, ge=0, le=100)
    updated_since: datetime | None = None
    status: Literal["published"] = "published"
    sort_by: SortField = SortField.UPDATED_AT
    order: SortOrder = SortOrder.DESC
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)

    @model_validator(mode="after")
    def _score_range_is_ordered(self) -> "PackageListQuery":
        if (
            self.min_score is not None
            and self.max_score is not None
            and self.min_score > self.max_score
        ):
            raise ValueError("min_score must not be greater than max_score")
        return self


class Owner(StrictContractModel):
    id: str
    display_name: str
    role: str
    username: str | None = None
    email: str | None = None


T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int
    total_pages: int


class HealthResponse(BaseModel):
    service: str
    version: str
    status: Literal["ok"] = "ok"


class ErrorBody(BaseModel):
    code: str
    message: str
    details: dict[str, object] = Field(default_factory=dict)


class ErrorEnvelope(BaseModel):
    error: ErrorBody
