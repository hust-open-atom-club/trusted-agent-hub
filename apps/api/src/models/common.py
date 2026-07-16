"""Shared models for the Consumer API contract."""

from enum import StrEnum
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field


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
    TRUST_SCORE = "trust_score"
    UPDATED_AT = "updated_at"
    INSTALL_COUNT = "install_count"
    AVG_RATING = "avg_rating"
    NAME = "name"


class SortOrder(StrEnum):
    ASC = "asc"
    DESC = "desc"


class PackageListQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    q: str | None = None
    type: PackageType | None = None
    client: str | None = None
    category: str | None = None
    status: Literal["published"] = "published"
    sort_by: SortField = SortField.TRUST_SCORE
    order: SortOrder = SortOrder.DESC
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class Owner(StrictContractModel):
    id: str
    username: str
    display_name: str
    role: str


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
