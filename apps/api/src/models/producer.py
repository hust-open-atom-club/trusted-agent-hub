"""供给侧请求/响应 Pydantic 模型。"""

from __future__ import annotations

from pydantic import Field

from .common import PackageType, StrictContractModel
from .packages import (
    Author,
    Installation,
    Permissions,
    Source,
    TrustScore,
)


class CreatePackageRequest(StrictContractModel):
    """POST /packages 请求体。"""

    name: str = Field(description="能力包名称，全局唯一")
    type: PackageType = Field(description="能力包类型")
    description: str = Field(description="简短描述")
    license: str | None = None
    keywords: list[str] = Field(default_factory=list)
    category: str | None = None
    homepage: str | None = None
    icon_url: str | None = None
    author: Author | None = None
    permissions: Permissions | None = None
    installation: Installation | None = None
    source: Source | None = None
    compatibility: list[str] = Field(default_factory=list)


class CreateVersionRequest(StrictContractModel):
    """POST /packages/{id}/versions 请求体。"""

    version: str = Field(description="SemVer 版本号，如 1.0.0")
    repo_url: str | None = Field(default=None, description="GitHub 仓库 HTTPS URL")
    description: str | None = None
    installation: Installation | None = None
    source: Source | None = None


class SubmitResponse(StrictContractModel):
    """POST /versions/{id}/submit 响应。"""

    version_id: str
    status: str
    scan_id: str
    message: str = "扫描任务已启动"


class PackageResponse(StrictContractModel):
    """GET /packages/{id} 响应。"""

    id: str
    name: str
    type: PackageType
    description: str
    status: str
    latest_version: str | None = None
    versions_count: int = 0
    license: str | None = None
    keywords: list[str] = Field(default_factory=list)
    category: str | None = None
    author: Author | None = None
    created_at: str | None = None
    updated_at: str | None = None


class VersionResponse(StrictContractModel):
    """GET /versions/{id} 响应。"""

    id: str
    package_id: str
    version: str
    status: str
    source: Source | None = None
    description: str | None = None
    scan_summary: dict[str, object] | None = None
    trust_score: TrustScore | None = None
    review_conclusion: str | None = None
    submitted_at: str | None = None
    created_at: str | None = None


# ── 审核与发布模型 ────────────────────────────────────────


class ReviewRequest(StrictContractModel):
    """POST /versions/{id}/reviews 请求体。"""

    conclusion: str = Field(description='审核结论：approved | rejected | changes_requested')
    comment: str | None = Field(default=None, description='审核意见（驳回/要求修改时必填）')


class ReviewResponse(StrictContractModel):
    """审核/发布/下架 操作的响应体。"""

    version_id: str
    conclusion: str | None = None
    new_status: str
    message: str = '操作完成'


class AuditLogEntry(StrictContractModel):
    """GET /audit-logs 响应条目。"""

    id: str
    action: str
    target_type: str
    target_id: str
    operator_id: str
    operator_name: str | None = None
    timestamp: str
    detail: dict[str, object] | None = None
