"""审核流转 HTTP 路由 — 审核员提交结论、管理员发布/下架、审计日志查询。

端点（均挂载在 /api/v0/producer 下）:
    POST /versions/{id}/reviews      — 审核员提交审核结论
    POST /versions/{id}/publish      — 管理员发布上线
    POST /versions/{id}/yank         — 管理员下架
    GET  /audit-logs                 — 审计日志查询
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from src.auth import require_role
from src.dependencies import CurrentUser
from src.database import create_session_factory, get_runtime_engine
from src.models.common import ErrorEnvelope
from src.models.producer import (
    AuditLogEntry,
    ReviewRequest,
    ReviewResponse,
)
from src.repositories.producer_sqlalchemy import ProducerRepository
from src.services.producer import ProducerService, ProducerServiceError
from src.settings import get_settings

router = APIRouter(prefix="/api/v0/producer", tags=["review"])


def _get_producer_repository() -> ProducerRepository:
    """构建供给侧仓库（复用消费侧的数据库引擎）。"""
    settings = get_settings()
    if settings.database_url is None:
        raise HTTPException(
            status_code=503,
            detail="DATABASE_URL 未配置，数据库不可用",
        )
    engine = get_runtime_engine(settings.database_url)
    return ProducerRepository(create_session_factory(engine))


# ── POST /versions/{version_id}/reviews ───────────────────

@router.post(
    "/versions/{version_id}/reviews",
    response_model=ReviewResponse,
    status_code=201,
    responses={400: {"model": ErrorEnvelope}, 404: {"model": ErrorEnvelope}},
)
def submit_review(
    version_id: str,
    body: ReviewRequest,
    _user: CurrentUser = Depends(require_role("reviewer")),
) -> ReviewResponse:
    """审核员对指定版本提交审核结论。

    conclusion: approved | rejected | changes_requested
    """
    repo = _get_producer_repository()
    service = ProducerService(repo)
    try:
        return service.review_version(
            version_id=version_id,
            conclusion=body.conclusion,
            comment=body.comment,
            reviewer_id=_user.id,
        )
    except ProducerServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── GET /versions/{version_id}/reviews ────────────────────

@router.get(
    "/versions/{version_id}/reviews",
)
def list_reviews(version_id: str):
    """获取某个版本的全部审核历史记录（按时间倒序）。"""
    repo = _get_producer_repository()
    return repo.list_review_records(version_id)


# ── POST /versions/{version_id}/publish ───────────────────

@router.post(
    "/versions/{version_id}/publish",
    response_model=ReviewResponse,
    status_code=200,
    responses={400: {"model": ErrorEnvelope}, 404: {"model": ErrorEnvelope}},
)
def publish_version(
    version_id: str,
    _user: CurrentUser = Depends(require_role("admin")),
) -> ReviewResponse:
    """管理员将审核通过的版本正式发布上线。

    状态：approved → published
    """
    repo = _get_producer_repository()
    service = ProducerService(repo)
    try:
        return service.publish_version(
            version_id=version_id,
            operator_id=_user.id,
        )
    except ProducerServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── POST /versions/{version_id}/yank ──────────────────────

@router.post(
    "/versions/{version_id}/yank",
    response_model=ReviewResponse,
    status_code=200,
    responses={400: {"model": ErrorEnvelope}, 404: {"model": ErrorEnvelope}},
)
def yank_version(
    version_id: str,
    _user: CurrentUser = Depends(require_role("admin")),
    reason: str = Query(default="", description="下架原因"),
) -> ReviewResponse:
    """管理员下架已发布的版本。

    状态：published → yanked
    """
    repo = _get_producer_repository()
    service = ProducerService(repo)
    try:
        return service.yank_version(
            version_id=version_id,
            operator_id=_user.id,
            reason=reason if reason else None,
        )
    except ProducerServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── GET /audit-logs ───────────────────────────────────────

@router.get(
    "/audit-logs",
    response_model=list[AuditLogEntry],
)
def list_audit_logs(
    target_type: str | None = Query(default=None, description="目标类型：package / version"),
    target_id: str | None = Query(default=None, description="目标 ID"),
    action: str | None = Query(default=None, description="操作类型"),
    start_date: str | None = Query(default=None, description="开始日期（ISO 格式，如 2026-07-01T00:00:00）"),
    end_date: str | None = Query(default=None, description="结束日期（ISO 格式，如 2026-07-31T23:59:59）"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[AuditLogEntry]:
    """查询审计日志，支持按目标类型/目标ID/操作类型/时间范围筛选。"""
    repo = _get_producer_repository()
    rows = repo.list_audit_logs(
        target_type=target_type,
        target_id=target_id,
        action=action,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset,
    )
    return rows
