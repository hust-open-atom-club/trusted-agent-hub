"""供给侧 HTTP 路由 — 包提交、版本管理与审核流转。

端点（均挂载在 /api/v0/producer 下）:
    POST /packages                    — 注册新能力包
    POST /packages/{id}/versions      — 创建新版本
    POST /versions/{id}/submit        — 提交审核（触发扫描）
    GET  /packages/{id}               — 包详情
    GET  /versions/{id}               — 版本详情（含扫描报告）
"""

from __future__ import annotations

from typing import Callable

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query

from src.database import (
    create_session_factory,
    get_runtime_engine,
)
from src.models.common import ErrorEnvelope
from src.models.producer import (
    CreatePackageRequest,
    CreateVersionRequest,
    PackageResponse,
    SubmitResponse,
    VersionResponse,
)
from src.repositories.producer_sqlalchemy import ProducerRepository
from src.services.producer import ProducerService, ProducerServiceError
from src.settings import get_settings

# ── 延迟导入 trust 模块的 _run_scan_task ──────────────────
# 避免循环导入，在 submit 端点内 import

router = APIRouter(prefix="/api/v0/producer", tags=["producer"])


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


# ── POST /packages ────────────────────────────────────────

@router.post(
    "/packages",
    response_model=PackageResponse,
    status_code=201,
    responses={400: {"model": ErrorEnvelope}},
)
def create_package(
    body: CreatePackageRequest,
) -> PackageResponse:
    """注册一个新能力包。

    提交元数据（名称、类型、描述、权限声明等），
    包状态初始为 draft。
    """
    repo = _get_producer_repository()
    service = ProducerService(repo)
    try:
        return service.create_package(body)
    except ProducerServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── POST /packages/{package_id}/versions ──────────────────

@router.post(
    "/packages/{package_id}/versions",
    status_code=201,
    responses={400: {"model": ErrorEnvelope}, 404: {"model": ErrorEnvelope}},
)
def create_version(
    package_id: str,
    body: CreateVersionRequest,
) -> dict[str, object]:
    """为指定包创建一个新版本。

    支持填写 GitHub 仓库 URL，版本号需符合 SemVer 规范。
    """
    repo = _get_producer_repository()
    service = ProducerService(repo)
    try:
        return service.create_version(package_id, body)
    except ProducerServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── POST /versions/{version_id}/submit ────────────────────

@router.post(
    "/versions/{version_id}/submit",
    response_model=SubmitResponse,
    responses={400: {"model": ErrorEnvelope}, 404: {"model": ErrorEnvelope}},
)
def submit_version(
    version_id: str,
    background_tasks: BackgroundTasks,
) -> SubmitResponse:
    """提交审核：状态 draft → submitted → scanning，自动触发安全扫描。

    扫描在后台执行（clone → 扫描 → 评分），完成后自动回调更新
    版本状态为 pending_review。
    """
    repo = _get_producer_repository()
    service = ProducerService(repo)
    try:
        repo_url, scan_id, next_status = service.submit_version(version_id)
    except ProducerServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # 对于 draft → submitted 的两跳路径，router 继续置为 scanning；
    # 对于 resubmitted / changes_requested / error 已在 service 层直达 scanning，跳过。
    if next_status != "scanning":
        repo.update_version_status(version_id, "scanning")

    # 构建回调闭包
    def on_scan_done(
        sid: str, report: dict[str, object] | None, error: str | None
    ) -> None:
        if error is not None:
            service.handle_scan_error(version_id, error)
        elif report is not None:
            service.handle_scan_complete(version_id, report)

    # 延迟导入 _run_scan_task 并注入回调
    from src.routers.trust import _run_scan_task

    background_tasks.add_task(
        _run_scan_task,
        scan_id,
        repo_url,
        is_local=False,
        on_complete=on_scan_done,
    )

    return SubmitResponse(
        version_id=version_id,
        status="scanning",
        scan_id=scan_id,
    )


# ── GET /packages/{package_id} ────────────────────────────

@router.get(
    "/packages/{package_id}",
    responses={404: {"model": ErrorEnvelope}},
)
def get_package(package_id: str) -> dict[str, object]:
    """获取包详情，含版本列表。"""
    repo = _get_producer_repository()
    pkg = repo.get_package(package_id)
    if pkg is None:
        raise HTTPException(status_code=404, detail=f"包 {package_id} 不存在")

    versions = repo.list_package_versions(package_id)
    pkg["versions"] = versions
    return pkg


# ── GET /versions/{version_id} ────────────────────────────

@router.get(
    "/versions/{version_id}",
    responses={404: {"model": ErrorEnvelope}},
)
def get_version(version_id: str) -> dict[str, object]:
    """获取版本详情，含扫描报告摘要和信任评分。"""
    repo = _get_producer_repository()
    service = ProducerService(repo)
    detail = service.get_version_detail(version_id)
    if detail is None:
        raise HTTPException(
            status_code=404, detail=f"版本 {version_id} 不存在"
        )
    return detail


# ── GET /versions ──────────────────────────────────────────

@router.get(
    "/versions",
    responses={400: {"model": ErrorEnvelope}},
)
def list_versions(
    submitter_id: str | None = Query(default=None, description="提交者用户 ID"),
    status: str | None = Query(default=None, description="按状态筛选，逗号分隔多个"),
    grade: str | None = Query(default=None, description="按风险等级筛选（A/B/C/D/E/F）"),
) -> list[dict[str, object]]:
    """获取版本列表（按提交时间倒序）。

    支持两种查询模式：
    - 按提交者筛选：?submitter_id=xxx
    - 按状态筛选：?status=pending_review（审核员用）
    - 组合筛选：?status=pending_review&grade=D
    """
    repo = _get_producer_repository()
    service = ProducerService(repo)

    if submitter_id is not None:
        return service.list_my_versions(submitter_id)

    if status is not None:
        return service.list_versions_by_status(
            status=status,
            grade=grade,
        )

    return service.list_versions_by_status()
