"""供给侧 HTTP 路由 — 包提交、版本管理与审核流转。

端点（均挂载在 /api/v0/producer 下）:
    POST /packages                    — 注册新能力包
    POST /packages/{id}/versions      — 创建新版本
    POST /versions/{id}/submit        — 提交审核（触发扫描）
    GET  /packages/{id}               — 包详情
    GET  /versions/{id}               — 版本详情（含扫描报告）
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import Field

from src.database import (
    create_session_factory,
    get_runtime_engine,
)
from src.auth import require_role, verify_resource_access
from src.dependencies import CurrentUser
from src.models.common import ErrorEnvelope, StrictContractModel
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
    _user: CurrentUser = Depends(require_role("submitter")),
) -> PackageResponse:
    """注册一个新能力包（需登录，仅 submitter 及以上角色）。

    提交元数据（名称、类型、描述、权限声明等），
    包状态初始为 draft。
    """
    repo = _get_producer_repository()
    service = ProducerService(repo)
    try:
        return service.create_package(body, submitter_id=_user.id)
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
    _user: CurrentUser = Depends(require_role("submitter")),
) -> dict[str, object]:
    """为指定包创建一个新版本（需登录，仅 submitter 及以上角色）。

    仅包所有者（或 admin/reviewer）可创建版本。
    支持填写 GitHub 仓库 URL，版本号需符合 SemVer 规范。
    """
    repo = _get_producer_repository()
    pkg = repo.get_package(package_id)
    if pkg is None:
        raise HTTPException(status_code=404, detail=f"包 {package_id} 不存在")
    verify_resource_access(_user, pkg.get("submitter_id", ""))

    service = ProducerService(repo)
    try:
        return service.create_version(package_id, body, submitter_id=_user.id)
    except ProducerServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── POST /versions/{version_id}/submit ────────────────────


class SubmitVersionRequest(StrictContractModel):
    """POST /versions/{id}/submit 可选请求体。"""
    initial_scan_id: str | None = Field(
        default=None,
        description='初次扫描的 scan_id。若提供且扫描已完成，则复用其结果，不再重新 clone+scan',
    )


@router.post(
    "/versions/{version_id}/submit",
    response_model=SubmitResponse,
    responses={400: {"model": ErrorEnvelope}, 404: {"model": ErrorEnvelope}},
)
def submit_version(
    version_id: str,
    background_tasks: BackgroundTasks,
    body: SubmitVersionRequest | None = None,
    _user: CurrentUser = Depends(require_role("submitter")),
) -> SubmitResponse:
    """提交审核（需登录）：状态变更 → scanning，自动触发安全扫描。
    扫描在后台执行，完成后自动回调更新版本状态为 pending_review。
    若传入 initial_scan_id 且对应扫描已完成，直接复用结果跳过重复扫描。

    仅版本所属包的提交者（或 admin/reviewer）可提交审核。
    """
    repo = _get_producer_repository()
    version = repo.get_version(version_id)
    if version is None:
        raise HTTPException(status_code=404, detail=f"版本 {version_id} 不存在")
    pkg_id = version.get("package_id")
    if pkg_id:
        pkg = repo.get_package(str(pkg_id))
        if pkg:
            verify_resource_access(_user, pkg.get("submitter_id", ""))

    service = ProducerService(repo)
    try:
        repo_url, scan_id, next_status = service.submit_version(version_id, user_id=_user.id)
    except ProducerServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

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

    # ── 检查是否可以复用初始扫描结果 ──
    initial_sid = body.initial_scan_id if body else None
    if initial_sid:
        from src.routers.trust import _scans
        initial_info = _scans.get(initial_sid)
        if initial_info and initial_info.get("status") == "complete":
            full_report = initial_info.get("full_report")
            if full_report:
                # 创建新的 service 实例（避免闭包引用问题）
                _repo = _get_producer_repository()
                _svc = ProducerService(_repo)
                _svc.handle_scan_complete(version_id, full_report)
                return SubmitResponse(
                    version_id=version_id,
                    status="pending_review",
                    scan_id=initial_sid,
                    message="复用初次扫描结果，已跳过重复扫描",
                )

    # 否则正常启动后台扫描
    from src.routers.trust import _run_scan_task, _scans, _SCAN_TTL_SECONDS
    import time as _time

    _scans[scan_id] = {
        "status": "pending",
        "package_name": None,
        "created_at": version.get("submitted_at") or datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
        "full_report": None,
        "summary": None,
        "trust_score": None,
        "error": None,
        "expires_at": _time.time() + _SCAN_TTL_SECONDS,
        "user_id": _user.id,
    }

    background_tasks.add_task(
        _run_scan_task,
        scan_id,
        repo_url,
        on_complete=on_scan_done,
    )

    return SubmitResponse(
        version_id=version_id,
        status="scanning",
        scan_id=scan_id,
    )


# ── GET /packages ─────────────────────────────────────────

@router.get(
    "/packages",
    responses={400: {"model": ErrorEnvelope}},
)
def list_packages(
    limit: int = Query(default=200, ge=1, le=500, description="每页数量"),
    offset: int = Query(default=0, ge=0, description="偏移量"),
    _user: CurrentUser = Depends(require_role("admin")),
) -> list[dict[str, object]]:
    """列出所有能力包（不限状态，仅 admin 可查看）。"""
    repo = _get_producer_repository()
    service = ProducerService(repo)
    return service.list_all_packages(limit=limit, offset=offset)


# ── GET /packages/{package_id} ────────────────────────────

@router.get(
    "/packages/{package_id}",
    responses={404: {"model": ErrorEnvelope}},
)
def get_package(
    package_id: str,
    _user: CurrentUser = Depends(require_role("submitter")),
) -> dict[str, object]:
    """获取包详情，含版本列表。仅所有者（submitter）或 reviewer/admin 可访问。"""
    repo = _get_producer_repository()
    pkg = repo.get_package(package_id)
    if pkg is None:
        raise HTTPException(status_code=404, detail=f"包 {package_id} 不存在")

    verify_resource_access(_user, pkg.get("submitter_id", ""))

    versions = repo.list_package_versions(package_id)
    pkg["versions"] = versions
    return pkg


# ── GET /versions/{version_id}/diff ────────────────────────

@router.get(
    "/versions/{version_id}/diff",
    responses={400: {"model": ErrorEnvelope}, 404: {"model": ErrorEnvelope}},
)
def diff_version(
    version_id: str,
    base: str | None = Query(default=None, description="基准版本 ID，不传则对比同包的上一版本"),
    _user: CurrentUser = Depends(require_role("reviewer")),
) -> dict[str, object]:
    """对比两个版本的元数据差异。

    默认对比同包中最近的前一个版本，
    也可通过 ?base={version_id} 指定基准版本。

    返回 current 和 base 的版本信息（含 source_url）及 diff 差异详情。
    """
    repo = _get_producer_repository()
    service = ProducerService(repo)
    try:
        return service.diff_versions(version_id, base_version_id=base)
    except ProducerServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

@router.get(
    "/versions/{version_id}",
    responses={404: {"model": ErrorEnvelope}},
)
def get_version(
    version_id: str,
    _user: CurrentUser = Depends(require_role("submitter")),
) -> dict[str, object]:
    """获取版本详情，含扫描报告摘要和信任评分。仅所有者或 reviewer/admin 可访问。"""
    repo = _get_producer_repository()
    service = ProducerService(repo)
    detail = service.get_version_detail(version_id)
    if detail is None:
        raise HTTPException(
            status_code=404, detail=f"版本 {version_id} 不存在"
        )
    pkg_id = detail.get("package_id")
    if pkg_id:
        pkg = repo.get_package(str(pkg_id))
        if pkg:
            verify_resource_access(_user, pkg.get("submitter_id", ""))
    return detail


# ── GET /versions ──────────────────────────────────────────

@router.get(
    "/versions",
    responses={400: {"model": ErrorEnvelope}},
)
def list_versions(
    submitter_id: str | None = Query(default=None, description="提交者用户 ID"),
    status: str | None = Query(default=None, description="按状态筛选，逗号分隔多个"),
    grade: str | None = Query(default=None, description="按风险等级筛选（A/B/C/D/E）"),
    since: str | None = Query(default=None, description="提交时间起始（ISO 格式）"),
    until: str | None = Query(default=None, description="提交时间截止（ISO 格式）"),
    limit: int = Query(default=50, ge=1, le=200, description="每页数量"),
    offset: int = Query(default=0, ge=0, description="偏移量"),
    _user: CurrentUser = Depends(require_role("submitter")),
) -> list[dict[str, object]]:
    """获取版本列表（按提交时间倒序）。

    支持两种查询模式：
    - 按提交者筛选：?submitter_id=xxx
    - 按状态筛选：?status=pending_review（审核员用）
    - 按时间范围筛选：?since=...&until=...
    - 组合筛选：?status=pending_review&grade=D
    """
    repo = _get_producer_repository()
    service = ProducerService(repo)

    # 惰性清理：顺带删除 rejected/error 版本遗留的安装产物
    try:
        service.cleanup_orphan_artifacts()
    except Exception:
        pass

    if submitter_id is not None:
        from schema.constants import UserRole
        if _user.role != UserRole.ADMIN.value and _user.role != UserRole.REVIEWER.value:
            submitter_id = _user.id
        return service.list_my_versions(submitter_id, limit=limit, offset=offset)

    if status is not None or since is not None or until is not None:
        return service.list_versions_by_status(
            status=status,
            grade=grade,
            since=since,
            until=until,
        )

    return service.list_versions_by_status()


# ── PATCH /versions/{version_id}/grade ──────────────────────

class GradeOverrideRequest(StrictContractModel):
    grade: str | None = Field(default=None, description="手动评级: A/B/C/D/E, 或 null 恢复自动")
    reason: str = Field(..., min_length=1, description="修改理由（必填）")


@router.patch(
    "/versions/{version_id}/grade",
    responses={400: {"model": ErrorEnvelope}, 404: {"model": ErrorEnvelope}},
)
def override_grade(
    version_id: str,
    body: GradeOverrideRequest,
    _user: CurrentUser = Depends(require_role("reviewer")),
) -> dict[str, object]:
    """手动覆盖 / 修改 / 清除评级（admin 和 reviewer 均可操作）。"""
    repo = _get_producer_repository()
    service = ProducerService(repo)
    try:
        return service.set_manual_grade(
            version_id=version_id,
            grade=body.grade,
            reason=body.reason,
            operator_id=_user.id,
        )
    except ProducerServiceError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── GET /versions/{version_id}/grade-history ─────────────────

@router.get(
    "/versions/{version_id}/grade-history",
    responses={404: {"model": ErrorEnvelope}},
)
def get_grade_history(
    version_id: str,
    _user: CurrentUser = Depends(require_role("reviewer")),
) -> list[dict[str, object]]:
    """查询手动评级修改历史（从 audit_logs 读取）。"""
    repo = _get_producer_repository()
    logs = repo.list_audit_logs(
        target_type="version",
        target_id=version_id,
        action="grade_override",
    )
    return [
        {
            "grade": log.get("detail", {}).get("new_manual_grade") if isinstance(log.get("detail"), dict) else None,
            "previous_grade": log.get("detail", {}).get("previous_manual_grade") if isinstance(log.get("detail"), dict) else None,
            "auto_grade": log.get("detail", {}).get("auto_grade") if isinstance(log.get("detail"), dict) else None,
            "operator_id": log.get("operator_id"),
            "reason": log.get("detail", {}).get("reason") if isinstance(log.get("detail"), dict) else None,
            "timestamp": log.get("timestamp"),
        }
        for log in logs
    ]


# ── DELETE /packages/{package_id} ──────────────────────────

@router.delete(
    "/packages/{package_id}",
    status_code=204,
    responses={403: {"model": ErrorEnvelope}, 404: {"model": ErrorEnvelope}},
)
def delete_package(
    package_id: str,
    _user: CurrentUser = Depends(require_role("admin")),
) -> None:
    """删除包（仅 admin 可操作，且仅无版本的孤儿包可删除）。"""
    repo = _get_producer_repository()
    pkg = repo.get_package(package_id)
    if pkg is None:
        raise HTTPException(status_code=404, detail=f"包 {package_id} 不存在")
    versions_count = pkg.get("versions_count", 0)
    if versions_count > 0:
        raise HTTPException(
            status_code=403,
            detail=f"包 {package_id} 包含 {versions_count} 个版本，无法删除。请先删除所有版本。",
        )
    if not repo.delete_package(package_id):
        raise HTTPException(status_code=404, detail=f"删除失败：包 {package_id} 不存在")
    return None


# ── GET /stats/dashboard ───────────────────────────────────

@router.get(
    "/stats/dashboard",
)
def get_dashboard_stats(
    _user: CurrentUser = Depends(require_role("admin")),
) -> dict[str, object]:
    """管理仪表盘统计数据（需 admin 权限）。"""
    repo = _get_producer_repository()
    return repo.get_dashboard_stats()
