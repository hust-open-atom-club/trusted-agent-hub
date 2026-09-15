"""供给侧 HTTP 路由 — 包提交、版本管理与审核流转。

端点（均挂载在 /api/v0/producer 下）:
    POST /packages                    — 注册新能力包
    POST /packages/{id}/versions      — 创建新版本
    POST /versions/{id}/submit        — 提交审核（触发扫描）
    GET  /packages/{id}               — 包详情
    GET  /versions/{id}               — 版本详情（reviewer/admin 含完整扫描报告）
"""

from __future__ import annotations

from datetime import datetime, timezone
from functools import wraps
import logging
import re
import threading
from typing import Any, Callable
from weakref import WeakValueDictionary

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import Field

from schema.constants import UserRole
from src.database import (
    create_session_factory,
    get_runtime_engine,
)
from src.auth import require_role, verify_resource_access
from src.dependencies import CurrentUser
from src.models.common import (
    ErrorEnvelope,
    StrictContractModel,
    require_safe_source_subdirectory,
)
from src.models.producer import (
    CreatePackageRequest,
    CreateVersionRequest,
    PackageResponse,
    SubmitResponse,
    VersionResponse,
)
from src.repositories.producer_sqlalchemy import ProducerRepository
from src.services.producer import (
    ProducerPersistenceError,
    ProducerService,
    ProducerServiceError,
    ProducerSourceConflictError,
    ProducerSubmissionConflict,
)
from src.settings import get_settings

# ── 延迟导入 trust 模块的 _run_scan_task ──────────────────
# 避免循环导入，在 submit 端点内 import

router = APIRouter(prefix="/api/v0/producer", tags=["producer"])
logger = logging.getLogger(__name__)

_VERSION_SUBMISSION_LOCK_GUARD = threading.Lock()
_VERSION_SUBMISSION_LOCKS: WeakValueDictionary[str, Any] = WeakValueDictionary()
_VERSION_SUBMISSION_CONFLICT_STATUSES = frozenset(
    {"submitted", "scanning", "pending_review"}
)


def _version_submission_lock(version_id: str) -> threading.RLock:
    with _VERSION_SUBMISSION_LOCK_GUARD:
        lock = _VERSION_SUBMISSION_LOCKS.get(version_id)
        if lock is None:
            lock = threading.RLock()
            _VERSION_SUBMISSION_LOCKS[version_id] = lock
        return lock


def _serialize_version_submission(
    handler: Callable[..., SubmitResponse],
) -> Callable[..., SubmitResponse]:
    """Serialize submissions for one version without blocking other versions."""
    @wraps(handler)
    def guarded_handler(*args: Any, **kwargs: Any) -> SubmitResponse:
        version_id = kwargs.get("version_id")
        if version_id is None and args:
            version_id = args[0]
        if not isinstance(version_id, str):
            raise TypeError("version_id is required")
        with _version_submission_lock(version_id):
            return handler(*args, **kwargs)

    return guarded_handler


def _mark_submission_failed(
    repository: Any,
    version_id: str,
    operator_id: str,
    error: str,
    *,
    expected_statuses: tuple[str, ...] = ("submitted", "scanning"),
) -> bool:
    """Move only an unfinished submission owned by this attempt to ``error``."""
    if not expected_statuses:
        return False
    try:
        transition = getattr(
            repository,
            "transition_version_status_if_current",
            None,
        )
        if callable(transition):
            transitioned = transition(
                version_id,
                expected_statuses,
                "error",
            )
        else:
            current = repository.get_version(version_id)
            transitioned = bool(
                isinstance(current, dict)
                and current.get("status") in expected_statuses
            )
            if transitioned:
                repository.update_version_status(version_id, "error")
        if not transitioned:
            return False
    except Exception:
        logger.exception(
            "Could not transition failed submission %s to error",
            version_id,
        )
        return False

    try:
        repository.update_version_data(
            version_id,
            {"scan_error": error},
        )
    except Exception:
        logger.exception(
            "Could not persist submission failure for %s",
            version_id,
        )

    try:
        from schema.constants import AuditAction

        repository.create_audit_log(
            action=AuditAction.SCAN_COMPLETE.value,
            target_type="version",
            target_id=version_id,
            operator_id=operator_id,
            detail={"error": error, "phase": "submission"},
        )
    except Exception:
        logger.exception(
            "Could not write submission failure audit for %s",
            version_id,
        )
    return True


def _mark_registered_scan_failed(scan_id: str | None, error: str) -> None:
    if not scan_id:
        return
    try:
        from src.routers.trust import _update_scan

        _update_scan(
            scan_id,
            status="error",
            error=error,
            callback_finished=True,
        )
    except Exception:
        logger.exception(
            "Could not mark registered scan %s as failed",
            scan_id,
        )


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
    responses={
        400: {"model": ErrorEnvelope},
        404: {"model": ErrorEnvelope},
        409: {"model": ErrorEnvelope},
    },
)
@_serialize_version_submission
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
    source_owner_id = _user.id
    if pkg_id:
        pkg = repo.get_package(str(pkg_id))
        if pkg:
            verify_resource_access(_user, pkg.get("submitter_id", ""))
            source_owner_id = str(pkg.get("submitter_id") or _user.id)
    if version.get("status") in _VERSION_SUBMISSION_CONFLICT_STATUSES:
        raise HTTPException(
            status_code=409,
            detail="该版本已提交或正在处理，请勿重复提交",
        )

    # Reject a non-default branch before changing the version state.  This
    # protects producer submissions as well as the standalone scan endpoint.
    source_data = version.get("source")
    source_url = (
        source_data.get("repository_url", "")
        if isinstance(source_data, dict)
        else ""
    )
    source_subdirectory_present = (
        isinstance(source_data, dict) and "subdirectory" in source_data
    )
    source_subdirectory: str | None = None
    if source_subdirectory_present:
        raw_subdirectory = source_data.get("subdirectory")
        if raw_subdirectory is not None and not isinstance(raw_subdirectory, str):
            raise HTTPException(
                status_code=400,
                detail="Version source subdirectory is invalid",
            )
        if isinstance(raw_subdirectory, str):
            try:
                normalized_subdirectory = require_safe_source_subdirectory(
                    raw_subdirectory.strip()
                )
            except ValueError as exc:
                raise HTTPException(
                    status_code=400,
                    detail="Version source subdirectory is invalid",
                ) from exc
            source_subdirectory = (
                None if normalized_subdirectory == "." else normalized_subdirectory
            )
    resolved_source = None
    if source_url:
        from src.routers.trust import _parse_github_url

        # Only the URL shape is validated up front.  The live GitHub
        # resolution (default branch + HEAD) runs below, after the reuse
        # branch decides it actually needs a brand-new scan: reusing a
        # completed snapshot is identified by the commit that was scanned,
        # not by whatever upstream HEAD says now.
        resolved_source = _parse_github_url(str(source_url))
        url_subdirectory = resolved_source.get("subdir")
        url_subdirectory_present = url_subdirectory not in (None, "")
        if not url_subdirectory_present:
            normalized_url_subdirectory = None
        elif isinstance(url_subdirectory, str):
            try:
                normalized_url_subdirectory = require_safe_source_subdirectory(
                    url_subdirectory
                )
            except ValueError as exc:
                raise HTTPException(
                    status_code=400,
                    detail="URL source subdirectory is invalid",
                ) from exc
            if normalized_url_subdirectory == ".":
                normalized_url_subdirectory = None
        else:
            raise HTTPException(
                status_code=400,
                detail="URL source subdirectory is invalid",
            )
        if (
            source_subdirectory_present
            and url_subdirectory_present
            and normalized_url_subdirectory != source_subdirectory
        ):
            raise HTTPException(
                status_code=400,
                detail="URL source subdirectory conflicts with version source.subdirectory",
            )
        if source_subdirectory_present:
            resolved_source["subdir"] = source_subdirectory

    # initial_scan_id 是用户凭据：状态变更前先校验/原子领取，失败或不存在时回落到持久化复用路径。
    initial_sid = body.initial_scan_id.strip() if body and body.initial_scan_id else None
    initial_info = None
    initial_claimed = False
    release_claim_fn: Callable[..., None] | None = None
    scan_owner_id = _user.id
    if initial_sid:
        from src.routers.trust import (
            _claim_reusable_scan,
            _get_scan,
            _release_reusable_scan,
        )

        release_claim_fn = _release_reusable_scan
        if _get_scan(initial_sid) is not None:
            from src.routers.trust import _resolve_default_branch_source

            # 复用校验只需要默认分支来规范化绑定；扫描身份以记录里的
            # commit 为准（不复用上游当前 HEAD 的解析结果）。
            reuse_binding_source = resolved_source
            if (
                isinstance(reuse_binding_source, dict)
                and not reuse_binding_source.get("ref")
            ):
                reuse_binding_source = _resolve_default_branch_source(
                    reuse_binding_source
                )
            initial_binding = _build_initial_scan_binding(
                source_data,
                reuse_binding_source,
            )
            initial_info = _claim_reusable_scan(
                initial_sid,
                owner_id=_user.id,
                source_binding=initial_binding,
            )
            initial_claimed = initial_info is not None
            if initial_info is not None:
                scan_owner_id = str(
                    initial_info.get("owner_user_id")
                    or initial_info.get("user_id")
                    or _user.id
                ).strip() or _user.id
        if not initial_claimed:
            # 回落：持久化扫描任务（数据库）复用路径。先校验归属/状态/来源，
            # 错误语义与既有行为保持一致。
            from src.routers.trust import (
                _authorized_scan_info,
                _scan_source_matches,
            )

            initial_info = _authorized_scan_info(initial_sid, _user)
            if initial_info is None:
                raise HTTPException(
                    status_code=404,
                    detail=f"扫描任务 {initial_sid} 不存在或已过期",
                )
            if initial_info.get("resource_consumed") is True:
                # 已被消费的扫描结果不得再次复用：其源码目录已被打包消费
                # （或删除），复用只会退回重新下载或打包失败。
                raise HTTPException(
                    status_code=409,
                    detail="该扫描结果已被消费，请重新扫描",
                )
            scan_owner_id = str(
                initial_info.get("owner_user_id")
                or initial_info.get("user_id")
                or ""
            ).strip()
            if not scan_owner_id:
                raise HTTPException(
                    status_code=503,
                    detail="Scan task has no owner",
                )
            if initial_info.get("status") != "complete" or not initial_info.get(
                "full_report"
            ):
                raise HTTPException(
                    status_code=409,
                    detail="只有已完成的扫描任务才能复用",
                )
            if resolved_source is None or not source_url:
                raise HTTPException(
                    status_code=400,
                    detail="复用扫描结果时必须提供源码仓库地址",
                )
            # The reuse identity is the commit captured by the scan itself.
            # A live HEAD lookup would fail every active repository the moment
            # anyone pushes, so upstream is deliberately not consulted here.
            full_report = initial_info.get("full_report")
            expected_commit_hash = initial_info.get("commit_hash")
            if expected_commit_hash is None and isinstance(full_report, dict):
                expected_commit_hash = full_report.get("commit_hash")
            if not source_url or not _scan_source_matches(
                initial_info,
                str(source_url),
                resolved_source=resolved_source,
                expected_source=source_data if isinstance(source_data, dict) else None,
                expected_commit_hash=expected_commit_hash,
            ):
                raise HTTPException(
                    status_code=400,
                    detail="扫描任务与当前版本的源码仓库不匹配",
                )

    # Reject duplicates before moving the version or creating a scan task.
    if not initial_sid and source_url:
        from src.routers.trust import (
            _find_scan_task_by_source_identity,
            scan_conflict_detail,
        )

        duplicate_info = _find_scan_task_by_source_identity(
            _user.id,
            str(source_url),
            source_subdirectory,
        )
        if duplicate_info is not None:
            raise HTTPException(
                status_code=409,
                detail=scan_conflict_detail(duplicate_info),
            )

    # New scans need the live GitHub resolution (default branch + HEAD) so
    # the task is pinned to an immutable commit.  The reuse branch above
    # already validated its snapshot against the scanned commit and skips
    # this entirely — that is what keeps reuse working on active
    # repositories that have moved HEAD since the scan completed.
    if not initial_sid and source_url:
        from src.routers.trust import (
            _pin_resolved_source,
            _resolve_default_branch_source,
        )

        resolved_source = _resolve_default_branch_source(resolved_source)
        try:
            resolved_source = _pin_resolved_source(resolved_source)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="无法将源码仓库解析为不可变提交版本",
            ) from exc

    service = ProducerService(repo)
    registered_scan_id: str | None = None

    def release_initial_claim(consumed: bool = False) -> None:
        nonlocal initial_claimed
        if not initial_claimed or release_claim_fn is None or initial_sid is None:
            return
        try:
            release_claim_fn(initial_sid, consumed=consumed)
        except Exception:
            logger.exception(
                "Could not release initial scan claim %s",
                initial_sid,
            )
        finally:
            initial_claimed = False

    def on_scan_error(sid: str, error: str) -> None:
        try:
            service.handle_scan_error(version_id, error)
        except Exception:
            repo.update_version_status(version_id, "error")
            repo.update_version_data(version_id, {"scan_error": error})

    def on_scan_done(
        sid: str, report: dict[str, object] | None, error: str | None
    ) -> None:
        if error is not None:
            on_scan_error(sid, error)
        elif report is not None:
            if service.handle_scan_complete(version_id, report) is not True:
                raise RuntimeError("扫描完成回调未能处理安装产物")

    try:
        repo_url, scan_id, _ = service.submit_version(
            version_id,
            user_id=_user.id,
            scan_task=(
                {
                    "owner_user_id": scan_owner_id,
                    "existing_scan_id": initial_sid,
                }
                if initial_sid
                else {
                    "owner_user_id": _user.id,
                    "source_ref": resolved_source.get("ref")
                    if isinstance(resolved_source, dict)
                    else None,
                    "commit_hash": resolved_source.get("commit_hash")
                    if isinstance(resolved_source, dict)
                    else None,
                    "source_subdirectory": resolved_source.get("subdir")
                    if isinstance(resolved_source, dict)
                    else None,
                }
            ),
        )
    except ProducerPersistenceError as exc:
        release_initial_claim()
        raise HTTPException(
            status_code=503,
            detail="扫描任务持久化暂时不可用，版本状态未改变",
        ) from exc
    except ProducerSourceConflictError as exc:
        release_initial_claim()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ProducerSubmissionConflict as exc:
        release_initial_claim()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ProducerServiceError as exc:
        release_initial_claim()
        error = str(exc) or type(exc).__name__
        _mark_submission_failed(
            repo,
            version_id,
            _user.id,
            error,
            expected_statuses=("submitted", "scanning"),
        )
        _mark_registered_scan_failed(registered_scan_id, error)
        raise HTTPException(status_code=400, detail=str(exc))

    # ── 采集平台信号（作者历史 / 审核记录 / 安装反馈）供评分引擎使用 ──
    from src.services.signals import collect_platform_signals
    version_row = repo.get_version(version_id)
    signals: dict[str, object] = {}
    if version_row:
        try:
            signals = collect_platform_signals(
                repo,
                version_id=version_id,
                package_id=str(version_row.get("package_id", "")),
                submitter_id=_user.id,
            )
        except Exception as exc:
            # 状态切换后的任何失败都必须把版本恢复到 error，不能留下无人
            # 认领的 "半提交" 状态。
            release_initial_claim()
            error = f"提交审核失败: {type(exc).__name__}: {exc}"
            _mark_submission_failed(
                repo,
                version_id,
                _user.id,
                error,
                expected_statuses=("submitted", "scanning"),
            )
            _mark_registered_scan_failed(registered_scan_id, error)
            raise

    # ── 复用初次扫描结果（进程内原子领取路径） ──
    if initial_claimed and initial_info is not None:
        full_report = initial_info.get("full_report")
        consumed = False
        try:
            if not isinstance(full_report, dict) or not full_report:
                raise HTTPException(
                    status_code=500,
                    detail="初始扫描结果缺少完整报告",
                )
            if service.handle_scan_complete(version_id, full_report) is not True:
                raise HTTPException(
                    status_code=500,
                    detail="安装产物打包失败，版本已置为 error",
                )
            persisted_version = repo.get_version(version_id)
            if (
                not isinstance(persisted_version, dict)
                or persisted_version.get("status") != "pending_review"
            ):
                raise HTTPException(
                    status_code=500,
                    detail="扫描结果未能写入 pending_review 状态",
                )
            consumed = True
            return SubmitResponse(
                version_id=version_id,
                status="pending_review",
                scan_id=initial_sid,
                message="复用初次扫描结果，已跳过重复扫描",
            )
        except Exception as exc:
            release_initial_claim()
            if isinstance(exc, HTTPException):
                error = str(exc.detail)
            else:
                error = f"提交审核失败: {type(exc).__name__}: {exc}"
            _mark_submission_failed(
                repo,
                version_id,
                _user.id,
                error,
                expected_statuses=("submitted", "scanning", "pending_review"),
            )
            raise
        finally:
            release_initial_claim(consumed=consumed)

    # ── 检查是否可以复用初始扫描结果 ──
    if initial_sid and initial_info is not None:
        from src.routers.trust import (
            _deliver_scan_callback,
            _get_scan_task_repository,
            _load_scan_info,
            _remember_scan_info,
            _schedule_scan_callback_retry,
            _scan_info_from_task,
            _update_scan_state,
            _version_scan_completion_callback,
        )

        try:
            # The association was committed by submit_version above.  Mirror
            # it before invoking user-visible side effects as a guard for
            # process-local state and for repositories with old task rows.
            _update_scan_state(
                initial_sid,
                {"version_id": version_id},
                required=True,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="扫描任务关联暂时不可用，回调尚未执行",
            ) from exc

        callback_info = _load_scan_info(initial_sid) or initial_info
        callback_lease_token: str | None = None
        callback_repository = _get_scan_task_repository()
        if callback_repository is not None:
            claim_callback = getattr(
                callback_repository,
                "claim_scan_callback_task",
                None,
            )
            claimed_callback = (
                claim_callback(
                    initial_sid,
                    lease_seconds=30 * 60,
                )
                if claim_callback is not None
                else None
            )
            if claimed_callback is None and claim_callback is not None:
                latest_info = _load_scan_info(initial_sid)
                if latest_info and latest_info.get("callback_status") == "delivered":
                    latest_version = repo.get_version(version_id) or {}
                    latest_status = str(
                        latest_version.get("status") or "scanning"
                    )
                    return SubmitResponse(
                        version_id=version_id,
                        status=(
                            "pending_review"
                            if latest_status == "pending_review"
                            else "error"
                        ),
                        scan_id=initial_sid,
                        message=(
                            "扫描结果已复用，版本已进入待审核"
                            if latest_status == "pending_review"
                            else "复用扫描结果处理失败"
                        ),
                    )
                return SubmitResponse(
                    version_id=version_id,
                    status="scanning",
                    scan_id=initial_sid,
                    message="扫描结果复用回调正在处理中，请稍后查询状态",
                )
            if claimed_callback is not None:
                callback_info = _scan_info_from_task(claimed_callback)
                _remember_scan_info(callback_info)
                callback_lease_token = (
                    callback_info.get("lease_token")
                    if isinstance(callback_info.get("lease_token"), str)
                    else None
                )
                # The persisted report deliberately omits local_source_dir.
                # Reload after remembering the claimed row so an in-process
                # scan can contribute its complete runtime report before the
                # callback decides whether it must reacquire the source.
                merged_callback_info = _load_scan_info(initial_sid)
                if merged_callback_info is not None:
                    callback_info = merged_callback_info
                if callback_lease_token:
                    callback_info["lease_token"] = callback_lease_token

        full_report = callback_info.get("full_report")
        if not isinstance(full_report, dict):
            raise HTTPException(
                status_code=503,
                detail="扫描报告暂时不可用，回调已保留待重试",
            )
        delivered = False
        try:
            delivered = _deliver_scan_callback(
                initial_sid,
                full_report,
                None,
                _version_scan_completion_callback(version_id),
                lease_token=callback_lease_token,
            )
        finally:
            if callback_lease_token:
                from src.routers.trust import _release_scan_lease

                _release_scan_lease(initial_sid, callback_lease_token)
        if not delivered:
            _schedule_scan_callback_retry(initial_sid)
        current_version = repo.get_version(version_id) or {}
        actual_status = str(current_version.get("status") or "scanning")
        response_status = (
            (
                "pending_review"
                if actual_status == "pending_review"
                else "error"
            )
            if delivered
            else actual_status
        )
        return SubmitResponse(
            version_id=version_id,
            status=response_status,
            scan_id=initial_sid,
            message=(
                "复用初次扫描结果，已跳过重复扫描"
                if delivered and response_status == "pending_review"
                else "复用扫描结果处理失败"
                if delivered
                else "复用扫描结果的回调待重试"
            ),
        )

    # 否则正常启动后台扫描
    from src.routers.trust import (
        _SCAN_MAX_EXECUTION_SECONDS,
        _SCAN_TTL_SECONDS,
        _register_scan,
        _run_scan_task,
    )
    from schema.constants import AuditAction
    import time as _time

    try:
        if scan_id is None:
            raise RuntimeError("提交审核未生成扫描任务 ID")
        _register_scan(
            scan_id,
            {
                "status": "pending",
                "execution_started": False,
                "execution_finished": False,
                "execution_deadline_at": _time.time() + _SCAN_MAX_EXECUTION_SECONDS,
                "callback_finished": False,
                "reuse_claimed": False,
                "resource_consumed": False,
                "package_name": None,
                "created_at": version.get("submitted_at")
                or datetime.now(timezone.utc).isoformat(),
                "finished_at": None,
                "full_report": None,
                "summary": None,
                "trust_score": None,
                "error": None,
                "expires_at": _time.time() + _SCAN_TTL_SECONDS,
                "user_id": _user.id,
                "source_owner_id": source_owner_id,
            },
            on_error=on_scan_error,
        )
        registered_scan_id = scan_id

        # 扫描任务真正启动时补写 SCAN_START 审计，与 scan_complete 的
        # detail.scan_id 形成证据链：submit → scan_start → scan_complete
        repo.create_audit_log(
            action=AuditAction.SCAN_START.value,
            target_type="version",
            target_id=version_id,
            operator_id=_user.id,
            detail={"scan_id": scan_id},
        )

        background_tasks.add_task(
            _run_scan_task,
            scan_id,
            repo_url,
            on_complete=on_scan_done,
            on_error=on_scan_error,
            signals=signals,
            resolved_source=resolved_source,
        )
    except Exception as exc:
        release_initial_claim()
        error = f"提交审核失败: {type(exc).__name__}: {exc}"
        _mark_submission_failed(
            repo,
            version_id,
            _user.id,
            error,
            expected_statuses=("submitted", "scanning"),
        )
        _mark_registered_scan_failed(registered_scan_id, error)
        raise

    return SubmitResponse(
        version_id=version_id,
        status="scanning",
        scan_id=scan_id,
    )


# ── GET /packages ─────────────────────────────────────────

def _build_initial_scan_binding(
    source_data: object,
    resolved_source: dict[str, object] | None,
) -> dict[str, object]:
    """Normalize the version source used to validate an initial scan reuse."""
    if not isinstance(source_data, dict) or not isinstance(resolved_source, dict):
        raise HTTPException(
            status_code=400,
            detail="版本缺少可用于绑定 initial_scan_id 的源码信息",
        )

    repository_url = str(resolved_source.get("base_url") or "").strip()
    default_branch = str(resolved_source.get("ref") or "").strip()
    if not repository_url or not default_branch:
        raise HTTPException(
            status_code=400,
            detail="版本源码地址无法规范化，不能复用 initial_scan_id",
        )

    url_subdirectory = resolved_source.get("subdir")
    declared_subdirectory = source_data.get("subdirectory")

    def normalize_subdirectory(value: object, field_name: str) -> str | None:
        if value in (None, ""):
            return None
        if not isinstance(value, str):
            raise HTTPException(
                status_code=400,
                detail=f"{field_name} 不是有效的源码子目录",
            )
        try:
            normalized = require_safe_source_subdirectory(value)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"{field_name} 不是有效的源码子目录: {exc}",
            ) from exc
        return None if normalized == "." else normalized

    url_subdirectory = normalize_subdirectory(url_subdirectory, "源码 URL 子目录")
    declared_subdirectory = normalize_subdirectory(
        declared_subdirectory,
        "版本 source.subdirectory",
    )
    if (
        url_subdirectory is not None
        and declared_subdirectory is not None
        and url_subdirectory != declared_subdirectory
    ):
        raise HTTPException(
            status_code=400,
            detail="版本源码 URL 子目录与 source.subdirectory 不一致",
        )
    subdirectory = declared_subdirectory or url_subdirectory

    raw_commit_hash = source_data.get("commit_hash")
    commit_hash = (
        str(raw_commit_hash).strip().lower()
        if raw_commit_hash is not None
        else ""
    )
    if (
        not re.fullmatch(r"[0-9a-f]{40}", commit_hash)
        or set(commit_hash) == {"0"}
    ):
        raise HTTPException(
            status_code=400,
            detail="版本缺少与 initial_scan_id 对应的完整 commit_hash",
        )

    raw_ref = source_data.get("ref")
    ref = str(raw_ref).strip() if raw_ref is not None else ""
    ref_type = str(source_data.get("ref_type") or "").strip().lower()
    if ref.casefold() == "head":
        ref = ""
    elif re.fullmatch(r"[0-9a-fA-F]{40}", ref):
        ref = ref.lower()
    if ref_type not in {"", "branch", "commit"}:
        raise HTTPException(
            status_code=400,
            detail="版本 source.ref_type 不能用于 initial_scan_id 绑定",
        )
    if ref_type == "commit" and ref != commit_hash:
        raise HTTPException(
            status_code=400,
            detail="版本 source.ref 与 commit_hash 不一致",
        )
    if ref_type == "branch" and ref and ref != default_branch:
        raise HTTPException(
            status_code=400,
            detail="版本 source.ref 不是仓库默认分支",
        )
    if ref_type == "" and ref:
        if re.fullmatch(r"[0-9a-f]{40}", ref):
            if ref != commit_hash:
                raise HTTPException(
                    status_code=400,
                    detail="版本 source.ref 与扫描 commit 不一致",
                )
        elif ref != default_branch:
            raise HTTPException(
                status_code=400,
                detail="版本 source.ref 与扫描默认分支不一致",
            )

    return {
        "repository_url": repository_url.casefold(),
        "subdirectory": subdirectory,
        "ref": default_branch,
        "commit_hash": commit_hash,
    }


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
    "/versions/{version_id}/file-context",
    responses={400: {"model": ErrorEnvelope}, 404: {"model": ErrorEnvelope}},
)
def get_version_file_context(
    version_id: str,
    path: str = Query(..., min_length=1, max_length=512, description="仓库内相对路径"),
    line: int = Query(default=1, ge=1, le=1_000_000, description="目标行号"),
    _user: CurrentUser = Depends(require_role("reviewer")),
) -> dict[str, object]:
    """返回审核用的脱敏、截断代码上下文，不返回完整源码。"""
    repo = _get_producer_repository()
    version = repo.get_version(version_id)
    if version is None:
        raise HTTPException(status_code=404, detail=f"版本 {version_id} 不存在")
    package = repo.get_package(str(version.get("package_id") or ""))
    if package is None:
        raise HTTPException(status_code=404, detail="版本所属包不存在")
    verify_resource_access(_user, package.get("submitter_id", ""))

    service = ProducerService(repo)
    try:
        return service.get_file_context(version_id, path, line=line)
    except ProducerServiceError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

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
    """获取版本详情；本人可看脱敏发现，完整报告仅 reviewer/admin 可看。"""
    repo = _get_producer_repository()
    version = repo.get_version(version_id)
    if version is None:
        raise HTTPException(
            status_code=404, detail=f"版本 {version_id} 不存在"
        )
    pkg_id = version.get("package_id")
    if not pkg_id:
        raise HTTPException(status_code=404, detail="版本所属包不存在")
    pkg = repo.get_package(str(pkg_id))
    if pkg is None:
        raise HTTPException(status_code=404, detail="版本所属包不存在")
    verify_resource_access(_user, pkg.get("submitter_id", ""))

    include_scan_report = _user.role in (
        UserRole.ADMIN.value,
        UserRole.REVIEWER.value,
    )
    service = ProducerService(repo)
    detail = service.get_version_detail(
        version_id,
        version=version,
        include_scan_report=include_scan_report,
        include_submitter_findings=not include_scan_report,
    )
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
    grade: str | None = Query(default=None, description="按风险等级筛选（A/B/C/D/E）"),
    since: str | None = Query(default=None, description="提交时间起始（ISO 格式）"),
    until: str | None = Query(default=None, description="提交时间截止（ISO 格式）"),
    limit: int = Query(default=50, ge=1, le=200, description="每页数量"),
    offset: int = Query(default=0, ge=0, description="偏移量"),
    _user: CurrentUser = Depends(require_role("submitter")),
) -> list[dict[str, object]]:
    """获取版本列表（按提交时间倒序）。

    submitter 只能查看自己的版本；reviewer/admin 可查看全量版本。
    reviewer/admin 支持以下筛选：
    - 按提交者筛选：?submitter_id=xxx
    - 按状态筛选：?status=pending_review
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

    is_reviewer_or_admin = _user.role in (
        UserRole.ADMIN.value,
        UserRole.REVIEWER.value,
    )

    # The endpoint serves both the submitter's own-submissions page and the
    # reviewer/admin queue.  Keep the ownership boundary independent of the
    # query string: omitting submitter_id must never turn this into a global
    # listing for a submitter.
    if not is_reviewer_or_admin:
        return service.list_my_versions(_user.id, limit=limit, offset=offset)

    if submitter_id is not None:
        return service.list_my_versions(submitter_id, limit=limit, offset=offset)

    if (
        status is not None
        or grade is not None
        or since is not None
        or until is not None
    ):
        return service.list_versions_by_status(
            status=status,
            grade=grade,
            since=since,
            until=until,
            limit=limit,
            offset=offset,
        )

    return service.list_versions_by_status(limit=limit, offset=offset)


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
