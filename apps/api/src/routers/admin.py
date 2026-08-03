"""管理员路由 — 用户管理（角色分配、账户启停）。"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field

from src.auth import require_role
from src.database import create_session_factory, get_runtime_engine
from src.dependencies import CurrentUser
from src.models.common import ErrorEnvelope, StrictContractModel
from src.repositories.producer_sqlalchemy import ProducerRepository
from src.settings import get_settings

router = APIRouter(prefix="/api/v0/admin", tags=["admin"])


def _get_repo() -> ProducerRepository:
    settings = get_settings()
    if settings.database_url is None:
        raise HTTPException(status_code=503, detail="DATABASE_URL 未配置")
    engine = get_runtime_engine(settings.database_url)
    return ProducerRepository(create_session_factory(engine))


# ── 请求模型 ──────────────────────────────────────────────


class UpdateRoleRequest(StrictContractModel):
    role: str = Field(..., description="新角色: user / submitter / reviewer / admin")


class UpdateStatusRequest(StrictContractModel):
    is_active: bool = Field(..., description="启用 (true) 或禁用 (false)")


# ── GET /admin/users ──────────────────────────────────────


@router.get(
    "/users",
    responses={400: {"model": ErrorEnvelope}},
)
def list_users(
    search: str | None = Query(default=None, description="邮箱或昵称模糊搜索"),
    role: str | None = Query(default=None, description="按角色筛选"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _user: CurrentUser = Depends(require_role("admin")),
) -> dict[str, object]:
    """获取用户列表（仅 admin 可访问）。"""
    repo = _get_repo()
    items, total = repo.list_users(search=search, role=role, limit=limit, offset=offset)
    return {"items": items, "total": total}


# ── PATCH /admin/users/{user_id}/role ─────────────────────


@router.patch(
    "/users/{user_id}/role",
    responses={
        400: {"model": ErrorEnvelope},
        404: {"model": ErrorEnvelope},
        409: {"model": ErrorEnvelope},
    },
)
def update_user_role(
    user_id: str,
    body: UpdateRoleRequest,
    _user: CurrentUser = Depends(require_role("admin")),
) -> dict[str, object]:
    """修改用户角色（仅 admin）。角色未变化时返回 409。"""
    from schema.constants import UserRole
    valid_roles = {r.value for r in UserRole}
    if body.role not in valid_roles:
        raise HTTPException(
            status_code=400,
            detail=f"无效角色 '{body.role}'，有效值: {', '.join(sorted(valid_roles))}",
        )

    repo = _get_repo()
    result = repo.update_user_role(user_id, body.role)
    if result is None:
        raise HTTPException(status_code=404, detail=f"用户 {user_id} 不存在")
    if result.get("conflict"):
        raise HTTPException(status_code=409, detail=f"用户角色已是 '{body.role}'，无需修改")
    return result


# ── PATCH /admin/users/{user_id}/status ───────────────────


@router.patch(
    "/users/{user_id}/status",
    responses={404: {"model": ErrorEnvelope}},
)
def update_user_status(
    user_id: str,
    body: UpdateStatusRequest,
    _user: CurrentUser = Depends(require_role("admin")),
) -> dict[str, object]:
    """启用或禁用用户账号（仅 admin）。禁用后该用户无法登录或刷新 token。"""
    repo = _get_repo()
    result = repo.update_user_status(user_id, body.is_active)
    if result is None:
        raise HTTPException(status_code=404, detail=f"用户 {user_id} 不存在")
    return result
