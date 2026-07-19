"""认证与授权模块 — JWT 签发/验证、密码哈希、角色依赖注入。

依赖：
- JWT: python-jose[cryptography]（HS256 对称签名）
- 密码哈希: passlib[bcrypt]（自动加盐，抗 GPU 暴力破解）
- 角色层级: admin > reviewer > submitter > user
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Depends, HTTPException
from jose import JWTError, jwt
from passlib.context import CryptContext
from schema.constants import UserRole
from src.dependencies import (
    BearerTokenInvalid,
    CurrentUser,
    get_current_user,
)

# ── 密码哈希（bcrypt）─────────────────────────────────────

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    """使用 bcrypt 生成密码哈希。"""
    return _pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """验证密码是否匹配哈希。"""
    return _pwd_context.verify(password, password_hash)


# ── JWT ───────────────────────────────────────────────────

_ACCESS_TOKEN_TTL = timedelta(hours=2)
_REFRESH_TOKEN_TTL = timedelta(days=7)
_ALGORITHM = "HS256"

# JWT 签名密钥（生产环境应从环境变量/密钥管理服务读取）
_JWT_SECRET: str | None = None


def _get_jwt_secret() -> str:
    """获取 JWT 签名密钥，优先从环境变量 JWT_SECRET 读取。"""
    global _JWT_SECRET
    if _JWT_SECRET is not None:
        return _JWT_SECRET
    _JWT_SECRET = os.getenv("JWT_SECRET", "").strip()
    if not _JWT_SECRET:
        # 开发环境自动生成随机密钥（进程重启后所有 token 失效）
        import base64
        _JWT_SECRET = base64.urlsafe_b64encode(os.urandom(32)).decode()
    return _JWT_SECRET


def create_access_token(user_id: str, role: str) -> str:
    """签发 access token（2h 有效）。"""
    return _create_token(user_id, role, _ACCESS_TOKEN_TTL)


def create_refresh_token(user_id: str, role: str) -> str:
    """签发 refresh token（7d 有效）。"""
    return _create_token(user_id, role, _REFRESH_TOKEN_TTL)


def _create_token(user_id: str, role: str, ttl: timedelta) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "role": role,
        "iat": now,
        "exp": now + ttl,
    }
    return jwt.encode(payload, _get_jwt_secret(), algorithm=_ALGORITHM)


def decode_token(token: str, *, verify_exp: bool = True) -> dict:
    """解码并验证 JWT token，返回 payload 字典。

    Raises:
        BearerTokenInvalid: token 无效或过期。
    """
    try:
        options = {"verify_exp": verify_exp}
        payload = jwt.decode(
            token, _get_jwt_secret(), algorithms=[_ALGORITHM], options=options
        )
        return payload
    except JWTError as exc:
        raise BearerTokenInvalid(f"Token 无效: {exc}")


# ── FastAPI 依赖 ──────────────────────────────────────────


def verify_jwt_token(token: str) -> CurrentUser:
    """JWT 验证函数，替换 dependencies 中的占位实现。"""
    payload = decode_token(token)
    return CurrentUser(id=payload["sub"], role=payload.get("role", "user"))


# 角色层级：值越小权限越高
_ROLE_HIERARCHY: dict[str, int] = {
    UserRole.ADMIN.value: 0,
    UserRole.REVIEWER.value: 1,
    UserRole.SUBMITTER.value: 2,
    UserRole.USER.value: 3,
}


def require_role(min_role: str):
    """FastAPI 依赖工厂：要求当前用户至少具备 min_role 权限。

    角色层级: admin(0) > reviewer(1) > submitter(2) > user(3)
    require_role("reviewer") → admin 和 reviewer 均可通过。

    Usage:
        @router.post("/reviews")
        def submit_review(
            user: CurrentUser = Depends(require_role("reviewer")),
        ): ...
    """

    def dependency(
        user: Annotated[CurrentUser, Depends(get_current_user)],
    ) -> CurrentUser:
        required_level = _ROLE_HIERARCHY.get(min_role)
        user_level = _ROLE_HIERARCHY.get(user.role)
        if required_level is None or user_level is None:
            raise HTTPException(status_code=403, detail="未知角色")
        if user_level > required_level:
            raise HTTPException(
                status_code=403,
                detail=f"需要 {min_role} 或更高权限，当前角色: {user.role}",
            )
        return user

    return dependency


# ── 启动安装 ──────────────────────────────────────────────


def install() -> None:
    """在应用启动时调用，将 JWT 验证注入到 FastAPI 依赖链。

    替换 dependencies.py 中的占位 verifier，
    并清除相关 LRU 缓存确保依赖解析使用新函数。
    """
    from src.dependencies import set_bearer_token_verifier, clear_runtime_dependencies

    set_bearer_token_verifier(verify_jwt_token)
    clear_runtime_dependencies()
