"""认证 HTTP 路由 — 注册、登录、Token 刷新。

端点:
    POST /auth/register — 注册新用户
    POST /auth/login    — 登录，返回 access + refresh token
    POST /auth/refresh  — 刷新 access token（refresh token rotation）
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from src.database import create_session_factory, get_runtime_engine
from src.repositories.orm_producer import UserRow
from src.repositories.producer_sqlalchemy import ProducerRepository
from src.settings import get_settings
from sqlalchemy import select
from sqlalchemy.orm import Session

router = APIRouter(prefix="/api/v0/auth", tags=["auth"])


# ── 请求/响应模型 ─────────────────────────────────────────


class RegisterRequest(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=6, max_length=128)


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


# ── 仓库辅助 ──────────────────────────────────────────────


def _get_session() -> Session:
    settings = get_settings()
    if settings.database_url is None:
        raise HTTPException(status_code=503, detail="DATABASE_URL 未配置")
    engine = get_runtime_engine(settings.database_url)
    return create_session_factory(engine)()


# ── POST /auth/register ───────────────────────────────────


@router.post("/register", status_code=201)
def register(body: RegisterRequest) -> dict:
    """注册新用户。默认角色为 submitter。"""
    session = _get_session()
    try:
        existing = session.scalar(
            select(UserRow).where(UserRow.username == body.username)
        )
        if existing is not None:
            raise HTTPException(status_code=409, detail="用户名已存在")

        import uuid

        user = UserRow(
            id=f"user-{uuid.uuid4().hex}",
            username=body.username,
            password_hash=hash_password(body.password),
            role="submitter",  # 默认角色
        )
        session.add(user)
        session.commit()
        return {"id": user.id, "username": user.username, "role": user.role}
    finally:
        session.close()


# ── POST /auth/login ──────────────────────────────────────


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest) -> TokenResponse:
    """登录，返回 access token（2h）+ refresh token（7d）。"""
    session = _get_session()
    try:
        user = session.scalar(
            select(UserRow).where(UserRow.username == body.username)
        )
        if user is None or not verify_password(body.password, user.password_hash):
            raise HTTPException(status_code=401, detail="用户名或密码错误")

        access = create_access_token(user.id, user.role)
        refresh = create_refresh_token(user.id, user.role)
        return TokenResponse(access_token=access, refresh_token=refresh)
    finally:
        session.close()


# ── POST /auth/refresh ────────────────────────────────────


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest) -> TokenResponse:
    """使用 refresh token 获取新的 access token。

    实现 refresh token rotation：旧的 refresh token 被消费后失效，
    同时签发新 access token 和新 refresh token。
    """
    # 解码 refresh token（不验证过期，refresh 自身有过期时间）
    try:
        payload = decode_token(body.refresh_token, verify_exp=False)
    except Exception:
        raise HTTPException(status_code=401, detail="Refresh token 无效")

    # 验证过期
    import time
    if time.time() > payload.get("exp", 0):
        raise HTTPException(status_code=401, detail="Refresh token 已过期，请重新登录")

    user_id = payload["sub"]
    role = payload.get("role", "user")

    # Rotation: 签发全新的 access + refresh token 对
    new_access = create_access_token(user_id, role)
    new_refresh = create_refresh_token(user_id, role)

    return TokenResponse(access_token=new_access, refresh_token=new_refresh)
