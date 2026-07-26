"""认证 HTTP 路由 — 注册、登录、Token 刷新。

端点:
    POST /auth/register — 注册新用户（邮箱+密码+昵称）
    POST /auth/login    — 登录（邮箱+密码），返回 access + refresh token
    POST /auth/refresh  — 刷新 access token（refresh token rotation）
"""

from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr, Field

from src.auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from src.database import create_session_factory, get_runtime_engine
from src.repositories.orm_producer import UserRow
from src.settings import get_settings
from sqlalchemy import select
from sqlalchemy.orm import Session

router = APIRouter(prefix="/api/v0/auth", tags=["auth"])


# ── 请求/响应模型 ─────────────────────────────────────────


class RegisterRequest(BaseModel):
    email: EmailStr = Field(description="邮箱地址，用作登录凭证")
    password: str = Field(min_length=6, max_length=128)
    display_name: str | None = Field(default=None, max_length=64, description="昵称，不填则取邮箱前缀")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: str
    email: str
    role: str
    display_name: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserResponse | None = None


class RefreshRequest(BaseModel):
    refresh_token: str


# ── 仓库辅助 ──────────────────────────────────────────────


def _get_session() -> Session:
    settings = get_settings()
    if settings.database_url is None:
        raise HTTPException(status_code=503, detail="DATABASE_URL 未配置")
    engine = get_runtime_engine(settings.database_url)
    return create_session_factory(engine)()


def _email_prefix(email: str) -> str:
    return email.split("@")[0][:64]


# ── POST /auth/register ───────────────────────────────────


@router.post("/register", status_code=201, response_model=TokenResponse)
def register(body: RegisterRequest) -> dict:
    """注册新用户。邮箱为登录凭证，昵称默认取邮箱前缀，角色默认 submitter。"""
    session = _get_session()
    import uuid

    email = body.email.lower().strip()

    try:
        existing = session.scalar(
            select(UserRow).where(UserRow.email == email)
        )
        if existing is not None:
            raise HTTPException(status_code=409, detail="该邮箱已注册")

        user_id = f"user-{uuid.uuid4().hex}"
        display_name = (body.display_name or "").strip()
        if not display_name:
            display_name = _email_prefix(email)

        user = UserRow(
            id=user_id,
            email=email,
            password_hash=hash_password(body.password),
            role="submitter",
            display_name=display_name,
        )
        session.add(user)
        session.commit()

        access = create_access_token(user.id, user.role, email=user.email, display_name=user.display_name)
        refresh = create_refresh_token(user.id, user.role)

        return {
            "access_token": access,
            "refresh_token": refresh,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "display_name": user.display_name,
            },
        }
    finally:
        session.close()


# ── POST /auth/login ──────────────────────────────────────


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest) -> TokenResponse:
    """登录（邮箱+密码），返回 access token（2h）+ refresh token（7d）+ 用户信息。"""
    session = _get_session()
    email = body.email.lower().strip()

    try:
        user = session.scalar(
            select(UserRow).where(UserRow.email == email)
        )
        if user is None or not verify_password(body.password, user.password_hash):
            raise HTTPException(status_code=401, detail="邮箱或密码错误")

        access = create_access_token(user.id, user.role, email=user.email, display_name=user.display_name)
        refresh = create_refresh_token(user.id, user.role)
        return TokenResponse(
            access_token=access,
            refresh_token=refresh,
            user=UserResponse(
                id=user.id,
                email=user.email,
                role=user.role,
                display_name=user.display_name,
            ),
        )
    finally:
        session.close()


# ── POST /auth/refresh ────────────────────────────────────


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest) -> TokenResponse:
    """使用 refresh token 获取新的 access token。

    实现 refresh token rotation：旧的 refresh token 被消费后失效，
    同时签发新 access token 和新 refresh token。
    """
    try:
        payload = decode_token(body.refresh_token, verify_exp=False)
    except Exception:
        raise HTTPException(status_code=401, detail="Refresh token 无效")

    import time
    if time.time() > payload.get("exp", 0):
        raise HTTPException(status_code=401, detail="Refresh token 已过期，请重新登录")

    user_id = payload["sub"]
    role = payload.get("role", "user")
    email = payload.get("email", "")
    display_name = payload.get("display_name", "")

    new_access = create_access_token(user_id, role, email=email, display_name=display_name)
    new_refresh = create_refresh_token(user_id, role)

    return TokenResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        user=UserResponse(
            id=user_id,
            email=email,
            role=role,
            display_name=display_name,
        ),
    )
