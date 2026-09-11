"""认证 HTTP 路由 — 注册、登录、Token 刷新。

端点:
    POST /auth/register — 注册新用户（邮箱+密码+昵称）
    POST /auth/login    — 登录（邮箱+密码），返回 access + refresh token
    GET  /auth/me       — 获取当前用户资料
    PATCH /auth/me      — 修改当前用户昵称
    POST /auth/change-password — 修改当前用户密码
    POST /auth/refresh  — CLI 刷新（body refresh token）
    POST /auth/refresh/browser — 浏览器刷新（HttpOnly Cookie）
    POST /auth/logout   — 撤销当前 refresh token 并清除浏览器 Cookie
"""

from __future__ import annotations

from datetime import datetime, timezone
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from src.auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    needs_password_rehash,
    verify_password,
)
from src.database import create_session_factory, get_runtime_engine
from src.dependencies import BearerTokenInvalid, CurrentUser, get_current_user
from src.models.common import StrictContractModel
from src.repositories.orm_producer import RefreshTokenRow, UserRow
from src.settings import get_settings
from src.sql import CLEANUP_REFRESH_TOKENS_SQL

router = APIRouter(prefix="/api/v0/auth", tags=["auth"])

_REFRESH_COOKIE_NAME = "tah_refresh_token"
_REFRESH_COOKIE_PATH = "/api/v0/auth"
_REFRESH_COOKIE_MAX_AGE = 3 * 60 * 60


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


class BrowserTokenResponse(BaseModel):
    """Browser response; refresh token is delivered only via HttpOnly Cookie."""

    access_token: str
    token_type: str = "bearer"
    user: UserResponse | None = None


AuthTokenResponse = TokenResponse | BrowserTokenResponse


class RefreshRequest(BaseModel):
    refresh_token: str | None = None


class ProfileUpdateRequest(StrictContractModel):
    display_name: str = Field(min_length=1, max_length=64)


class ChangePasswordRequest(StrictContractModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=6, max_length=128)


# ── 仓库辅助 ──────────────────────────────────────────────


def _get_session() -> Session:
    settings = get_settings()
    if settings.database_url is None:
        raise HTTPException(status_code=503, detail="DATABASE_URL 未配置")
    engine = get_runtime_engine(settings.database_url)
    return create_session_factory(engine)()


def _email_prefix(email: str) -> str:
    return email.split("@")[0][:64]


def _user_response(user: UserRow) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        role=user.role,
        display_name=user.display_name,
    )


def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    """Keep the browser refresh token out of JavaScript-readable storage."""
    settings = get_settings()
    secure = bool(
        settings.public_api_base_url
        and settings.public_api_base_url.startswith("https://")
    )
    response.set_cookie(
        key=_REFRESH_COOKIE_NAME,
        value=refresh_token,
        max_age=_REFRESH_COOKIE_MAX_AGE,
        httponly=True,
        secure=secure,
        samesite="lax",
        path=_REFRESH_COOKIE_PATH,
    )


def _cleanup_refresh_tokens(session: Session) -> None:
    """Bound refresh-token state during normal token issuance.

    Used tokens can be removed immediately and expired tokens are no longer
    needed for validation because JWT expiry is checked before the lookup.
    The indexed timestamp columns keep this maintenance bounded by the
    eligible rows instead of retaining every historical session forever.
    """
    # The application session factory intentionally disables autoflush. Flush
    # first so a just-consumed token is visible to the shared cleanup SQL.
    session.flush()
    session.execute(text(CLEANUP_REFRESH_TOKENS_SQL))


def _token_response(session: Session, user: UserRow) -> TokenResponse:
    refresh_jti = uuid.uuid4().hex
    access = create_access_token(
        user.id,
        user.role,
        email=user.email,
        display_name=user.display_name,
        auth_version=user.auth_version,
    )
    refresh = create_refresh_token(
        user.id,
        user.role,
        auth_version=user.auth_version,
        jti=refresh_jti,
    )
    refresh_payload = decode_token(refresh)
    _cleanup_refresh_tokens(session)
    session.add(
        RefreshTokenRow(
            jti=refresh_jti,
            user_id=user.id,
            expires_at=datetime.fromtimestamp(
                int(refresh_payload["exp"]), tz=timezone.utc
            ),
        )
    )
    session.commit()
    return TokenResponse(
        access_token=access,
        refresh_token=refresh,
        token_type="bearer",
        user=_user_response(user),
    )


def _response_for_client(
    token_response: TokenResponse,
    browser_client: bool,
) -> AuthTokenResponse:
    if not browser_client:
        return token_response
    return BrowserTokenResponse(
        access_token=token_response.access_token,
        token_type=token_response.token_type,
        user=token_response.user,
    )


def _load_active_user(session: Session, user_id: str) -> UserRow:
    user = session.scalar(select(UserRow).where(UserRow.id == user_id))
    if user is None:
        raise HTTPException(status_code=401, detail="用户不存在")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="该账号已被禁用，请联系管理员")
    return user


# ── POST /auth/register ───────────────────────────────────


@router.post("/register", status_code=201, response_model=AuthTokenResponse)
def register(
    body: RegisterRequest,
    response: Response,
    browser_client: bool = Header(default=False, alias="X-TAH-Browser"),
) -> AuthTokenResponse:
    """注册新用户。邮箱为登录凭证，昵称默认取邮箱前缀，角色默认 submitter。"""
    session = _get_session()
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
        session.flush()

        token_response = _token_response(session, user)
        _set_refresh_cookie(response, token_response.refresh_token)
        return _response_for_client(token_response, browser_client)
    finally:
        session.close()


# ── POST /auth/login ──────────────────────────────────────


@router.post("/login", response_model=AuthTokenResponse)
def login(
    body: LoginRequest,
    response: Response,
    browser_client: bool = Header(default=False, alias="X-TAH-Browser"),
) -> AuthTokenResponse:
    """登录（邮箱+密码），返回 30 分钟 access token 和 3 小时 refresh token。"""
    session = _get_session()
    email = body.email.lower().strip()

    try:
        user = session.scalar(
            select(UserRow).where(UserRow.email == email)
        )
        if user is None or not verify_password(body.password, user.password_hash):
            raise HTTPException(status_code=401, detail="邮箱或密码错误")

        # Seamlessly upgrade legacy bcrypt hashes after a successful login.
        if needs_password_rehash(user.password_hash):
            user.password_hash = hash_password(body.password)
            session.commit()

        if not user.is_active:
            raise HTTPException(status_code=403, detail="该账号已被禁用，请联系管理员")

        token_response = _token_response(session, user)
        _set_refresh_cookie(response, token_response.refresh_token)
        return _response_for_client(token_response, browser_client)
    finally:
        session.close()


# ── GET/PATCH /auth/me ─────────────────────────────────────


@router.get("/me", response_model=UserResponse)
def get_me(current_user: CurrentUser = Depends(get_current_user)) -> UserResponse:
    """返回当前登录用户的最新资料。"""
    session = _get_session()
    try:
        return _user_response(_load_active_user(session, current_user.id))
    finally:
        session.close()


@router.patch("/me", response_model=UserResponse)
def update_me(
    body: ProfileUpdateRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> UserResponse:
    """修改当前用户可编辑的资料；邮箱、角色和状态不可自助修改。"""
    display_name = body.display_name.strip()
    if not display_name:
        raise HTTPException(status_code=422, detail="昵称不能为空")

    session = _get_session()
    try:
        user = _load_active_user(session, current_user.id)
        user.display_name = display_name
        session.commit()
        return _user_response(user)
    finally:
        session.close()


# ── POST /auth/change-password ─────────────────────────────


@router.post("/change-password", response_model=AuthTokenResponse)
def change_password(
    body: ChangePasswordRequest,
    response: Response,
    browser_client: bool = Header(default=False, alias="X-TAH-Browser"),
    current_user: CurrentUser = Depends(get_current_user),
) -> AuthTokenResponse:
    """修改当前用户密码，并使修改前签发的 Token 全部失效。"""
    session = _get_session()
    try:
        user = _load_active_user(session, current_user.id)
        if not verify_password(body.current_password, user.password_hash):
            raise HTTPException(status_code=400, detail="当前密码错误")
        if verify_password(body.new_password, user.password_hash):
            raise HTTPException(status_code=400, detail="新密码不能与当前密码相同")

        user.password_hash = hash_password(body.new_password)
        user.auth_version += 1
        token_response = _token_response(session, user)
        _set_refresh_cookie(response, token_response.refresh_token)
        return _response_for_client(token_response, browser_client)
    finally:
        session.close()


def _rotate_refresh_token(refresh_token: str) -> TokenResponse:
    """Consume one stored refresh token and issue its replacement."""
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token 缺失")

    try:
        payload = decode_token(refresh_token, verify_exp=False)
    except BearerTokenInvalid:
        raise HTTPException(status_code=401, detail="Refresh token 无效")

    import time
    try:
        expires_at = int(payload.get("exp", 0))
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Refresh token 无效") from None
    if time.time() >= expires_at:
        raise HTTPException(status_code=401, detail="Refresh token 已过期，请重新登录")

    if payload.get("token_type") != "refresh":
        raise HTTPException(status_code=401, detail="Refresh token 类型无效")
    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        raise HTTPException(status_code=401, detail="Refresh token 无效")

    user_id = payload.get("sub")
    if not isinstance(user_id, str) or not user_id:
        raise HTTPException(status_code=401, detail="Refresh token 无效")
    try:
        auth_version = int(payload.get("auth_version", 0))
    except (TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Refresh token 无效") from None

    session = _get_session()
    try:
        user = _load_active_user(session, user_id)
        if user.auth_version != auth_version:
            raise HTTPException(status_code=401, detail="Refresh token 已失效")
        stored_token = session.scalar(
            select(RefreshTokenRow)
            .where(RefreshTokenRow.jti == jti)
            .with_for_update()
        )
        if (
            stored_token is None
            or stored_token.user_id != user.id
            or stored_token.used_at is not None
        ):
            raise HTTPException(status_code=401, detail="Refresh token 已使用或无效")
        stored_token.used_at = datetime.now(timezone.utc)
        return _token_response(session, user)
    finally:
        session.close()


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: RefreshRequest | None = None) -> TokenResponse:
    """CLI refresh contract: the token must be supplied in the request body.

    This endpoint deliberately never reads the browser cookie and never
    changes it. Browser clients must use ``/refresh/browser`` instead.
    """
    if body is None or not body.refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token 缺失")
    return _rotate_refresh_token(body.refresh_token)


@router.post("/refresh/browser", response_model=BrowserTokenResponse)
def refresh_browser(request: Request, response: Response) -> BrowserTokenResponse:
    """Browser refresh contract: accept only the HttpOnly refresh cookie."""
    refresh_token = request.cookies.get(_REFRESH_COOKIE_NAME)
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Refresh token 缺失")

    token_response = _rotate_refresh_token(refresh_token)
    _set_refresh_cookie(response, token_response.refresh_token)
    return BrowserTokenResponse(
        access_token=token_response.access_token,
        token_type=token_response.token_type,
        user=token_response.user,
    )


@router.post("/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    body: RefreshRequest | None = None,
) -> None:
    """Revoke the presented refresh token and clear the browser cookie.

    Browser clients normally authenticate this request with the HttpOnly
    cookie.  Body-based tokens remain supported for CLI clients, and logout
    stays idempotent for missing or already-invalid tokens.
    """
    refresh_token = (
        (body.refresh_token if body is not None else None)
        or request.cookies.get(_REFRESH_COOKIE_NAME)
    )

    if refresh_token:
        try:
            payload = decode_token(refresh_token, verify_exp=False)
        except BearerTokenInvalid:
            payload = None

        jti = payload.get("jti") if payload else None
        user_id = payload.get("sub") if payload else None
        if (
            payload is not None
            and payload.get("token_type") == "refresh"
            and isinstance(jti, str)
            and bool(jti)
            and isinstance(user_id, str)
            and bool(user_id)
        ):
            session = _get_session()
            try:
                stored_token = session.scalar(
                    select(RefreshTokenRow)
                    .where(
                        RefreshTokenRow.jti == jti,
                        RefreshTokenRow.user_id == user_id,
                    )
                    .with_for_update()
                )
                if stored_token is not None and stored_token.used_at is None:
                    stored_token.used_at = datetime.now(timezone.utc)
                    session.commit()
            finally:
                session.close()

    response.delete_cookie(
        key=_REFRESH_COOKIE_NAME,
        path=_REFRESH_COOKIE_PATH,
    )
