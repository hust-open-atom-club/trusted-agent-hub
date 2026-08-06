"""认证与鉴权测试 — 注册/登录/刷新、JWT 过期/伪造、角色层级访问控制。

使用真实 PostgreSQL + 真实 JWT 签发（与 test_review_integration.py 同模式）。
所有测试注册的用户在测试结束后自动删除，避免账号累积。
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from jose import jwt as jose_jwt

from src.main import create_app
from src.settings import get_settings

_TEST_USER_IDS: list[str] = []


# ── Helpers ───────────────────────────────────────────────


def _random_email(prefix: str = "auth") -> str:
    return f"auth-{prefix}-{uuid.uuid4().hex[:8]}@example.com"


def _get_client() -> TestClient:
    from src.auth import install as install_auth

    install_auth()
    app = create_app()
    return TestClient(app)


def _db_execute(sql: str, params: tuple = ()) -> None:
    import psycopg2
    from urllib.parse import urlparse

    settings = get_settings()
    url = urlparse(settings.database_url)
    conn = psycopg2.connect(
        host=url.hostname, port=url.port or 5432,
        dbname=url.path.lstrip("/"), user=url.username, password=url.password,
    )
    cur = conn.cursor()
    cur.execute(sql, params)
    conn.commit()
    cur.close()
    conn.close()


def _register(client: TestClient, email: str, password: str = "Test123456") -> dict:
    resp = client.post("/api/v0/auth/register", json={
        "email": email,
        "password": password,
        "display_name": "AuthTester",
    })
    assert resp.status_code == 201, f"Register failed: {resp.text}"
    data = resp.json()
    _TEST_USER_IDS.append(data["user"]["id"])
    return data


def _login(client: TestClient, email: str, password: str = "Test123456") -> dict:
    resp = client.post("/api/v0/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.json()


def _register_as(client: TestClient, role: str) -> dict:
    """注册用户并通过 DB 直改角色，返回登录后的 token 响应。"""
    email = _random_email(role)
    data = _register(client, email)
    _db_execute("UPDATE users SET role = %s WHERE id = %s", (role, data["user"]["id"]))
    return _login(client, email)


def _make_token(payload: dict, secret: str | None = None) -> str:
    """用指定密钥签发 JWT；secret 为 None 时使用真实密钥（用于过期 token）。"""
    from src.auth import _ALGORITHM, _get_jwt_secret

    return jose_jwt.encode(payload, secret or _get_jwt_secret(), algorithm=_ALGORITHM)


# ── Cleanup ───────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _cleanup_test_users():
    """测试结束删除本文件注册的所有测试用户。"""
    _TEST_USER_IDS.clear()
    yield
    if _TEST_USER_IDS:
        for uid in _TEST_USER_IDS:
            try:
                _db_execute("DELETE FROM users WHERE id = %s", (uid,))
            except Exception:
                pass


def _needs_db() -> None:
    if not get_settings().database_url:
        pytest.skip("DATABASE_URL not configured")


# ═══════════════════════════════════════════════════════════
# 注册 / 登录 / 刷新
# ═══════════════════════════════════════════════════════════

class TestRegisterLoginRefresh:

    def test_register_success(self):
        """正常注册：201，返回 access/refresh token 与用户信息，默认角色 submitter。"""
        _needs_db()
        client = _get_client()

        data = _register(client, _random_email("ok"))
        assert data["access_token"]
        assert data["refresh_token"]
        assert data["user"]["role"] == "submitter"
        assert data["user"]["email"].endswith("@example.com")

    def test_register_duplicate_email(self):
        """重复邮箱注册：409。"""
        _needs_db()
        client = _get_client()

        email = _random_email("dup")
        _register(client, email)
        resp = client.post("/api/v0/auth/register", json={
            "email": email,
            "password": "Test123456",
            "display_name": "Dup",
        })
        assert resp.status_code == 409

    def test_login_success(self):
        """正确密码登录：200，返回 token 对。"""
        _needs_db()
        client = _get_client()

        email = _random_email("login")
        _register(client, email)
        data = _login(client, email)
        assert data["access_token"]
        assert data["refresh_token"]

    def test_login_wrong_password(self):
        """错误密码登录：401。"""
        _needs_db()
        client = _get_client()

        email = _random_email("wrong")
        _register(client, email)
        resp = client.post("/api/v0/auth/login", json={"email": email, "password": "WrongPass123"})
        assert resp.status_code == 401

    def test_login_disabled_user(self):
        """禁用账号登录：403。"""
        _needs_db()
        client = _get_client()

        email = _random_email("disabled")
        data = _register(client, email)
        _db_execute("UPDATE users SET is_active = false WHERE id = %s", (data["user"]["id"],))
        resp = client.post("/api/v0/auth/login", json={"email": email, "password": "Test123456"})
        assert resp.status_code == 403

    def test_refresh_rotates_tokens(self):
        """refresh 换发新 access + 新 refresh（rotation）。"""
        _needs_db()
        client = _get_client()

        data = _register(client, _random_email("refresh"))
        resp = client.post("/api/v0/auth/refresh", json={"refresh_token": data["refresh_token"]})
        assert resp.status_code == 200, f"Refresh failed: {resp.text}"
        new = resp.json()
        assert new["access_token"]
        assert new["refresh_token"]

        # 新 access token 可正常访问受保护端点（refresh 产出的凭证有效）
        resp = client.get(
            "/api/v0/producer/audit-logs",
            headers={"Authorization": f"Bearer {new['access_token']}"},
        )
        # submitter 角色能过鉴权但无 reviewer 权限 → 403（而非 401），证明 token 有效
        assert resp.status_code == 403

    def test_refresh_rejects_expired_token(self):
        """过期 refresh token：401。"""
        _needs_db()
        client = _get_client()

        data = _register(client, _random_email("refexp"))
        expired = _make_token({
            "sub": data["user"]["id"],
            "role": "submitter",
            "exp": int(time.time()) - 3600,
        })
        resp = client.post("/api/v0/auth/refresh", json={"refresh_token": expired})
        assert resp.status_code == 401

    def test_refresh_rejects_forged_token(self):
        """伪造签名 refresh token：401。"""
        _needs_db()
        client = _get_client()

        forged = _make_token({
            "sub": "user-unknown",
            "role": "admin",
            "exp": int(time.time()) + 3600,
        }, secret="attacker-secret")
        resp = client.post("/api/v0/auth/refresh", json={"refresh_token": forged})
        assert resp.status_code == 401


# ═══════════════════════════════════════════════════════════
# JWT 过期 / 伪造
# ═══════════════════════════════════════════════════════════

class TestJwtValidation:

    _PROTECTED = "/api/v0/producer/packages"

    def test_expired_access_token_rejected(self):
        """过期 access token 访问受保护端点：401。"""
        _needs_db()
        client = _get_client()

        data = _register(client, _random_email("exp"))
        expired = _make_token({
            "sub": data["user"]["id"],
            "role": "submitter",
            "exp": int(time.time()) - 60,
        })
        resp = client.get(
            self._PROTECTED,
            headers={"Authorization": f"Bearer {expired}"},
        )
        assert resp.status_code == 401

    def test_forged_signature_rejected(self):
        """伪造签名 token：401。"""
        _needs_db()
        client = _get_client()

        forged = _make_token({
            "sub": "user-forged",
            "role": "admin",
            "exp": int(time.time()) + 3600,
        }, secret="wrong-secret")
        resp = client.get(
            self._PROTECTED,
            headers={"Authorization": f"Bearer {forged}"},
        )
        assert resp.status_code == 401

    def test_missing_token_rejected(self):
        """无 token 访问受保护端点：401。"""
        _needs_db()
        client = _get_client()

        resp = client.get(self._PROTECTED)
        assert resp.status_code == 401

    def test_valid_token_accepted(self):
        """真实 token 正常放行（基线对照）。"""
        _needs_db()
        client = _get_client()

        data = _register(client, _random_email("valid"))
        # GET /packages/{id} 是 submitter+ 可访问的端点：
        # 能通过鉴权（非 401）即证明 token 有效；包不存在返回 404
        resp = client.get(
            "/api/v0/producer/packages/ver-nonexistent",
            headers={"Authorization": f"Bearer {data['access_token']}"},
        )
        assert resp.status_code == 404


# ═══════════════════════════════════════════════════════════
# 角色层级访问控制：admin(0) > reviewer(1) > submitter(2) > user(3)
# ═══════════════════════════════════════════════════════════

class TestRoleHierarchy:

    def test_admin_can_access_admin_endpoint(self):
        """admin 可调用 yank（admin-only）。"""
        _needs_db()
        client = _get_client()

        data = _register_as(client, "admin")
        # 用不存在的版本号调用，能走到业务层（400 版本不存在）即证明权限通过
        resp = client.post(
            "/api/v0/producer/versions/ver-nonexistent/yank",
            headers={"Authorization": f"Bearer {data['access_token']}"},
        )
        assert resp.status_code == 400

    def test_reviewer_cannot_access_admin_endpoint(self):
        """reviewer 调用 admin-only 的 yank：403。"""
        _needs_db()
        client = _get_client()

        data = _register_as(client, "reviewer")
        resp = client.post(
            "/api/v0/producer/versions/ver-nonexistent/yank",
            headers={"Authorization": f"Bearer {data['access_token']}"},
        )
        assert resp.status_code == 403

    def test_submitter_cannot_access_reviewer_endpoint(self):
        """submitter 调用 reviewer+ 的 audit-logs：403。"""
        _needs_db()
        client = _get_client()

        data = _register_as(client, "submitter")
        resp = client.get(
            "/api/v0/producer/audit-logs",
            headers={"Authorization": f"Bearer {data['access_token']}"},
        )
        assert resp.status_code == 403

    def test_user_cannot_access_submitter_endpoint(self):
        """user 调用 submitter+ 的包列表：403。"""
        _needs_db()
        client = _get_client()

        data = _register_as(client, "user")
        resp = client.get(
            "/api/v0/producer/packages",
            headers={"Authorization": f"Bearer {data['access_token']}"},
        )
        assert resp.status_code == 403

    def test_reviewer_can_access_reviewer_endpoint(self):
        """reviewer 可调用 audit-logs（reviewer+）：200。"""
        _needs_db()
        client = _get_client()

        data = _register_as(client, "reviewer")
        resp = client.get(
            "/api/v0/producer/audit-logs",
            headers={"Authorization": f"Bearer {data['access_token']}"},
        )
        assert resp.status_code == 200

    def test_submitter_can_access_submitter_endpoint(self):
        """submitter 可调用包详情（submitter+）：404（过鉴权但包不存在）。"""
        _needs_db()
        client = _get_client()

        data = _register_as(client, "submitter")
        resp = client.get(
            "/api/v0/producer/packages/ver-nonexistent",
            headers={"Authorization": f"Bearer {data['access_token']}"},
        )
        assert resp.status_code == 404

    def test_admin_can_access_reviewer_endpoint(self):
        """admin 向下兼容：可调用 reviewer+ 端点（200）。"""
        _needs_db()
        client = _get_client()

        data = _register_as(client, "admin")
        resp = client.get(
            "/api/v0/producer/audit-logs",
            headers={"Authorization": f"Bearer {data['access_token']}"},
        )
        assert resp.status_code == 200
