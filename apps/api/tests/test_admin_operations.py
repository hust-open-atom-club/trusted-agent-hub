"""供给侧管理操作测试 — yank/unyank/re-review/grade-override/grade-history。

使用真实 PostgreSQL，沿用 test_review_integration.py 模式：
真实注册用户（DB 直改角色）+ 注入 mock 扫描报告 + 状态流转断言。
所有测试创建的版本/用户测试结束后自动删除。
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from src.main import create_app
from src.settings import get_settings

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
with open(os.path.join(FIXTURES, "scan_clean.json"), encoding="utf-8") as f:
    SCAN_CLEAN = json.load(f)

_CLEANUP_IDS: list[str] = []
_TEST_USER_IDS: list[str] = []


# ── Helpers ───────────────────────────────────────────────


def _random_email(prefix: str = "ops") -> str:
    return f"ops-{prefix}-{uuid.uuid4().hex[:8]}@example.com"


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


def _db_query_row(sql: str, params: tuple = ()) -> str | None:
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
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row[0] if row is not None else None


def _register(client: TestClient, email: str, password: str = "Test123456") -> dict:
    resp = client.post("/api/v0/auth/register", json={
        "email": email,
        "password": password,
        "display_name": "OpsTester",
    })
    assert resp.status_code == 201, f"Register failed: {resp.text}"
    data = resp.json()
    _TEST_USER_IDS.append(data["user"]["id"])
    return data


def _login(client: TestClient, email: str, password: str = "Test123456") -> dict:
    resp = client.post("/api/v0/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.json()


def _register_and_login_as(client: TestClient, role: str) -> str:
    """注册用户 → DB 改角色 → 登录，返回 access_token。"""
    email = _random_email(role)
    user = _register(client, email)
    _db_execute("UPDATE users SET role = %s WHERE id = %s", (role, user["user"]["id"]))
    return _login(client, email)["access_token"]


def _create_package(client: TestClient, token: str, name: str) -> dict:
    resp = client.post(
        "/api/v0/producer/packages",
        json={
            "name": name,
            "type": "skill",
            "description": "Ops test package",
            "license": "MIT",
            "keywords": ["test"],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201, f"Create package failed: {resp.text}"
    return resp.json()


def _create_version(client: TestClient, token: str, package_id: str) -> dict:
    resp = client.post(
        f"/api/v0/producer/packages/{package_id}/versions",
        json={"version": "1.0.0", "repo_url": f"https://github.com/test/{package_id}"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201, f"Create version failed: {resp.text}"
    return resp.json()


def _simulate_scan_complete(version_id: str) -> None:
    """注入干净扫描报告并把版本推到 pending_review（模拟 handle_scan_complete）。

    与 test_review_integration.py 的 _simulate_scan_complete 一致：
    - 注入 scan_reports；
    - 补全安装资料（source/integrity/permissions/installation）；
    - 同时更新 status 列和 data JSON 中的 status（review/publish 从 data 读取）。
    """
    import psycopg2
    from urllib.parse import urlparse

    settings = get_settings()
    url = urlparse(settings.database_url)
    conn = psycopg2.connect(
        host=url.hostname, port=url.port or 5432,
        dbname=url.path.lstrip("/"), user=url.username, password=url.password,
    )
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scan_reports (version_id, scan_json, report_path, scanned_at) "
        "VALUES (%s, %s, %s, %s) ON CONFLICT (version_id) DO UPDATE SET scan_json = EXCLUDED.scan_json",
        (version_id, json.dumps(SCAN_CLEAN), "test/fixture.json", datetime.now(timezone.utc)),
    )
    cur.execute("SELECT data FROM package_versions WHERE id = %s", (version_id,))
    row = cur.fetchone()
    data = dict(row[0]) if row and row[0] else {}

    pkg_name = SCAN_CLEAN.get("package_name", "test-package")
    pkg_version = SCAN_CLEAN.get("version", "1.0.0")
    commit_hash = "a" * 40
    zip_name = f"{pkg_name}-{pkg_version}-{commit_hash[:8]}.zip"
    download_url = f"/api/v0/artifacts/{zip_name}"

    source = dict(data.get("source") or {})
    source["download_url"] = download_url
    source["commit_hash"] = commit_hash
    data["source"] = source
    data["integrity"] = {"sha256": "a" * 64, "download_size_bytes": 1024}
    if not data.get("permissions"):
        data["permissions"] = {
            "filesystem": {"read": [], "write": [], "delete": False},
            "shell": {"allowed": False},
            "network": {"allowed": False},
        }

    compat = data.get("compatibility") or ["claude-code"]
    if not compat:
        compat = ["claude-code"]
    target_client = compat[0]
    data["compatibility"] = compat
    data["installation"] = {
        "method": "copy_directory",
        "target_client": target_client,
        "steps": [
            {"action": "download", "url": download_url},
            {"action": "verify", "algorithm": "sha256", "checksum": "a" * 64},
            {"action": "extract"},
            {"action": "copy", "client": target_client,
             "destination": f"~/.claude/skills/{pkg_name}/"},
        ],
    }
    data["status"] = "pending_review"
    cur.execute(
        "UPDATE package_versions SET status = 'pending_review', data = %s WHERE id = %s",
        (json.dumps(data), version_id),
    )
    conn.commit()
    cur.close()
    conn.close()


def _approve_and_publish(client: TestClient, rtoken: str, atoken: str, version_id: str) -> None:
    resp = client.post(
        f"/api/v0/producer/versions/{version_id}/reviews",
        json={"conclusion": "approved", "comment": "OK"},
        headers={"Authorization": f"Bearer {rtoken}"},
    )
    assert resp.status_code == 201, f"Approve failed: {resp.text}"
    resp = client.post(
        f"/api/v0/producer/versions/{version_id}/publish",
        headers={"Authorization": f"Bearer {atoken}"},
    )
    assert resp.status_code == 200, f"Publish failed: {resp.text}"
    assert resp.json()["new_status"] == "published"


# ── Cleanup ───────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _cleanup_test_ids():
    """测试结束删除本文件创建的版本/包/用户。"""
    _CLEANUP_IDS.clear()
    _TEST_USER_IDS.clear()
    yield
    if _CLEANUP_IDS or _TEST_USER_IDS:
        for vid in reversed(_CLEANUP_IDS):
            try:
                pkg_id = _db_query_row("SELECT package_id FROM package_versions WHERE id = %s", (vid,))
                if pkg_id:
                    _db_execute("DELETE FROM scan_reports WHERE version_id = %s", (vid,))
                    _db_execute("DELETE FROM review_records WHERE version_id = %s", (vid,))
                    _db_execute("DELETE FROM audit_logs WHERE target_id = %s", (vid,))
                    _db_execute("DELETE FROM package_versions WHERE id = %s", (vid,))
                    _db_execute("DELETE FROM packages WHERE id = %s", (pkg_id,))
            except Exception:
                pass
        for uid in reversed(_TEST_USER_IDS):
            try:
                _db_execute("DELETE FROM users WHERE id = %s", (uid,))
            except Exception:
                pass


def _needs_db() -> None:
    if not get_settings().database_url:
        pytest.skip("DATABASE_URL not configured")


# ═══════════════════════════════════════════════════════════
# 下架 / 恢复 / 重新审核
# ═══════════════════════════════════════════════════════════

class TestYankUnyankReReview:

    def _make_published_version(self, client: TestClient):
        """公共准备：submitter 提交包 → reviewer 通过 → admin 发布。"""
        stoken = _register_and_login_as(client, "submitter")
        rtoken = _register_and_login_as(client, "reviewer")
        atoken = _register_and_login_as(client, "admin")

        pkg = _create_package(client, stoken, f"ops-yank-{uuid.uuid4().hex[:6]}")
        ver = _create_version(client, stoken, pkg["id"])
        _CLEANUP_IDS.append(ver["id"])

        _simulate_scan_complete(ver["id"])
        _approve_and_publish(client, rtoken, atoken, ver["id"])
        return ver["id"]

    def test_yank_published_version(self):
        """管理员下架已发布版本：published → yanked，审计日志写入。"""
        _needs_db()
        client = _get_client()
        vid = self._make_published_version(client)
        atoken = _register_and_login_as(client, "admin")

        resp = client.post(
            f"/api/v0/producer/versions/{vid}/yank?reason=Security issue",
            headers={"Authorization": f"Bearer {atoken}"},
        )
        assert resp.status_code == 200, f"Yank failed: {resp.text}"
        assert resp.json()["new_status"] == "yanked"

        # 数据库状态确认
        assert _db_query_row("SELECT status FROM package_versions WHERE id = %s", (vid,)) == "yanked"
        # 审计日志确认
        assert _db_query_row(
            "SELECT COUNT(*) FROM audit_logs WHERE target_id = %s AND action = 'yank'", (vid,)
        ) == 1

    def test_yank_requires_admin(self):
        """非 admin（reviewer）调用 yank：403。"""
        _needs_db()
        client = _get_client()
        vid = self._make_published_version(client)
        rtoken = _register_and_login_as(client, "reviewer")

        resp = client.post(
            f"/api/v0/producer/versions/{vid}/yank",
            headers={"Authorization": f"Bearer {rtoken}"},
        )
        assert resp.status_code == 403

    def test_unyank_restores_published(self):
        """撤销下架：yanked → published。"""
        _needs_db()
        client = _get_client()
        vid = self._make_published_version(client)
        atoken = _register_and_login_as(client, "admin")

        client.post(
            f"/api/v0/producer/versions/{vid}/yank",
            headers={"Authorization": f"Bearer {atoken}"},
        )
        resp = client.post(
            f"/api/v0/producer/versions/{vid}/unyank",
            headers={"Authorization": f"Bearer {atoken}"},
        )
        assert resp.status_code == 200, f"Unyank failed: {resp.text}"
        assert resp.json()["new_status"] == "published"
        assert _db_query_row("SELECT status FROM package_versions WHERE id = %s", (vid,)) == "published"

    def test_re_review_returns_to_queue(self):
        """管理员退回审核：published → pending_review。"""
        _needs_db()
        client = _get_client()
        vid = self._make_published_version(client)
        atoken = _register_and_login_as(client, "admin")

        resp = client.post(
            f"/api/v0/producer/versions/{vid}/re-review",
            headers={"Authorization": f"Bearer {atoken}"},
        )
        assert resp.status_code == 200, f"Re-review failed: {resp.text}"
        assert resp.json()["new_status"] == "pending_review"
        assert _db_query_row("SELECT status FROM package_versions WHERE id = %s", (vid,)) == "pending_review"


# ═══════════════════════════════════════════════════════════
# 手动评级覆盖 / 评级历史
# ═══════════════════════════════════════════════════════════

class TestGradeOverride:

    def _make_version(self, client: TestClient):
        """公共准备：submitter 创建包+版本（无需扫描即可评级）。"""
        stoken = _register_and_login_as(client, "submitter")
        pkg = _create_package(client, stoken, f"ops-grade-{uuid.uuid4().hex[:6]}")
        ver = _create_version(client, stoken, pkg["id"])
        _CLEANUP_IDS.append(ver["id"])
        return ver["id"]

    def test_set_manual_grade(self):
        """reviewer 手动评级 A：返回 manual_grade=A，数据库落盘。"""
        _needs_db()
        client = _get_client()
        vid = self._make_version(client)
        rtoken = _register_and_login_as(client, "reviewer")

        resp = client.patch(
            f"/api/v0/producer/versions/{vid}/grade",
            json={"grade": "A", "reason": "高质量实现"},
            headers={"Authorization": f"Bearer {rtoken}"},
        )
        assert resp.status_code == 200, f"Grade failed: {resp.text}"
        assert resp.json()["manual_grade"] == "A"
        assert resp.json()["effective_grade"] == "A"

        # 审计日志确认
        assert _db_query_row(
            "SELECT COUNT(*) FROM audit_logs WHERE target_id = %s AND action = 'grade_override'", (vid,)
        ) == 1

    def test_clear_manual_grade(self):
        """grade=null 清除人工评级，恢复自动评分。"""
        _needs_db()
        client = _get_client()
        vid = self._make_version(client)
        rtoken = _register_and_login_as(client, "reviewer")

        client.patch(
            f"/api/v0/producer/versions/{vid}/grade",
            json={"grade": "B", "reason": "初评"},
            headers={"Authorization": f"Bearer {rtoken}"},
        )
        resp = client.patch(
            f"/api/v0/producer/versions/{vid}/grade",
            json={"grade": None, "reason": "恢复自动"},
            headers={"Authorization": f"Bearer {rtoken}"},
        )
        assert resp.status_code == 200, f"Clear grade failed: {resp.text}"
        assert resp.json()["manual_grade"] is None

    def test_invalid_grade_rejected(self):
        """非法评级 X：400。"""
        _needs_db()
        client = _get_client()
        vid = self._make_version(client)
        rtoken = _register_and_login_as(client, "reviewer")

        resp = client.patch(
            f"/api/v0/producer/versions/{vid}/grade",
            json={"grade": "X", "reason": "测试非法值"},
            headers={"Authorization": f"Bearer {rtoken}"},
        )
        assert resp.status_code == 400

    def test_empty_reason_rejected(self):
        """评级理由为空：400。"""
        _needs_db()
        client = _get_client()
        vid = self._make_version(client)
        rtoken = _register_and_login_as(client, "reviewer")

        resp = client.patch(
            f"/api/v0/producer/versions/{vid}/grade",
            json={"grade": "A", "reason": "  "},
            headers={"Authorization": f"Bearer {rtoken}"},
        )
        assert resp.status_code == 400

    def test_grade_requires_reviewer(self):
        """submitter 调用评级接口：403。"""
        _needs_db()
        client = _get_client()
        vid = self._make_version(client)
        stoken = _register_and_login_as(client, "submitter")

        resp = client.patch(
            f"/api/v0/producer/versions/{vid}/grade",
            json={"grade": "A", "reason": "越权"},
            headers={"Authorization": f"Bearer {stoken}"},
        )
        assert resp.status_code == 403

    def test_grade_history_tracks_changes(self):
        """评级历史：两次修改后 history 返回两条，含前后值。"""
        _needs_db()
        client = _get_client()
        vid = self._make_version(client)
        rtoken = _register_and_login_as(client, "reviewer")

        client.patch(
            f"/api/v0/producer/versions/{vid}/grade",
            json={"grade": "B", "reason": "初评 B"},
            headers={"Authorization": f"Bearer {rtoken}"},
        )
        client.patch(
            f"/api/v0/producer/versions/{vid}/grade",
            json={"grade": "A", "reason": "复审升 A"},
            headers={"Authorization": f"Bearer {rtoken}"},
        )

        resp = client.get(
            f"/api/v0/producer/versions/{vid}/grade-history",
            headers={"Authorization": f"Bearer {rtoken}"},
        )
        assert resp.status_code == 200
        history = resp.json()
        assert len(history) >= 2
        # 历史中应存在一次 B→A 的修改记录（previous=B, new=A）
        # 注：audit 按时间戳降序，同秒记录顺序不保证，故用存在性断言
        assert any(
            h.get("previous_grade") == "B" and h.get("grade") == "A"
            for h in history
        ), f"历史中未找到 B→A 记录: {history}"
