"""Audit flow integration tests: submit → scan → review → publish → yank.

Uses real PostgreSQL database with unique test data.
Scanner is mocked by injecting scan reports directly into DB.
"""

import json
import os
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from src.main import create_app
from src.settings import get_settings

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

with open(os.path.join(FIXTURES, "scan_clean.json")) as f:
    SCAN_CLEAN = json.load(f)
with open(os.path.join(FIXTURES, "scan_risky.json")) as f:
    SCAN_RISKY = json.load(f)


@pytest.fixture(autouse=True)
def _mock_artifact_build(monkeypatch):
    """Integration tests must never hit real git/network for artifact packaging."""

    def _fake_build_artifact(*, repo_url, commit_hash, package_name, version, local_source_dir=None):
        zip_name = f"{package_name}-{version}-{commit_hash[:8]}.zip"
        return {
            # 消费侧 install-manifest 校验要求 https 或 localhost http 地址
            "download_url": f"http://127.0.0.1:8000/api/v0/artifacts/{zip_name}",
            "sha256": "a" * 64,
            "download_size_bytes": 1024,
        }

    monkeypatch.setattr("src.services.artifacts.build_artifact", _fake_build_artifact)


def _random_email(prefix: str = "test") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


def _get_client() -> TestClient:
    from src.auth import install as install_auth
    install_auth()
    app = create_app()
    return TestClient(app)


def _register(client: TestClient, email: str, password: str, display_name: str = "Tester") -> dict:
    resp = client.post("/api/v0/auth/register", json={
        "email": email,
        "password": password,
        "display_name": display_name,
    })
    assert resp.status_code == 201, f"Register failed: {resp.text}"
    data = resp.json()
    _TEST_USER_IDS.append(data["user"]["id"])
    return data


def _set_user_role(user_id: str, role: str):
    """Direct DB update to change user role (for test setup)."""
    _db_execute("UPDATE users SET role = %s WHERE id = %s", (role, user_id))


def _login(client: TestClient, email: str, password: str) -> dict:
    resp = client.post("/api/v0/auth/login", json={
        "email": email,
        "password": password,
    })
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    return resp.json()


def _register_and_login(client: TestClient, email: str, password: str = "Test123456") -> dict:
    user = _register(client, email, password)
    return _login(client, email, password)


def _register_and_login_as(client: TestClient, email: str, role: str, password: str = "Test123456") -> dict:
    """Register user, set role via DB, then login with elevated role."""
    user = _register(client, email, password)
    _set_user_role(user["user"]["id"], role)
    return _login(client, email, password)


def _create_package(client: TestClient, token: str, name: str, ptype: str = "skill") -> dict:
    resp = client.post(
        "/api/v0/producer/packages",
        json={
            "name": name,
            "type": ptype,
            "description": f"Test package {name} for integration testing",
            "license": "MIT",
            "keywords": ["test"],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201, f"Create package failed: {resp.text}"
    return resp.json()


def _create_version(client: TestClient, token: str, package_id: str, version: str = "1.0.0") -> dict:
    resp = client.post(
        f"/api/v0/producer/packages/{package_id}/versions",
        json={
            "version": version,
            "repo_url": f"https://github.com/test/{package_id}",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201, f"Create version failed: {resp.text}"
    return resp.json()


def _submit_version(client: TestClient, token: str, version_id: str):
    resp = client.post(
        f"/api/v0/producer/versions/{version_id}/submit",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code in (200, 201), f"Submit failed: {resp.text}"
    return resp.json()


def _set_version_status(version_id: str, status: str):
    """Direct DB update to set version status (bypasses background scan task)."""
    settings = get_settings()
    engine = create_engine_from_url(settings.database_url)
    session_factory = create_session_factory(engine)
    with session_factory() as session:
        session.execute(text(
            "UPDATE package_versions SET status = :status WHERE id = :vid"
        ), {"vid": version_id, "status": status})
        session.commit()
    engine.dispose()


def _simulate_scan_complete(version_id: str, scan_data: dict):
    """Set scan report + install artifacts + update version status to pending_review.

    Simulates handle_scan_complete: scan report + trust score are injected
    directly, and install manifest fields (download_url / sha256 / steps)
    are written back as if artifact packaging had completed.
    """
    _inject_scan(version_id, scan_data)
    import psycopg2
    from urllib.parse import urlparse
    settings = get_settings()
    url = urlparse(settings.database_url)
    conn = psycopg2.connect(
        host=url.hostname, port=url.port or 5432,
        dbname=url.path.lstrip("/"), user=url.username, password=url.password,
    )
    cur = conn.cursor()
    cur.execute("SELECT data FROM package_versions WHERE id = %s", (version_id,))
    row = cur.fetchone()
    if row:
        data = row[0] if isinstance(row[0], dict) else {}
        pkg_name = scan_data.get("package_name", "test-package")
        pkg_version = scan_data.get("version", "1.0.0")
        commit_hash = "a" * 40
        zip_name = f"{pkg_name}-{pkg_version}-{commit_hash[:8]}.zip"
        # 消费侧 install-manifest 校验要求 https 或 localhost http 的下载地址
        download_url = f"http://127.0.0.1:8000/api/v0/artifacts/{zip_name}"

        source = dict(data.get("source") or {})
        source.setdefault("type", "github")
        source.setdefault("ref", "main")
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
                {"action": "extract", "archive": zip_name},
                {"action": "copy", "source": pkg_name + "/",
                 "destination": f"~/.claude/skills/{pkg_name}/"},
            ],
        }
        data["status"] = "pending_review"
        cur.execute(
            "UPDATE package_versions SET status = %s, data = %s WHERE id = %s",
            ("pending_review", json.dumps(data), version_id),
        )
    conn.commit()
    cur.close()
    conn.close()


def _inject_scan(version_id: str, scan_data: dict):
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
        "VALUES (%s, %s, %s, %s) "
        "ON CONFLICT (version_id) DO UPDATE SET scan_json = EXCLUDED.scan_json",
        (version_id, json.dumps(scan_data), "test/fixture.json", datetime.now(timezone.utc)),
    )
    conn.commit()
    cur.close()
    conn.close()


def _db_execute(sql: str, params: tuple = ()):
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


def _get_db_version(version_id: str) -> dict | None:
    import psycopg2
    from urllib.parse import urlparse
    settings = get_settings()
    url = urlparse(settings.database_url)
    conn = psycopg2.connect(
        host=url.hostname, port=url.port or 5432,
        dbname=url.path.lstrip("/"), user=url.username, password=url.password,
    )
    cur = conn.cursor()
    cur.execute("SELECT status, data FROM package_versions WHERE id = %s", (version_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if row is None:
        return None
    return {"status": row[0], "data": row[1]}


def _db_query_row(sql: str, params: tuple = ()) -> str | None:
    """Execute a scalar query and return the first column of the first row."""
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


def _db_query_audit_logs(target_id: str) -> list[dict]:
    """Query audit_logs for a target (version), ordered by timestamp ascending."""
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
        "SELECT action, operator_id, detail FROM audit_logs "
        "WHERE target_id = %s ORDER BY timestamp",
        (target_id,),
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [
        {"action": r[0], "operator_id": r[1], "detail": r[2] if isinstance(r[2], dict) else {}}
        for r in rows
    ]


# ── Cleanup helper ───────────────────────────────────────

_CLEANUP_IDS: list[str] = []
_TEST_USER_IDS: list[str] = []


@pytest.fixture(autouse=True)
def _cleanup_test_ids():
    import psycopg2
    from urllib.parse import urlparse
    _CLEANUP_IDS.clear()
    _TEST_USER_IDS.clear()
    yield
    if _CLEANUP_IDS or _TEST_USER_IDS:
        settings = get_settings()
        if settings.database_url:
            url = urlparse(settings.database_url)
            conn = psycopg2.connect(
                host=url.hostname, port=url.port or 5432,
                dbname=url.path.lstrip("/"), user=url.username, password=url.password,
            )
            cur = conn.cursor()
            for vid in reversed(_CLEANUP_IDS):
                try:
                    cur.execute("SELECT package_id FROM package_versions WHERE id = %s", (vid,))
                    ver = cur.fetchone()
                    if ver:
                        cur.execute("DELETE FROM scan_reports WHERE version_id = %s", (vid,))
                        cur.execute("DELETE FROM review_records WHERE version_id = %s", (vid,))
                        cur.execute("DELETE FROM audit_logs WHERE target_id = %s", (vid,))
                        cur.execute("DELETE FROM package_versions WHERE id = %s", (vid,))
                        cur.execute("DELETE FROM packages WHERE id = %s", (ver[0],))
                except Exception:
                    pass
            for uid in reversed(_TEST_USER_IDS):
                try:
                    cur.execute("DELETE FROM users WHERE id = %s", (uid,))
                except Exception:
                    pass
            conn.commit()
            cur.close()
            conn.close()


def _needs_db():
    """Skip test if DATABASE_URL not configured."""
    settings = get_settings()
    if not settings.database_url:
        pytest.skip("DATABASE_URL not configured")


# ═══════════════════════════════════════════════════════════
# Test Cases
# ═══════════════════════════════════════════════════════════

class TestIntegrationAuditFlow:

    def test_case1_high_risk_rejected(self):
        """High risk package → scan finds critical issues → reviewer rejects."""
        _needs_db()
        client = _get_client()

        stoken = _register_and_login_as(client, _random_email("sub"), "submitter")["access_token"]
        rtoken = _register_and_login_as(client, _random_email("rev"), "reviewer")["access_token"]

        pkg = _create_package(client, stoken, f"test-reject-{uuid.uuid4().hex[:6]}")
        ver = _create_version(client, stoken, pkg["id"])
        _CLEANUP_IDS.append(ver["id"])

        _simulate_scan_complete(ver["id"], SCAN_RISKY)

        resp = client.post(
            f"/api/v0/producer/versions/{ver['id']}/reviews",
            json={"conclusion": "rejected", "comment": "Contains critical shell injection"},
            headers={"Authorization": f"Bearer {rtoken}"},
        )
        assert resp.status_code == 201, f"Review rejected failed: {resp.text}"
        result = resp.json()
        assert result["new_status"] == "rejected"

        dbv = _get_db_version(ver["id"])
        assert dbv["status"] == "rejected"

    def test_case2_normal_publish(self):
        """Clean package → approve → publish → visible."""
        _needs_db()
        client = _get_client()

        stoken = _register_and_login_as(client, _random_email("sub"), "submitter")["access_token"]
        rtoken = _register_and_login_as(client, _random_email("rev"), "reviewer")["access_token"]
        atoken = _register_and_login_as(client, _random_email("adm"), "admin")["access_token"]

        pkg = _create_package(client, stoken, f"test-publish-{uuid.uuid4().hex[:6]}")
        ver = _create_version(client, stoken, pkg["id"])
        _CLEANUP_IDS.append(ver["id"])

        _simulate_scan_complete(ver["id"], SCAN_CLEAN)

        resp = client.post(
            f"/api/v0/producer/versions/{ver['id']}/reviews",
            json={"conclusion": "approved", "comment": "Looks good"},
            headers={"Authorization": f"Bearer {rtoken}"},
        )
        assert resp.status_code == 201
        assert resp.json()["new_status"] == "approved"

        resp = client.post(
            f"/api/v0/producer/versions/{ver['id']}/publish",
            headers={"Authorization": f"Bearer {atoken}"},
        )
        assert resp.status_code == 200, f"Publish failed: {resp.text}"
        assert resp.json()["new_status"] == "published"

        dbv = _get_db_version(ver["id"])
        assert dbv["status"] == "published"

        resp = client.get(f"/api/v0/packages/{pkg['name']}")
        assert resp.status_code == 200

    def test_case3_changes_requested_resubmit(self):
        """Reviewer requests changes → submitter resubmits → re-review → approve."""
        _needs_db()
        client = _get_client()

        stoken = _register_and_login_as(client, _random_email("sub"), "submitter")["access_token"]
        rtoken = _register_and_login_as(client, _random_email("rev"), "reviewer")["access_token"]

        pkg = _create_package(client, stoken, f"test-changes-{uuid.uuid4().hex[:6]}")
        ver = _create_version(client, stoken, pkg["id"])
        _CLEANUP_IDS.append(ver["id"])

        _simulate_scan_complete(ver["id"], SCAN_CLEAN)

        resp = client.post(
            f"/api/v0/producer/versions/{ver['id']}/reviews",
            json={"conclusion": "changes_requested", "comment": "Please add license file"},
            headers={"Authorization": f"Bearer {rtoken}"},
        )
        assert resp.status_code == 201
        assert resp.json()["new_status"] == "changes_requested"

        # Directly set status to pending_review (skip background scan)
        _simulate_scan_complete(ver["id"], SCAN_CLEAN)

        resp = client.post(
            f"/api/v0/producer/versions/{ver['id']}/reviews",
            json={"conclusion": "approved", "comment": "Fixed"},
            headers={"Authorization": f"Bearer {rtoken}"},
        )
        assert resp.status_code == 201
        assert resp.json()["new_status"] == "approved"

    def test_case4_publish_then_yank(self):
        """Publish then yank (admin)."""
        _needs_db()
        client = _get_client()

        stoken = _register_and_login_as(client, _random_email("sub"), "submitter")["access_token"]
        rtoken = _register_and_login_as(client, _random_email("rev"), "reviewer")["access_token"]
        atoken = _register_and_login_as(client, _random_email("adm"), "admin")["access_token"]

        pkg = _create_package(client, stoken, f"test-yank-{uuid.uuid4().hex[:6]}")
        ver = _create_version(client, stoken, pkg["id"])
        _CLEANUP_IDS.append(ver["id"])

        _simulate_scan_complete(ver["id"], SCAN_CLEAN)

        client.post(
            f"/api/v0/producer/versions/{ver['id']}/reviews",
            json={"conclusion": "approved", "comment": "OK"},
            headers={"Authorization": f"Bearer {rtoken}"},
        )
        client.post(
            f"/api/v0/producer/versions/{ver['id']}/publish",
            headers={"Authorization": f"Bearer {atoken}"},
        )

        resp = client.post(
            f"/api/v0/producer/versions/{ver['id']}/yank?reason=Security issue found",
            headers={"Authorization": f"Bearer {atoken}"},
        )
        assert resp.status_code == 200, f"Yank failed: {resp.text}"
        assert resp.json()["new_status"] == "yanked"

        dbv = _get_db_version(ver["id"])
        assert dbv["status"] == "yanked"

        # 下架的是最新版本时，包状态应同步为 yanked，消费侧不再暴露
        dbpkg = _db_query_row(
            "SELECT status FROM packages WHERE id = %s", (pkg["id"],)
        )
        assert dbpkg == "yanked"
        detail = client.get(f"/api/v0/packages/{pkg['name']}")
        assert detail.status_code == 404, (
            f"Consumer detail should 404 after yank: {detail.text}"
        )

    def test_case5_illegal_transition_rejected(self):
        """Try to publish from draft → should be rejected (400)."""
        _needs_db()
        client = _get_client()

        stoken = _register_and_login_as(client, _random_email("sub"), "submitter")["access_token"]
        atoken = _register_and_login_as(client, _random_email("adm"), "admin")["access_token"]

        pkg = _create_package(client, stoken, f"test-illegal-{uuid.uuid4().hex[:6]}")
        ver = _create_version(client, stoken, pkg["id"])
        _CLEANUP_IDS.append(ver["id"])

        resp = client.post(
            f"/api/v0/producer/versions/{ver['id']}/publish",
            headers={"Authorization": f"Bearer {atoken}"},
        )
        assert resp.status_code == 400, f"Expected 400, got {resp.status_code}"
        assert "非法" in resp.json()["detail"] or "not allowed" in resp.json()["detail"].lower()

    def test_case6_publish_refreshes_trust_score_with_real_signals(self):
        """Publish 后评分用真实审核/安装信号刷新（manual_review / user_feedback）。"""
        _needs_db()
        client = _get_client()

        stoken = _register_and_login_as(
            client, _random_email("sub"), "submitter"
        )["access_token"]
        rtoken = _register_and_login_as(
            client, _random_email("rev"), "reviewer"
        )["access_token"]
        atoken = _register_and_login_as(
            client, _random_email("adm"), "admin"
        )["access_token"]

        pkg = _create_package(
            client, stoken, f"test-refresh-{uuid.uuid4().hex[:6]}"
        )
        ver = _create_version(client, stoken, pkg["id"])
        _CLEANUP_IDS.append(ver["id"])

        _simulate_scan_complete(ver["id"], SCAN_CLEAN)

        client.post(
            f"/api/v0/producer/versions/{ver['id']}/reviews",
            json={"conclusion": "approved", "comment": "OK"},
            headers={"Authorization": f"Bearer {rtoken}"},
        )
        resp = client.post(
            f"/api/v0/producer/versions/{ver['id']}/publish",
            headers={"Authorization": f"Bearer {atoken}"},
        )
        assert resp.status_code == 200, f"Publish failed: {resp.text}"

        # 发布后评分应已用 approved 审核信号重算并持久化
        dbv = _get_db_version(ver["id"])
        trust_score = (dbv["data"] or {}).get("trust_score")
        assert trust_score is not None, (
            "publish refresh should persist trust_score"
        )
        manual = trust_score["dimensions"]["manual_review"]["details"]
        assert manual["review_status"] == "approved"
        assert int(trust_score["score"]) > 0

        # 匿名安装上报后，GET trust-score 应惰性刷新 user_feedback 维度
        install = client.post(
            "/api/v0/installs",
            json={
                "package_name": pkg["name"],
                "version": "1.0.0",
                "client": "claude-code",
                "event_id": f"e2e-install-{uuid.uuid4().hex}",
                "integrity_verified": True,
            },
        )
        assert install.status_code == 201, (
            f"Install report failed: {install.text}"
        )

        ts = client.get(f"/api/v0/versions/{ver['id']}/trust-score")
        assert ts.status_code == 200, f"trust-score failed: {ts.text}"
        body = ts.json()
        feedback = body["dimensions"]["user_feedback"]["details"]
        assert feedback["total_installs"] == 1
        assert (
            body["dimensions"]["manual_review"]["details"]["review_status"]
            == "approved"
        )

        # 信号未变化时再次读取不应重算（评分保持一致）
        ts2 = client.get(f"/api/v0/versions/{ver['id']}/trust-score")
        assert ts2.status_code == 200
        assert (
            ts2.json()["risk_summary"]["grade"]
            == body["risk_summary"]["grade"]
        )
        assert ts2.json()["calculated_at"] == body["calculated_at"]

        # 提交 positive 反馈后，level_counts 应进入 user_feedback 维度
        fb = client.post(
            f"/api/v0/packages/{pkg['name']}/feedback",
            json={"level": "positive", "comment": "works well"},
            headers={"Authorization": f"Bearer {stoken}"},
        )
        assert fb.status_code == 201, f"Feedback failed: {fb.text}"

        ts3 = client.get(f"/api/v0/versions/{ver['id']}/trust-score")
        assert ts3.status_code == 200
        counts = ts3.json()["dimensions"]["user_feedback"]["details"][
            "level_counts"
        ]
        assert counts["positive"] >= 1

    def test_scan_start_audit_log_written(self, monkeypatch):
        """Submit → real /submit endpoint writes SCAN_START audit log.

        Evidence chain: submit → scan_start → scan_complete.
        Background scan task is replaced with a no-op to avoid real network.
        """
        _needs_db()
        client = _get_client()

        def _noop_scan(*args, **kwargs):
            return None

        monkeypatch.setattr("src.routers.trust._run_scan_task", _noop_scan)

        reg = _register_and_login_as(client, _random_email("sub"), "submitter")
        stoken = reg["access_token"]
        user_id = reg["user"]["id"]

        pkg = _create_package(client, stoken, f"test-scanstart-{uuid.uuid4().hex[:6]}")
        ver = _create_version(client, stoken, pkg["id"])
        _CLEANUP_IDS.append(ver["id"])

        resp = client.post(
            f"/api/v0/producer/versions/{ver['id']}/submit",
            headers={"Authorization": f"Bearer {stoken}"},
        )
        assert resp.status_code == 200, f"Submit failed: {resp.text}"
        result = resp.json()
        assert result["status"] == "scanning"
        task_scan_id = result["scan_id"]

        logs = _db_query_audit_logs(ver["id"])
        actions = [log["action"] for log in logs]
        assert "submit" in actions, f"submit audit missing: {actions}"
        assert "scan_start" in actions, f"scan_start audit missing: {actions}"

        scan_start = [log for log in logs if log["action"] == "scan_start"][0]
        assert scan_start["operator_id"] == user_id
        assert scan_start["detail"].get("scan_id") == task_scan_id

    def test_scan_complete_persists_task_scan_id(self):
        """handle_scan_complete writes task-level scan_id into scan_reports.scan_json.

        The persisted scan_id must match the audit detail.scan_id so the
        audit → report traceability chain is consistent.
        """
        _needs_db()
        client = _get_client()

        stoken = _register_and_login_as(client, _random_email("sub"), "submitter")["access_token"]
        pkg = _create_package(client, stoken, f"test-scanid-{uuid.uuid4().hex[:6]}")
        ver = _create_version(client, stoken, pkg["id"])
        _CLEANUP_IDS.append(ver["id"])

        import copy
        full_report = {
            "scan_id": f"scan-{uuid.uuid4().hex[:12]}",
            "scan_report": copy.deepcopy(SCAN_CLEAN),
            "trust_score": {
                "risk_summary": {
                    "grade": "A",
                    "level": "trusted",
                    "install_recommendation": "safe",
                }
            },
            "file_contents": {"SKILL.md": "---\nname: test\n---\n"},
            "local_source_dir": None,
        }

        from src.database import create_session_factory, get_runtime_engine
        from src.repositories.producer_sqlalchemy import ProducerRepository
        from src.services.producer import ProducerService
        from src.settings import get_settings as _get_settings

        settings = _get_settings()
        repo = ProducerRepository(
            create_session_factory(get_runtime_engine(settings.database_url))
        )
        ProducerService(repo).handle_scan_complete(ver["id"], full_report)

        scan = repo.get_scan_report(ver["id"])
        assert scan is not None, "scan_reports row missing"
        scan_json = scan["scan_json"]
        assert scan_json["scan_id"] == full_report["scan_id"]
        assert scan_json["file_contents"] == full_report["file_contents"]

        logs = _db_query_audit_logs(ver["id"])
        complete = [log for log in logs if log["action"] == "scan_complete"]
        assert complete, f"scan_complete audit missing: {logs}"
        assert complete[-1]["detail"].get("scan_id") == full_report["scan_id"]

    def test_review_audit_actions_normalized(self):
        """Review conclusions map to AuditAction constants in audit logs.

        approved → 'approve', rejected → 'reject', changes_requested → 'request_changes'
        (must match packages/schema/constants.py, not the raw conclusion string).
        """
        _needs_db()
        client = _get_client()

        stoken = _register_and_login_as(client, _random_email("sub"), "submitter")["access_token"]
        rtoken = _register_and_login_as(client, _random_email("rev"), "reviewer")["access_token"]

        # ── rejected → 'reject' ──
        pkg = _create_package(client, stoken, f"test-audit-rej-{uuid.uuid4().hex[:6]}")
        ver = _create_version(client, stoken, pkg["id"])
        _CLEANUP_IDS.append(ver["id"])
        _simulate_scan_complete(ver["id"], SCAN_RISKY)
        resp = client.post(
            f"/api/v0/producer/versions/{ver['id']}/reviews",
            json={"conclusion": "rejected", "comment": "risky"},
            headers={"Authorization": f"Bearer {rtoken}"},
        )
        assert resp.status_code == 201
        actions = [log["action"] for log in _db_query_audit_logs(ver["id"])]
        assert "reject" in actions, f"expected 'reject' audit, got: {actions}"
        assert "rejected" not in actions, f"legacy raw conclusion should not be written: {actions}"

        # ── changes_requested → 'request_changes' ──
        pkg2 = _create_package(client, stoken, f"test-audit-cr-{uuid.uuid4().hex[:6]}")
        ver2 = _create_version(client, stoken, pkg2["id"])
        _CLEANUP_IDS.append(ver2["id"])
        _simulate_scan_complete(ver2["id"], SCAN_CLEAN)
        resp = client.post(
            f"/api/v0/producer/versions/{ver2['id']}/reviews",
            json={"conclusion": "changes_requested", "comment": "add license"},
            headers={"Authorization": f"Bearer {rtoken}"},
        )
        assert resp.status_code == 201
        actions2 = [log["action"] for log in _db_query_audit_logs(ver2["id"])]
        assert "request_changes" in actions2, f"expected 'request_changes' audit, got: {actions2}"

        # ── approved → 'approve' ──
        _simulate_scan_complete(ver2["id"], SCAN_CLEAN)
        resp = client.post(
            f"/api/v0/producer/versions/{ver2['id']}/reviews",
            json={"conclusion": "approved", "comment": "fixed"},
            headers={"Authorization": f"Bearer {rtoken}"},
        )
        assert resp.status_code == 201
        actions3 = [log["action"] for log in _db_query_audit_logs(ver2["id"])]
        assert "approve" in actions3, f"expected 'approve' audit, got: {actions3}"
        assert "approved" not in actions3, f"legacy raw conclusion should not be written: {actions3}"


def test_upload_mcp_dependencies_persist_through_producer():
    """用户上传的 MCP 包必须保留 dependencies.mcp_servers，发布后消费侧可安装注册。"""
    _needs_db()
    client = _get_client()
    stoken = _register_and_login_as(
        client, _random_email("sub"), "submitter"
    )["access_token"]
    rtoken = _register_and_login_as(
        client, _random_email("rev"), "reviewer"
    )["access_token"]
    atoken = _register_and_login_as(
        client, _random_email("adm"), "admin"
    )["access_token"]

    pkg = _create_package(
        client, stoken, f"mcp-upload-{uuid.uuid4().hex[:6]}", ptype="mcp_server"
    )
    resp = client.post(
        f"/api/v0/producer/packages/{pkg['id']}/versions",
        json={
            "version": "1.0.0",
            "repo_url": f"https://github.com/test/{pkg['name']}",
            "compatibility": ["claude-code"],
            "source": {
                "type": "github",
                "repository_url": f"https://github.com/test/{pkg['name']}",
                "ref": "main",
                "commit_hash": "a" * 40,
            },
            "dependencies": {
                "npm": None,
                "pip": None,
                "system": None,
                "docker": None,
                "mcp_servers": [
                    {
                        "name": "time",
                        "command": "uvx",
                        "args": [
                            "--with",
                            "mcp==1.9.0",
                            "mcp-server-time==2025.9.25",
                        ],
                        "env": None,
                    }
                ],
            },
        },
        headers={"Authorization": f"Bearer {stoken}"},
    )
    assert resp.status_code == 201, f"Create version failed: {resp.text}"
    version_id = resp.json()["id"]
    _CLEANUP_IDS.append(version_id)

    # 提交 → 扫描完成（注入）→ 审核通过 → 发布
    _submit_version(client, stoken, version_id)
    _simulate_scan_complete(version_id, SCAN_CLEAN)
    resp = client.post(
        f"/api/v0/producer/versions/{version_id}/reviews",
        json={"conclusion": "approved", "comment": "ok"},
        headers={"Authorization": f"Bearer {rtoken}"},
    )
    assert resp.status_code == 201, f"Review failed: {resp.text}"
    resp = client.post(
        f"/api/v0/producer/versions/{version_id}/publish",
        headers={"Authorization": f"Bearer {atoken}"},
    )
    assert resp.status_code == 200, f"Publish failed: {resp.text}"
    assert resp.json()["new_status"] == "published"

    # 供给侧版本详情保留 dependencies
    detail = client.get(
        f"/api/v0/producer/versions/{version_id}",
        headers={"Authorization": f"Bearer {stoken}"},
    )
    assert detail.status_code == 200, f"Version detail failed: {detail.text}"
    deps = detail.json().get("dependencies") or {}
    mcp_servers = deps.get("mcp_servers") or []
    assert len(mcp_servers) == 1
    assert mcp_servers[0]["name"] == "time"
    assert mcp_servers[0]["command"] == "uvx"
    assert mcp_servers[0]["args"] == [
        "--with",
        "mcp==1.9.0",
        "mcp-server-time==2025.9.25",
    ]

    # 消费侧 install-manifest 必须携带 mcp_servers，供 CLI 写客户端配置
    manifest = client.get(
        f"/api/v0/packages/{pkg['name']}/install-manifest",
        params={"client": "claude-code"},
    )
    assert manifest.status_code == 200, f"Install manifest failed: {manifest.text}"
    manifest_mcp = (manifest.json().get("dependencies") or {}).get("mcp_servers") or []
    assert len(manifest_mcp) == 1
    assert manifest_mcp[0]["name"] == "time"
    assert manifest_mcp[0]["command"] == "uvx"
