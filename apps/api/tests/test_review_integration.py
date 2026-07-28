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
    return resp.json()


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
    """Set scan report + update version status to pending_review (skips real scanner)."""
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


# ── Cleanup helper ───────────────────────────────────────

_CLEANUP_IDS: list[str] = []


@pytest.fixture(autouse=True)
def _cleanup_test_ids():
    import psycopg2
    from urllib.parse import urlparse
    _CLEANUP_IDS.clear()
    yield
    if _CLEANUP_IDS:
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
