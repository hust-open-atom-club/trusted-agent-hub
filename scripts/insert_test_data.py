"""一次性脚本：为测试直接向 PostgreSQL 插入 submitter 的测试包数据。
用法：D:\Anaconda\envs\bainian\python.exe scripts/insert_test_data.py
"""
import json, uuid, sys, os
from datetime import datetime, timezone

REPO = r"E:\open source internship program\TrustedAgentHub"
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "packages"))
sys.path.insert(0, os.path.join(REPO, "apps", "api"))

from src.database import create_engine_from_url, create_session_factory

DB_URL = "postgresql://postgres:293021@localhost:5432/trusted_agent_hub"
engine = create_engine_from_url(DB_URL)
SessionFactory = create_session_factory(engine)

def now():
    return datetime.now(timezone.utc).isoformat()

def insert_test_data():
    from sqlalchemy import text

    with SessionFactory() as s:
        r = s.execute(text("SELECT id, username FROM users WHERE username='submitter'"))
        user = r.fetchone()
        if not user:
            print("ERROR: submitter 用户不存在")
            return
        submitter_id = user[0]
        print(f"submitter_id={submitter_id}")

    packages = [
        {
            "name": "demo-code-review",
            "type": "skill",
            "description": "Multi-dimension code review agent skill with PR analysis, security scanning, and code quality checks",
            "license": "MIT",
            "keywords": ["code-review", "pull-request", "lint", "security"],
            "category": "developer-tools",
            "compatibility": ["codewhale", "cursor", "claude"],
            "version": "1.2.0",
            "status": "pending_review",
            "scan_report": "packages/schema/reports/scan-07a83e42cffb.json",
        },
        {
            "name": "demo-filesystem-mcp",
            "type": "mcp_server",
            "description": "Read-only filesystem MCP server providing safe file browsing and search capabilities",
            "license": "Apache-2.0",
            "keywords": ["mcp", "filesystem", "read-only", "search"],
            "category": "infrastructure",
            "compatibility": ["codewhale", "claude"],
            "version": "0.5.0",
            "status": "scanning",
            "scan_report": None,
        },
        {
            "name": "demo-dev-toolkit",
            "type": "plugin",
            "description": "Developer toolkit plugin aggregating 3 skills: lint, test, and deploy automation",
            "license": "MIT",
            "keywords": ["devtools", "lint", "test", "deploy", "automation"],
            "category": "developer-tools",
            "compatibility": ["codewhale", "cursor", "windsurf"],
            "version": "2.0.1",
            "status": "published",
            "scan_report": "packages/schema/reports/scan-0caeb64f5c2d.json",
        },
        {
            "name": "risky-executor",
            "type": "command",
            "description": "A deliberately risky executor package with multiple attack vectors for scanner stress testing",
            "license": "NONE",
            "keywords": ["test", "risky", "scanner-test"],
            "category": "testing",
            "compatibility": ["codewhale"],
            "version": "0.1.0",
            "status": "rejected",
            "scan_report": "packages/schema/reports/scan-b5330c9560b8.json",
        },
    ]

    for pkg_data in packages:
        pkg_id = f"pkg-{uuid.uuid4().hex[:12]}"
        ver_id = f"ver-{uuid.uuid4().hex[:12]}"
        name = pkg_data["name"]
        ver = pkg_data["version"]
        status = pkg_data["status"]

        pkg_json = {
            "type": pkg_data["type"],
            "description": pkg_data["description"],
            "license": pkg_data["license"],
            "keywords": pkg_data["keywords"],
            "category": pkg_data["category"],
            "compatibility": pkg_data["compatibility"],
            "submitter_id": submitter_id,
            "homepage": f"https://github.com/example/{name}",
            "author": {"name": "Test Submitter", "email": "submitter@test.com"},
            "created_at": now(),
            "updated_at": now(),
        }

        ver_json = {
            "description": pkg_data["description"],
            "source": {"repository_url": f"https://github.com/example/{name}"},
            "submitter_id": submitter_id,
            "submitted_at": now(),
            "created_at": now(),
        }

        with SessionFactory() as s:
            existing = s.execute(
                text("SELECT id FROM packages WHERE name = :n"), {"n": name}
            ).fetchone()
            if existing:
                print(f"SKIP: {name} already exists (id={existing[0]})")
                continue

            s.execute(
                text("INSERT INTO packages (id, name, status, latest_version, data) VALUES (:id, :name, :status, :lv, :data::jsonb)"),
                {"id": pkg_id, "name": name, "status": status, "lv": ver, "data": json.dumps(pkg_json)},
            )
            s.execute(
                text("INSERT INTO package_versions (id, package_id, version, status, data) VALUES (:id, :pid, :ver, :status, :data::jsonb)"),
                {"id": ver_id, "pid": pkg_id, "ver": ver, "status": status, "data": json.dumps(ver_json)},
            )
            s.commit()
            print(f"OK: {name} v{ver} status={status} pkg_id={pkg_id} ver_id={ver_id}")

        report_rel = pkg_data.get("scan_report")
        if report_rel:
            full_path = os.path.join(REPO, report_rel)
            try:
                with open(full_path, encoding="utf-8") as f:
                    scan_json = json.load(f)
                with SessionFactory() as s:
                    s.execute(
                        text("INSERT INTO scan_reports (version_id, scan_json, report_path, scanned_at) VALUES (:vid, :json::jsonb, :path, :ts) ON CONFLICT (version_id) DO NOTHING"),
                        {"vid": ver_id, "json": json.dumps(scan_json), "path": report_rel, "ts": now()},
                    )
                    s.commit()
                print(f"  + scan_report: {report_rel}")
            except FileNotFoundError:
                print(f"  - scan_report not found: {full_path}")

    print("\nDone!")

if __name__ == "__main__":
    insert_test_data()
