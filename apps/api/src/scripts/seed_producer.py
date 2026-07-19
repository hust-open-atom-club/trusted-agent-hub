"""一次性种子脚本：将 mock JSON 数据导入 PostgreSQL。

用法：
    cd apps/api
    $env:DATABASE_URL="postgresql://postgres:password@localhost:5432/trusted_agent_hub"
    python -m src.scripts.seed_producer
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_API_DIR = Path(__file__).resolve().parents[2]  # apps/api
_PROJECT = _API_DIR.parent.parent  # repo root
sys.path.insert(0, str(_API_DIR))

from src.database import create_engine_from_url, create_session_factory
from src.repositories.sqlalchemy import (
    SqlAlchemyPackageRepository,
    seed_sqlalchemy_repository,
)
from src.repositories.mock import JsonPackageRepository
from src.settings import get_settings

MOCK_DIR = _PROJECT / "packages" / "schema" / "mock"
REPORTS_DIR = _PROJECT / "packages" / "schema" / "reports"


def seed_packages(repo: SqlAlchemyPackageRepository) -> int:
    """将 mock JSON 的包和版本数据导入 PG。"""
    pkg_file = MOCK_DIR / "packages.json"
    if not pkg_file.is_file():
        print("[seed]   mock/packages.json 不存在，跳过包数据导入")
        return 0

    source = JsonPackageRepository(pkg_file, MOCK_DIR / "versions")
    packages = list(source.list_packages())
    seed_sqlalchemy_repository(repo, source)
    print(f"[seed]   包: {len(packages)} 个")
    for p in packages:
        versions = list(source.list_versions(p.name))
        print(f"[seed]     {p.name} ({len(versions)} 版本)")
    return len(packages)


def seed_scan_reports(repo: SqlAlchemyPackageRepository) -> int:
    """将 reports 目录下的扫描报告写入 scan_reports 表。"""
    if not REPORTS_DIR.is_dir():
        print("[seed]   reports 目录不存在，跳过")
        return 0

    count = 0
    for fpath in sorted(REPORTS_DIR.glob("scan-*.json")):
        try:
            report = json.loads(fpath.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            print(f"[seed]   跳过 {fpath.name}: 读取失败")
            continue

        pkg_name = report.get("package_name", "")
        version_id = None
        for p in repo.list_packages():
            if p.name == pkg_name:
                v = repo.get_version(p.name, p.latest_version)
                if v:
                    version_id = v.id
                break

        if not version_id:
            print(f"[seed]   跳过 {fpath.name}: 无法匹配到包 {pkg_name}")
            continue

        scanned_at = report.get("finished_at") or report.get("created_at") or ""

        with repo.session_factory() as session:
            conn = session.connection().connection  # raw psycopg connection
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO scan_reports (version_id, scan_json, report_path, scanned_at) "
                    "VALUES (%s, %s::jsonb, %s, %s) "
                    "ON CONFLICT (version_id) DO UPDATE SET "
                    "scan_json = EXCLUDED.scan_json, "
                    "report_path = EXCLUDED.report_path, "
                    "scanned_at = EXCLUDED.scanned_at",
                    (version_id, json.dumps(report, ensure_ascii=False), str(fpath), scanned_at),
                )
            conn.commit()
            count += 1
            print(f"[seed]   report: {fpath.name} → {pkg_name}")

    return count


def seed_users() -> int:
    """预置测试账号到 users 表。"""
    from src.repositories.orm_producer import UserRow
    from sqlalchemy import select
    import uuid

    engine = create_engine_from_url(get_settings().database_url)
    session = create_session_factory(engine)()

    users = [
        ("admin", "admin123", "admin"),
        ("reviewer", "review123", "reviewer"),
        ("submitter", "submit123", "submitter"),
    ]

    count = 0
    try:
        for username, password, role in users:
            existing = session.scalar(
                select(UserRow).where(UserRow.username == username)
            )
            if existing is not None:
                print(f"[seed]   用户 {username} 已存在，跳过")
                continue
            user = UserRow(
                id=f"user-{uuid.uuid4().hex}",
                username=username,
                password_hash=hash_password(password),
                role=role,
            )
            session.add(user)
            count += 1
            print(f"[seed]   创建用户: {username} (role={role})")
        session.commit()
    finally:
        session.close()
    return count


def main() -> None:
    settings = get_settings()
    if not settings.database_url:
        print("[seed] 错误：DATABASE_URL 未设置", file=sys.stderr)
        sys.exit(1)

    engine = create_engine_from_url(settings.database_url)
    repo = SqlAlchemyPackageRepository(create_session_factory(engine))

    print("[seed] 开始种子数据导入...")
    n_pkgs = seed_packages(repo)
    print(f"[seed] 包数据: {n_pkgs} 个包")

    n_users = seed_users()
    print(f"[seed] 用户数据: {n_users} 个用户")

    n_reports = seed_scan_reports(repo)
    print(f"[seed] 扫描报告: {n_reports} 个")

    total = repo.list_packages()
    print(f"[seed] DONE! PG has {len(total)} packages")


if __name__ == "__main__":
    main()
