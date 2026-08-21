"""一次性种子脚本：将 mock JSON 数据导入 PostgreSQL。

用法：
    cd apps/api
    $env:DATABASE_URL="postgresql://postgres:password@localhost:5432/trusted_agent_hub"
    python -m src.scripts.seed_producer
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
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
from src.repositories.orm_producer import ScanReportRow
from src.settings import get_settings

MOCK_DIR = _PROJECT / "packages" / "schema" / "mock"
REPORTS_DIR = _PROJECT / "packages" / "schema" / "reports"
IMPORT_SOURCE_ROOTS = (
    _PROJECT / "examples",
    _PROJECT / "packages" / "schema" / "examples",
)

_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".next",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "venv",
    ".venv",
}

_TEXT_SUFFIXES = {
    ".cfg",
    ".css",
    ".csv",
    ".env",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".jsx",
    ".lock",
    ".md",
    ".mjs",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}

_TEXT_FILENAMES = {
    ".gitignore",
    ".gitattributes",
    "Dockerfile",
    "LICENSE",
    "Makefile",
    "README",
    "SKILL.md",
}

_MAX_FILE_BYTES = 256 * 1024
_MAX_TOTAL_BYTES = 2 * 1024 * 1024


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
        version = repo.get_version_by_id(version_id)
        report = _with_imported_file_contents(
            report,
            package_name=pkg_name,
            version=version.version if version else None,
            source_roots=IMPORT_SOURCE_ROOTS,
        )

        _upsert_seed_scan_report(
            repo,
            version_id=version_id,
            scan_json=report,
            report_path=str(fpath),
            scanned_at=_parse_report_datetime(scanned_at),
        )
        count += 1
        print(f"[seed]   report: {fpath.name} → {pkg_name}")

    return count


def seed_import_file_snapshots(
    repo: SqlAlchemyPackageRepository,
    source_roots: tuple[Path, ...] | list[Path] = IMPORT_SOURCE_ROOTS,
) -> int:
    """为直接导入但没有扫描文件快照的版本补 scan_reports.file_contents。"""
    count = 0
    for package in repo.list_packages():
        for version in repo.list_versions(package.name):
            existing = repo.get_scan_report(version.id)
            existing_scan_json = (
                dict(existing.get("scan_json") or {})
                if existing and isinstance(existing.get("scan_json"), dict)
                else {}
            )
            report = _with_imported_file_contents(
                existing_scan_json,
                package_name=package.name,
                version=version.version,
                source_roots=source_roots,
            )
            file_contents = report.get("file_contents")
            if not isinstance(file_contents, dict) or not file_contents:
                continue
            if report == existing_scan_json:
                continue

            report.setdefault("package_name", package.name)
            report.setdefault("version", version.version)
            report.setdefault("summary", {"total": 0})
            _upsert_seed_scan_report(
                repo,
                version_id=version.id,
                scan_json=report,
                report_path=(
                    str(existing.get("report_path"))
                    if existing and existing.get("report_path")
                    else None
                ),
                scanned_at=None,
            )
            count += 1
            print(f"[seed]   file snapshot: {package.name}@{version.version}")
    return count


def _collect_text_file_contents(root: Path) -> dict[str, str]:
    """Collect a bounded text-only snapshot for a package directory."""
    files: dict[str, str] = {}
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or _is_under_skipped_dir(path, root):
            continue
        if not _looks_like_text_file(path):
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > _MAX_FILE_BYTES or total_bytes + size > _MAX_TOTAL_BYTES:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        except OSError:
            continue

        rel = path.relative_to(root).as_posix()
        files[rel] = content
        total_bytes += size
    return files


def _find_imported_package_file_contents(
    package_name: str,
    version: str | None,
    source_roots: tuple[Path, ...] | list[Path] = IMPORT_SOURCE_ROOTS,
) -> dict[str, str]:
    """Find local imported package files by manifest name/version."""
    for source_root in source_roots:
        if not source_root.is_dir():
            continue
        manifests = sorted(source_root.rglob("manifest.json"))
        manifests.extend(sorted(source_root.rglob("plugin.json")))
        for manifest_path in manifests:
            if _is_under_skipped_dir(manifest_path, source_root):
                continue
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError, UnicodeDecodeError):
                continue
            if not isinstance(manifest, dict):
                continue
            manifest_name = str(manifest.get("name") or "").strip()
            manifest_version = str(manifest.get("version") or "").strip()
            if manifest_name != package_name:
                continue
            if version and manifest_version and manifest_version != version:
                continue
            return _collect_text_file_contents(manifest_path.parent)
    return {}


def _with_imported_file_contents(
    report: dict[str, object],
    *,
    package_name: str,
    version: str | None,
    source_roots: tuple[Path, ...] | list[Path] = IMPORT_SOURCE_ROOTS,
) -> dict[str, object]:
    """Preserve scanner snapshots, otherwise add local import file contents."""
    existing = report.get("file_contents")
    if isinstance(existing, dict) and existing:
        return report

    file_contents = _find_imported_package_file_contents(
        package_name,
        version,
        source_roots,
    )
    if not file_contents:
        return report

    enriched = dict(report)
    enriched["file_contents"] = file_contents
    return enriched


def _is_under_skipped_dir(path: Path, root: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return True
    return any(part in _SKIP_DIRS for part in parts[:-1])


def _looks_like_text_file(path: Path) -> bool:
    return path.name in _TEXT_FILENAMES or path.suffix.lower() in _TEXT_SUFFIXES


def _parse_report_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _upsert_seed_scan_report(
    repo: SqlAlchemyPackageRepository,
    *,
    version_id: str,
    scan_json: dict[str, object],
    report_path: str | None,
    scanned_at: datetime | None,
) -> None:
    with repo.session_factory() as session:
        row = session.get(ScanReportRow, version_id)
        timestamp = scanned_at or datetime.now(timezone.utc)
        if row is None:
            session.add(
                ScanReportRow(
                    version_id=version_id,
                    scan_json=scan_json,
                    report_path=report_path,
                    scanned_at=timestamp,
                )
            )
        else:
            row.scan_json = scan_json
            row.report_path = report_path
            row.scanned_at = timestamp
        session.commit()


def seed_users() -> int:
    """预置测试账号到 users 表。"""
    from src.repositories.orm_producer import UserRow
    from sqlalchemy import select
    import uuid

    engine = create_engine_from_url(get_settings().database_url)
    session = create_session_factory(engine)()

    users = [
        ("admin@local.dev", "admin123", "admin", "admin"),
        ("reviewer@local.dev", "review123", "reviewer", "reviewer"),
        ("submitter@local.dev", "submit123", "submitter", "submitter"),
    ]

    count = 0
    try:
        for email, password, role, display_name in users:
            existing = session.scalar(
                select(UserRow).where(UserRow.email == email)
            )
            if existing is not None:
                print(f"[seed]   用户 {email} 已存在，跳过")
                continue
            user = UserRow(
                id=f"user-{uuid.uuid4().hex}",
                email=email,
                password_hash=hash_password(password),
                role=role,
                display_name=display_name,
            )
            session.add(user)
            count += 1
            print(f"[seed]   创建用户: {email} (role={role})")
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

    n_snapshots = seed_import_file_snapshots(repo)
    print(f"[seed] 导入文件快照: {n_snapshots} 个")

    total = repo.list_packages()
    print(f"[seed] DONE! PG has {len(total)} packages")


if __name__ == "__main__":
    main()
