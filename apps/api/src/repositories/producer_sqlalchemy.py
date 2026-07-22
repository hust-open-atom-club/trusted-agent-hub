"""供给侧数据库操作仓库。

与消费侧 SqlAlchemyPackageRepository 并行，
专门负责供给侧表（review_records / scan_reports / audit_logs / users）
以及供给侧对 packages / package_versions 的写操作。
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select, func
from sqlalchemy.orm import Session

from src.repositories.orm import (
    PackageRow,
    PackageVersionRow,
)
from src.repositories.orm_producer import (
    AuditLogRow,
    ReviewRecordRow,
    ScanReportRow,
    UserRow,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso_date(value: str) -> datetime:
    """将 ISO 格式日期字符串转为带时区的 datetime。"""
    s = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _serialize_dt(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


class ProducerRepository:
    """供给侧所有数据库写操作 + 查询。"""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self.session_factory = session_factory

    # ── 包操作 ────────────────────────────────────────────

    def create_package(
        self,
        *,
        name: str,
        type: str,
        description: str,
        submitter_id: str | None = None,
        license: str | None = None,
        keywords: list[str] | None = None,
        category: str | None = None,
        homepage: str | None = None,
        icon_url: str | None = None,
        author: dict[str, object] | None = None,
        permissions: dict[str, object] | None = None,
        installation: dict[str, object] | None = None,
        source: dict[str, object] | None = None,
        compatibility: list[str] | None = None,
    ) -> dict[str, object]:
        """创建能力包，返回包基本信息。"""
        pkg_id = f"pkg-{uuid4().hex}"
        now = _utc_now()
        data: dict[str, object] = {
            "id": pkg_id,
            "name": name,
            "description": description,
            "type": type,
            "submitter_id": submitter_id,
            "license": license,
            "keywords": keywords or [],
            "category": category,
            "homepage": homepage,
            "icon_url": icon_url,
            "author": author,
            "permissions": permissions,
            "installation": installation,
            "source": source,
            "compatibility": compatibility or [],
            "latest_version": "0.0.0",
            "status": "draft",
            "trust_score": None,
            "risk_level": None,
            "install_count": 0,
            "avg_rating": None,
            "created_at": _serialize_dt(now),
            "updated_at": _serialize_dt(now),
        }
        with self.session_factory() as session:
            session.add(
                PackageRow(
                    id=pkg_id,
                    name=name,
                    status="draft",
                    latest_version="0.0.0",
                    data=data,
                )
            )
            session.commit()
        return data

    def get_package(self, package_id: str) -> dict[str, object] | None:
        with self.session_factory() as session:
            row = session.get(PackageRow, package_id)
            if row is None:
                return None
            versions_count = session.scalar(
                select(func.count())
                .select_from(PackageVersionRow)
                .where(PackageVersionRow.package_id == package_id)
            )
            data = dict(row.data)
            data["versions_count"] = versions_count or 0
            return data

    def delete_package(self, package_id: str) -> bool:
        """删除包（仅无版本的包可删除，防止误删有数据的包）。"""
        with self.session_factory() as session:
            pkg = session.get(PackageRow, package_id)
            if pkg is None:
                return False
            has_versions = session.scalar(
                select(func.count())
                .select_from(PackageVersionRow)
                .where(PackageVersionRow.package_id == package_id)
            )
            if has_versions:
                return False
            session.delete(pkg)
            session.commit()
            return True

    def list_package_versions(
        self, package_id: str
    ) -> list[dict[str, object]]:
        with self.session_factory() as session:
            rows = session.scalars(
                select(PackageVersionRow)
                .where(PackageVersionRow.package_id == package_id)
                .order_by(PackageVersionRow.version)
            ).all()
            return [_version_brief(row) for row in rows]

    # ── 版本操作 ──────────────────────────────────────────

    def create_version(
        self,
        *,
        package_id: str,
        version: str,
        submitter_id: str | None = None,
        repo_url: str | None = None,
        description: str | None = None,
        installation: dict[str, object] | None = None,
        source: dict[str, object] | None = None,
    ) -> dict[str, object]:
        """创建新版本，返回版本信息。"""
        version_id = f"ver-{uuid4().hex}"
        now = _utc_now()
        data: dict[str, object] = {
            "id": version_id,
            "package_id": package_id,
            "version": version,
            "status": "draft",
            "submitter_id": submitter_id,
            "source": source or {"type": "git", "repository_url": repo_url or "", "ref": "", "commit_hash": ""},
            "description": description,
            "installation": installation,
            "submitted_at": None,
            "trust_score": None,
            "created_at": _serialize_dt(now),
        }
        with self.session_factory() as session:
            session.add(
                PackageVersionRow(
                    id=version_id,
                    package_id=package_id,
                    version=version,
                    status="draft",
                    data=data,
                )
            )
            session.commit()
        return data

    def get_version(self, version_id: str) -> dict[str, object] | None:
        with self.session_factory() as session:
            row = session.get(PackageVersionRow, version_id)
            if row is None:
                return None
            return dict(row.data)

    def get_previous_version(
        self, version_id: str
    ) -> dict[str, object] | None:
        with self.session_factory() as session:
            current = session.get(PackageVersionRow, version_id)
            if current is None:
                return None
            prev = session.scalars(
                select(PackageVersionRow)
                .where(
                    PackageVersionRow.package_id == current.package_id,
                    PackageVersionRow.id != version_id,
                )
                .order_by(
                    PackageVersionRow.data["created_at"]
                    .as_string()
                    .desc()
                )
                .limit(1)
            ).first()
            if prev is None:
                return None
            return dict(prev.data)

    def update_version_status(
        self, version_id: str, new_status: str
    ) -> None:
        with self.session_factory() as session:
            row = session.get(PackageVersionRow, version_id)
            if row is None:
                return
            row.status = new_status
            # 同步更新 data JSON 中的 status
            data = dict(row.data) if row.data else {}
            data["status"] = new_status
            row.data = data
            session.commit()

    def update_version_data(
        self, version_id: str, updates: dict[str, object]
    ) -> None:
        with self.session_factory() as session:
            row = session.get(PackageVersionRow, version_id)
            if row is None:
                return
            data = dict(row.data) if row.data else {}
            data.update(updates)
            row.data = data
            session.commit()

    # ── 扫描报告 ──────────────────────────────────────────

    def save_scan_report(
        self,
        *,
        version_id: str,
        scan_json: dict[str, object],
        report_path: str | None = None,
    ) -> None:
        with self.session_factory() as session:
            existing = session.get(ScanReportRow, version_id)
            if existing is not None:
                existing.scan_json = scan_json
                existing.report_path = report_path
                existing.scanned_at = _utc_now()
            else:
                session.add(
                    ScanReportRow(
                        version_id=version_id,
                        scan_json=scan_json,
                        report_path=report_path,
                        scanned_at=_utc_now(),
                    )
                )
            session.commit()

    def get_scan_report(
        self, version_id: str
    ) -> dict[str, object] | None:
        with self.session_factory() as session:
            row = session.get(ScanReportRow, version_id)
            if row is None:
                return None
            return {
                "scan_json": row.scan_json,
                "report_path": row.report_path,
                "scanned_at": _serialize_dt(row.scanned_at),
            }

    # ── 审核记录 ──────────────────────────────────────────

    def create_review_record(
        self,
        *,
        version_id: str,
        reviewer_id: str,
        conclusion: str,
        comment: str | None = None,
    ) -> dict[str, object]:
        record_id = f"rev-{uuid4().hex}"
        now = _utc_now()
        with self.session_factory() as session:
            session.add(
                ReviewRecordRow(
                    id=record_id,
                    version_id=version_id,
                    reviewer_id=reviewer_id,
                    conclusion=conclusion,
                    comment=comment,
                    created_at=now,
                )
            )
            session.commit()
        return {
            "id": record_id,
            "version_id": version_id,
            "reviewer_id": reviewer_id,
            "conclusion": conclusion,
            "comment": comment,
            "created_at": _serialize_dt(now),
        }

    def list_review_records(
        self, version_id: str
    ) -> list[dict[str, object]]:
        with self.session_factory() as session:
            stmt = (
                select(
                    ReviewRecordRow.id,
                    ReviewRecordRow.version_id,
                    ReviewRecordRow.reviewer_id,
                    ReviewRecordRow.conclusion,
                    ReviewRecordRow.comment,
                    ReviewRecordRow.created_at,
                    UserRow.username.label("reviewer_name"),
                    UserRow.display_name.label("reviewer_display_name"),
                )
                .outerjoin(UserRow, UserRow.id == ReviewRecordRow.reviewer_id)
                .where(ReviewRecordRow.version_id == version_id)
                .order_by(ReviewRecordRow.created_at.desc())
            )
            rows = session.execute(stmt).all()
            return [
                {
                    "id": row.id,
                    "version_id": row.version_id,
                    "reviewer_id": row.reviewer_id,
                    "reviewer_name": row.reviewer_name,
                    "reviewer_display_name": row.reviewer_display_name,
                    "conclusion": row.conclusion,
                    "comment": row.comment,
                    "created_at": _serialize_dt(row.created_at),
                }
                for row in rows
            ]

    def list_reviews_by_reviewer(
        self, reviewer_id: str, limit: int = 50, offset: int = 0
    ) -> list[dict[str, object]]:
        """返回某审核员的全部审核记录，附带版本和包信息。"""
        with self.session_factory() as session:
            stmt = (
                select(
                    ReviewRecordRow.id,
                    ReviewRecordRow.version_id,
                    ReviewRecordRow.conclusion,
                    ReviewRecordRow.comment,
                    ReviewRecordRow.created_at,
                    PackageVersionRow.version.label("version_label"),
                    PackageVersionRow.status.label("version_status"),
                    PackageRow.name.label("package_name"),
                )
                .join(
                    PackageVersionRow,
                    PackageVersionRow.id == ReviewRecordRow.version_id,
                )
                .join(
                    PackageRow,
                    PackageRow.id == PackageVersionRow.package_id,
                )
                .where(ReviewRecordRow.reviewer_id == reviewer_id)
                .order_by(ReviewRecordRow.created_at.desc())
                .offset(offset)
                .limit(limit)
            )
            rows = session.execute(stmt).all()
            return [
                {
                    "id": row.id,
                    "version_id": row.version_id,
                    "conclusion": row.conclusion,
                    "comment": row.comment,
                    "created_at": _serialize_dt(row.created_at),
                    "version": row.version_label,
                    "version_status": row.version_status,
                    "package_name": row.package_name,
                }
                for row in rows
            ]

    # ── 审计日志 ──────────────────────────────────────────

    def create_audit_log(
        self,
        *,
        action: str,
        target_type: str,
        target_id: str,
        operator_id: str,
        detail: dict[str, object] | None = None,
    ) -> None:
        with self.session_factory() as session:
            session.add(
                AuditLogRow(
                    id=f"audit-{uuid4().hex}",
                    action=action,
                    target_type=target_type,
                    target_id=target_id,
                    operator_id=operator_id,
                    detail=detail,
                    timestamp=_utc_now(),
                )
            )
            session.commit()



    def list_audit_logs(
        self,
        *,
        target_type: str | None = None,
        target_id: str | None = None,
        action: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, object]]:
        """分页查询审计日志，支持按目标类型/目标ID/操作类型/时间范围筛选。"""
        with self.session_factory() as session:
            stmt = select(
                AuditLogRow.id,
                AuditLogRow.action,
                AuditLogRow.target_type,
                AuditLogRow.target_id,
                AuditLogRow.operator_id,
                AuditLogRow.timestamp,
                AuditLogRow.detail,
                UserRow.username.label("operator_name"),
            ).outerjoin(UserRow, UserRow.id == AuditLogRow.operator_id)
            if target_type:
                stmt = stmt.where(AuditLogRow.target_type == target_type)
            if target_id:
                stmt = stmt.where(AuditLogRow.target_id == target_id)
            if action:
                stmt = stmt.where(AuditLogRow.action == action)
            if start_date:
                stmt = stmt.where(AuditLogRow.timestamp >= _parse_iso_date(start_date))
            if end_date:
                stmt = stmt.where(AuditLogRow.timestamp <= _parse_iso_date(end_date))
            stmt = stmt.order_by(AuditLogRow.timestamp.desc())
            stmt = stmt.offset(offset).limit(limit)
            rows = session.execute(stmt).all()
            return [
                {
                    "id": row.id,
                    "action": row.action,
                    "target_type": row.target_type,
                    "target_id": row.target_id,
                    "operator_id": row.operator_id,
                    "operator_name": row.operator_name,
                    "timestamp": _serialize_dt(row.timestamp),
                    "detail": row.detail,
                }
                for row in rows
            ]
# ── 统计查询 ──────────────────────────────────────────────

    def get_dashboard_stats(self) -> dict[str, object]:
        """返回管理仪表盘统计数据。"""
        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        with self.session_factory() as session:
            total_packages = session.scalar(
                select(func.count()).select_from(PackageRow)
            ) or 0
            total_versions = session.scalar(
                select(func.count()).select_from(PackageVersionRow)
            ) or 0
            pending_review = session.scalar(
                select(func.count())
                .select_from(PackageVersionRow)
                .where(PackageVersionRow.status == "pending_review")
            ) or 0
            today_submissions = session.scalar(
                select(func.count())
                .select_from(PackageVersionRow)
                .where(
                    PackageVersionRow.data["submitted_at"]
                    .as_string()
                    >= today_start.isoformat()
                )
            ) or 0
            approved_count = session.scalar(
                select(func.count())
                .select_from(PackageVersionRow)
                .where(PackageVersionRow.status == "approved")
            ) or 0
            published_count = session.scalar(
                select(func.count())
                .select_from(PackageVersionRow)
                .where(PackageVersionRow.status == "published")
            ) or 0
            rejected_count = session.scalar(
                select(func.count())
                .select_from(PackageVersionRow)
                .where(PackageVersionRow.status == "rejected")
            ) or 0
            yanked_count = session.scalar(
                select(func.count())
                .select_from(PackageVersionRow)
                .where(PackageVersionRow.status == "yanked")
            ) or 0
        return {
            "total_packages": total_packages,
            "total_versions": total_versions,
            "pending_review": pending_review,
            "today_submissions": today_submissions,
            "approved": approved_count,
            "published": published_count,
            "rejected": rejected_count,
            "yanked": yanked_count,
        }

# ── 辅助函数 ──────────────────────────────────────────────

    def list_versions_by_submitter(
        self, submitter_id: str, limit: int = 50, offset: int = 0
    ) -> list[dict[str, object]]:
        """返回某个提交者的所有版本列表，按提交时间倒序。"""
        with self.session_factory() as session:
            rows = session.execute(
                select(
                    PackageVersionRow.id,
                    PackageVersionRow.package_id,
                    PackageVersionRow.version,
                    PackageVersionRow.status,
                    PackageVersionRow.data,
                    PackageRow.name.label("package_name"),
                )
                .join(PackageRow, PackageRow.id == PackageVersionRow.package_id)
                .where(
                    PackageVersionRow.data["submitter_id"].as_string()
                    == submitter_id
                )
                .order_by(
                    PackageVersionRow.data["submitted_at"]
                    .as_string()
                    .desc()
                    .nullslast()
                )
                .offset(offset)
                .limit(limit)
            ).all()
            return [
                {
                    "version_id": row.id,
                    "package_id": row.package_id,
                    "package_name": row.package_name,
                    "version": row.version,
                    "status": row.status,
                    "submitted_at": (row.data or {}).get("submitted_at"),
                }
                for row in rows
            ]

    def list_versions_by_status(
        self,
        *,
        status: str | list[str] | None = None,
        grade: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, object]]:
        """按状态筛选版本列表（审核员视图用），带包名和扫描摘要。

        支持逗号分隔的多状态筛选、风险等级过滤。
        返回字段：version_id / package_id / package_name / package_type /
        version / status / submitted_at / grade / findings_count。
        """
        with self.session_factory() as session:
            stmt = (
                select(
                    PackageVersionRow.id,
                    PackageVersionRow.package_id,
                    PackageVersionRow.version,
                    PackageVersionRow.status,
                    PackageVersionRow.data,
                    PackageRow.name.label("package_name"),
                    PackageRow.data.label("package_data"),
                    ScanReportRow.scan_json,
                )
                .join(PackageRow, PackageRow.id == PackageVersionRow.package_id)
                .outerjoin(
                    ScanReportRow,
                    ScanReportRow.version_id == PackageVersionRow.id,
                )
            )

            if status:
                if isinstance(status, str):
                    statuses = [s.strip() for s in status.split(",") if s.strip()]
                else:
                    statuses = status
                if statuses:
                    stmt = stmt.where(PackageVersionRow.status.in_(statuses))

            stmt = stmt.order_by(
                PackageVersionRow.data["submitted_at"]
                .as_string()
                .desc()
                .nullslast()
            ).offset(offset).limit(limit)

            rows = session.execute(stmt).all()

        results: list[dict[str, object]] = []
        for row in rows:
            data = row.data or {}
            trust_score = data.get("trust_score", {})
            grade_val = None
            if isinstance(trust_score, dict):
                risk_summary = trust_score.get("risk_summary", {})
                if isinstance(risk_summary, dict):
                    grade_val = risk_summary.get("grade")

            findings_count = 0
            if row.scan_json and isinstance(row.scan_json, dict):
                summary = row.scan_json.get("summary", {})
                if isinstance(summary, dict):
                    findings_count = summary.get("total", 0)

            pkg_data = row.package_data or {}
            package_type = None
            if isinstance(pkg_data, dict):
                package_type = pkg_data.get("type")

            results.append({
                "version_id": row.id,
                "package_id": row.package_id,
                "package_name": row.package_name,
                "package_type": package_type,
                "version": row.version,
                "status": row.status,
                "submitted_at": data.get("submitted_at"),
                "published_at": data.get("published_at"),
                "grade": grade_val,
                "findings_count": findings_count,
            })

        if grade:
            results = [r for r in results if r.get("grade") == grade]

        return results


def _version_brief(row: PackageVersionRow) -> dict[str, object]:
    data = dict(row.data) if row.data else {}
    return {
        "id": row.id,
        "version": row.version,
        "status": row.status,
        "submitted_at": data.get("submitted_at"),
        "created_at": data.get("created_at"),
    }
