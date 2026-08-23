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
    FeedbackRecordRow,
    PackageRow,
    PackageVersionRow,
    TrustLevelRow,
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
        dependencies: dict[str, object] | None = None,
        source: dict[str, object] | None = None,
        compatibility: list[str] | None = None,
        field_source: dict[str, str] | None = None,
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
            "dependencies": dependencies,
            "source": source,
            "field_source": field_source,
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

    def package_name_exists(self, name: str) -> bool:
        """检查包名是否已存在。"""
        with self.session_factory() as session:
            return session.scalar(
                select(func.count())
                .select_from(PackageRow)
                .where(PackageRow.name == name)
            ) > 0

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

    def delete_version(self, version_id: str) -> bool:
        """删除指定版本。"""
        with self.session_factory() as session:
            ver = session.get(PackageVersionRow, version_id)
            if ver is None:
                return False
            session.delete(ver)
            session.commit()
            return True

    def list_all_packages(
        self,
        *,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, object]]:
        """列出所有能力包（不限状态），含版本数和最新版本。"""
        with self.session_factory() as session:
            rows = session.execute(
                select(
                    PackageRow.id,
                    PackageRow.name,
                    PackageRow.status,
                    PackageRow.latest_version,
                    PackageRow.data,
                )
                .order_by(PackageRow.data["created_at"].as_string().desc().nullslast())
                .offset(offset)
                .limit(limit)
            ).all()
        packages: list[dict[str, object]] = []
        for row in rows:
            pkg_data = row.data or {}
            packages.append({
                "package_id": row.id,
                "package_name": row.name,
                "package_type": pkg_data.get("type"),
                "description": pkg_data.get("description"),
                "status": row.status,
                "latest_version": row.latest_version,
                "submitter_id": pkg_data.get("submitter_id"),
                "created_at": pkg_data.get("created_at"),
                "updated_at": pkg_data.get("updated_at"),
            })
        return packages

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
        author: dict[str, object] | None = None,
        license: str | None = None,
        source: dict[str, object] | None = None,
        integrity: dict[str, object] | None = None,
        permissions: dict[str, object] | None = None,
        compatibility: list[str] | None = None,
        installation: dict[str, object] | None = None,
        dependencies: dict[str, object] | None = None,
        field_source: dict[str, str] | None = None,
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
            "integrity": integrity,
            "permissions": permissions or {},
            "compatibility": compatibility or [],
            "description": description,
            "author": author,
            "license": license,
            "installation": installation,
            "dependencies": dependencies,
            "field_source": field_source,
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
            data = dict(row.data) if row.data else {}
            data["manual_grade"] = row.manual_grade if row.manual_grade and row.manual_grade != "F" else None
            data["manual_grade_by"] = row.manual_grade_by
            data["manual_grade_at"] = _serialize_dt(row.manual_grade_at) if row.manual_grade_at else None
            data["manual_grade_reason"] = row.manual_grade_reason
            if row.manual_grade_by:
                user_row = session.get(UserRow, row.manual_grade_by)
                if user_row:
                    data["manual_grade_by_name"] = user_row.display_name or user_row.email
            return data

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

    def set_manual_grade(
        self,
        *,
        version_id: str,
        grade: str | None,
        operator_id: str | None = None,
        reason: str | None = None,
    ) -> None:
        with self.session_factory() as session:
            row = session.get(PackageVersionRow, version_id)
            if row is None:
                return
            row.manual_grade = grade
            row.manual_grade_by = operator_id if grade else None
            row.manual_grade_at = _utc_now() if grade else None
            row.manual_grade_reason = reason if grade else None
            session.commit()

    def clear_manual_grade(self, version_id: str) -> None:
        self.set_manual_grade(version_id=version_id, grade=None)

    def update_package_status(
        self, package_id: str, new_status: str, latest_version: str | None = None
    ) -> None:
        """更新包状态，同步数据 JSON。"""
        with self.session_factory() as session:
            row = session.get(PackageRow, package_id)
            if row is None:
                return
            row.status = new_status
            if latest_version:
                row.latest_version = latest_version
            data = dict(row.data) if row.data else {}
            data["status"] = new_status
            if latest_version:
                data["latest_version"] = latest_version
            row.data = data
            session.commit()

    def update_package_data(
        self, package_id: str, updates: dict[str, object]
    ) -> None:
        with self.session_factory() as session:
            row = session.get(PackageRow, package_id)
            if row is None:
                return
            data = dict(row.data) if row.data else {}
            data.update(updates)
            row.data = data
            session.commit()

    def upsert_trust_level(
        self,
        *,
        version_id: str,
        level: str,
        recommendation: str,
    ) -> None:
        with self.session_factory() as session:
            existing = session.get(TrustLevelRow, version_id)
            if existing:
                existing.level = level
                existing.install_recommendation = recommendation
            else:
                session.add(TrustLevelRow(
                    version_id=version_id,
                    level=level,
                    install_recommendation=recommendation,
                    top_risks=[],
                    model_version="0.3.0",
                ))
            session.commit()

    def get_feedback_level_counts(
        self,
        package_id: str,
    ) -> dict[str, int]:
        """聚合某包的 level 反馈计数（positive/neutral/negative）。"""
        with self.session_factory() as session:
            rows = session.execute(
                select(FeedbackRecordRow.level, func.count())
                .where(FeedbackRecordRow.package_id == package_id)
                .group_by(FeedbackRecordRow.level)
            ).all()
        counts = {"positive": 0, "neutral": 0, "negative": 0}
        for level, count in rows:
            counts[str(level)] = int(count)
        return counts

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
                    "reviewer_name": row.reviewer_display_name,
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
                UserRow.display_name.label("operator_name"),
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
                .select_from(PackageRow)
                .where(PackageRow.status == "pending_review")
            ) or 0
            today_submissions = session.scalar(
                select(func.count(func.distinct(PackageVersionRow.package_id)))
                .select_from(PackageVersionRow)
                .where(
                    PackageVersionRow.data["submitted_at"]
                    .as_string()
                    >= today_start.isoformat()
                )
            ) or 0
            approved_count = session.scalar(
                select(func.count())
                .select_from(PackageRow)
                .where(PackageRow.status == "approved")
            ) or 0
            published_count = session.scalar(
                select(func.count())
                .select_from(PackageRow)
                .where(PackageRow.status == "published")
            ) or 0
            rejected_count = session.scalar(
                select(func.count())
                .select_from(PackageRow)
                .where(PackageRow.status == "rejected")
            ) or 0
            yanked_count = session.scalar(
                select(func.count())
                .select_from(PackageRow)
                .where(PackageRow.status == "yanked")
            ) or 0
            total_users = session.scalar(
                select(func.count())
                .select_from(UserRow)
                .where(UserRow.is_active.is_(True))
            ) or 0
            today_audit_actions = session.scalar(
                select(func.count())
                .select_from(AuditLogRow)
                .where(AuditLogRow.timestamp >= today_start)
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
            "total_users": total_users,
            "today_audit_actions": today_audit_actions,
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
                    "yank_reason": (row.data or {}).get("yank_reason"),
                    "trust_score": (row.data or {}).get("trust_score"),
                }
                for row in rows
            ]

    def list_versions_by_status(
        self,
        *,
        status: str | list[str] | None = None,
        grade: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, object]]:
        """按状态筛选版本列表（审核员视图用），带包名和扫描摘要。

        支持逗号分隔的多状态筛选、风险等级过滤、提交时间范围过滤。
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
                    PackageVersionRow.manual_grade,
                    PackageVersionRow.manual_grade_by,
                    PackageVersionRow.manual_grade_reason,
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

            if since:
                stmt = stmt.where(
                    PackageVersionRow.data["submitted_at"].as_string() >= since
                )
            if until:
                stmt = stmt.where(
                    PackageVersionRow.data["submitted_at"].as_string() <= until
                )

            stmt = stmt.order_by(
                PackageVersionRow.data["submitted_at"]
                .as_string()
                .desc()
                .nullslast()
            ).offset(offset).limit(limit)

            rows = session.execute(stmt).all()

        results: list[dict[str, object]] = []
        user_ids = {row.manual_grade_by for row in rows if row.manual_grade_by}
        user_names: dict[str, str] = {}
        if user_ids:
            with self.session_factory() as session:
                user_rows = session.execute(
                    select(UserRow.id, UserRow.display_name)
                    .where(UserRow.id.in_(user_ids))
                ).all()
                user_names = {r.id: r.display_name or r.id for r in user_rows}

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
                "auto_grade": grade_val,
                "manual_grade": row.manual_grade if row.manual_grade and row.manual_grade != "F" else None,
                "manual_grade_by": row.manual_grade_by,
                "manual_grade_by_name": user_names.get(row.manual_grade_by or "") if row.manual_grade_by else None,
                "manual_grade_reason": row.manual_grade_reason,
                "grade": (row.manual_grade if row.manual_grade and row.manual_grade != "F" else None) or grade_val,
                "findings_count": findings_count,
                "yank_reason": data.get("yank_reason"),
            })

        if grade:
            results = [r for r in results if r.get("grade") == grade]

        return results

    # ── 用户管理 ────────────────────────────────────────────

    def list_users(
        self,
        *,
        search: str | None = None,
        role: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, object]], int]:
        """分页查询用户列表，支持邮箱/昵称模糊搜索 + 角色筛选。"""
        with self.session_factory() as session:
            base = select(UserRow)
            count_base = select(func.count()).select_from(UserRow)

            if search:
                pattern = f"%{search}%"
                base = base.where(
                    UserRow.email.ilike(pattern) | UserRow.display_name.ilike(pattern)
                )
                count_base = count_base.where(
                    UserRow.email.ilike(pattern) | UserRow.display_name.ilike(pattern)
                )

            if role:
                base = base.where(UserRow.role == role)
                count_base = count_base.where(UserRow.role == role)

            total = session.scalar(count_base) or 0

            rows = session.execute(
                base.order_by(UserRow.created_at.desc()).offset(offset).limit(limit)
            ).scalars().all()

            items = [
                {
                    "id": row.id,
                    "email": row.email,
                    "display_name": row.display_name,
                    "role": row.role,
                    "is_active": row.is_active,
                    "created_at": _serialize_dt(row.created_at),
                }
                for row in rows
            ]
            return items, total

    def update_user_role(self, user_id: str, new_role: str) -> dict[str, object] | None:
        """更新用户角色。返回更新后的用户信息；若用户不存在返回 None；若角色未变返回特殊标记。
        
        Returns:
            dict with "conflict": True 表示角色未变化。
        """
        with self.session_factory() as session:
            user = session.get(UserRow, user_id)
            if user is None:
                return None
            if user.role == new_role:
                return {"conflict": True}
            user.role = new_role
            session.commit()
            return {
                "id": user.id,
                "email": user.email,
                "display_name": user.display_name,
                "role": user.role,
                "is_active": user.is_active,
                "created_at": _serialize_dt(user.created_at),
            }

    def update_user_status(self, user_id: str, is_active: bool) -> dict[str, object] | None:
        """启用或禁用用户账号。返回更新后的用户信息，若用户不存在返回 None。"""
        with self.session_factory() as session:
            user = session.get(UserRow, user_id)
            if user is None:
                return None
            user.is_active = is_active
            session.commit()
            return {
                "id": user.id,
                "email": user.email,
                "display_name": user.display_name,
                "role": user.role,
                "is_active": user.is_active,
                "created_at": _serialize_dt(user.created_at),
            }


def _version_brief(row: PackageVersionRow) -> dict[str, object]:
    data = dict(row.data) if row.data else {}
    return {
        "id": row.id,
        "version": row.version,
        "status": row.status,
        "submitted_at": data.get("submitted_at"),
        "created_at": data.get("created_at"),
    }
