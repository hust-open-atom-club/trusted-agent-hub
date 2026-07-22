"""供给侧 ORM 模型定义。

对应迁移 20260717_0002_producer_tables.py 创建的四张表：
- users: 用户账户
- review_records: 审核记录
- scan_reports: 扫描报告
- audit_logs: 审计日志
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from src.database import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class UserRow(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(32), index=True)
    email: Mapped[str | None] = mapped_column(String(256), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now
    )


class ReviewRecordRow(Base):
    __tablename__ = "review_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version_id: Mapped[str] = mapped_column(
        ForeignKey("package_versions.id", ondelete="CASCADE"),
        index=True,
    )
    reviewer_id: Mapped[str] = mapped_column(String(64))
    conclusion: Mapped[str] = mapped_column(String(32), index=True)
    comment: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now
    )


class ScanReportRow(Base):
    __tablename__ = "scan_reports"

    version_id: Mapped[str] = mapped_column(
        ForeignKey("package_versions.id", ondelete="CASCADE"),
        primary_key=True,
    )
    scan_json: Mapped[dict[str, object]] = mapped_column(JSON)
    report_path: Mapped[str | None] = mapped_column(String(512))
    scanned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now
    )


class AuditLogRow(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    action: Mapped[str] = mapped_column(String(64))
    target_type: Mapped[str] = mapped_column(String(64))
    target_id: Mapped[str] = mapped_column(String(64))
    operator_id: Mapped[str] = mapped_column(String(64))
    detail: Mapped[dict[str, object] | None] = mapped_column(JSON)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now
    )
