"""供给侧 ORM 模型定义。

对应 Alembic migration 创建的供给侧表：
- users: 用户账户
- refresh_tokens: 一次性 refresh token 消费状态
- review_records: 审核记录
- scan_reports: 扫描报告
- scan_tasks: 可恢复的扫描任务状态与报告
- audit_logs: 审计日志
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from src.database import Base


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class UserRow(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("email", name="uq_users_email"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    email: Mapped[str] = mapped_column(String(256), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(32), index=True)
    display_name: Mapped[str] = mapped_column(String(128))
    auth_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        server_default=text("true"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now
    )


class RefreshTokenRow(Base):
    """One-time server-side state for refresh-token rotation."""

    __tablename__ = "refresh_tokens"

    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utc_now, nullable=False
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


class ScanTaskRow(Base):
    """Durable state for a user-created repository scan.

    A scan can exist before a package/version is created.  Keeping this
    lifecycle separate from ``scan_reports`` lets the submit page recover a
    scan after a browser refresh and lets the API enforce ownership from the
    database instead of relying on the process-local ``_scans`` cache.
    """

    __tablename__ = "scan_tasks"
    __table_args__ = (
        UniqueConstraint(
            "owner_user_id",
            "client_request_id",
            name="uq_scan_tasks_owner_request",
        ),
        Index(
            "uq_scan_tasks_source_identity",
            "owner_user_id",
            "dedup_repo_url",
            text("COALESCE(source_subdirectory, '')"),
            unique=True,
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    owner_user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    client_request_id: Mapped[str] = mapped_column(
        String(128), nullable=False
    )
    repo_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    # Normalized repository identity used for source-level dedup. The
    # unique index above covers (owner, dedup_repo_url, source_subdirectory)
    # so two tasks for the same repository target cannot coexist.
    dedup_repo_url: Mapped[str] = mapped_column(
        String(2048), nullable=False, server_default=text("''")
    )
    # The ref is retained for provenance; commit_hash is the immutable
    # acquisition identity used by every resumed execution.
    source_ref: Mapped[str | None] = mapped_column(
        String(512), nullable=True
    )
    commit_hash: Mapped[str | None] = mapped_column(
        String(40), nullable=True
    )
    source_subdirectory: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )
    version_id: Mapped[str | None] = mapped_column(
        ForeignKey("package_versions.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    status: Mapped[str] = mapped_column(
        String(32), index=True, nullable=False
    )
    package_name: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    lease_token: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    lease_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True, nullable=True
    )
    attempt_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    completion_delivered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    callback_status: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )
    callback_attempt_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    callback_next_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True, nullable=True
    )
    callback_last_error: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True, nullable=True
    )
    summary: Mapped[dict[str, object] | None] = mapped_column(
        JSON, nullable=True
    )
    trust_score: Mapped[dict[str, object] | None] = mapped_column(
        JSON, nullable=True
    )
    llm_review: Mapped[dict[str, object] | None] = mapped_column(
        JSON, nullable=True
    )
    metadata_json: Mapped[dict[str, object] | None] = mapped_column(
        JSON, nullable=True
    )
    capabilities: Mapped[list[dict[str, object]] | None] = mapped_column(
        JSON, nullable=True
    )
    report_json: Mapped[dict[str, object] | None] = mapped_column(
        JSON, nullable=True
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


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
