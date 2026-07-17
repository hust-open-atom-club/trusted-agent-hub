"""SQLAlchemy ORM models for Consumer persistence."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class PackageRow(Base):
    __tablename__ = "packages"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    latest_version: Mapped[str] = mapped_column(String(64))
    data: Mapped[dict[str, object]] = mapped_column(JSON)

    versions: Mapped[list[PackageVersionRow]] = relationship(
        back_populates="package",
        cascade="all, delete-orphan",
    )
    feedback: Mapped[list[FeedbackRecordRow]] = relationship(
        back_populates="package",
        cascade="all, delete-orphan",
    )


class PackageVersionRow(Base):
    __tablename__ = "package_versions"
    __table_args__ = (
        UniqueConstraint("package_id", "version", name="uq_package_version"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    package_id: Mapped[str] = mapped_column(
        ForeignKey("packages.id", ondelete="CASCADE"),
        index=True,
    )
    version: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    data: Mapped[dict[str, object]] = mapped_column(JSON)

    package: Mapped[PackageRow] = relationship(back_populates="versions")
    trust_level: Mapped[TrustLevelRow | None] = relationship(
        back_populates="version",
        cascade="all, delete-orphan",
    )
    installs: Mapped[list[InstallRecordRow]] = relationship(
        back_populates="version",
        cascade="all, delete-orphan",
    )


class TrustLevelRow(Base):
    __tablename__ = "trust_levels"
    __table_args__ = (
        CheckConstraint(
            "level IN ('trusted', 'low_risk', 'medium_risk', 'high_risk', 'untrusted')",
            name="ck_trust_levels_level",
        ),
    )

    version_id: Mapped[str] = mapped_column(
        ForeignKey("package_versions.id", ondelete="CASCADE"),
        primary_key=True,
    )
    level: Mapped[str] = mapped_column(String(32), index=True)
    install_recommendation: Mapped[str] = mapped_column(String(64))
    top_risks: Mapped[list[str]] = mapped_column(JSON, default=list)
    explanation: Mapped[str | None] = mapped_column(Text)
    model_version: Mapped[str] = mapped_column(String(64))
    calculated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )

    version: Mapped[PackageVersionRow] = relationship(back_populates="trust_level")


class InstallRecordRow(Base):
    __tablename__ = "install_records"
    __table_args__ = (
        UniqueConstraint(
            "version_id",
            "user_id",
            "client",
            "install_path",
            name="uq_install_idempotency",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version_id: Mapped[str] = mapped_column(
        ForeignKey("package_versions.id", ondelete="CASCADE"),
        index=True,
    )
    user_id: Mapped[str] = mapped_column(String(128), index=True)
    client: Mapped[str] = mapped_column(String(64), index=True)
    install_path: Mapped[str] = mapped_column(String(512))
    integrity_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    installed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )

    version: Mapped[PackageVersionRow] = relationship(back_populates="installs")


class FeedbackRecordRow(Base):
    __tablename__ = "feedback_records"
    __table_args__ = (
        UniqueConstraint("package_id", "user_id", name="uq_feedback_user_package"),
        CheckConstraint(
            "level IN ('positive', 'neutral', 'negative')",
            name="ck_feedback_records_level",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    package_id: Mapped[str] = mapped_column(
        ForeignKey("packages.id", ondelete="CASCADE"),
        index=True,
    )
    user_id: Mapped[str] = mapped_column(String(128), index=True)
    level: Mapped[str] = mapped_column(String(32), index=True)
    comment: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )

    package: Mapped[PackageRow] = relationship(back_populates="feedback")
