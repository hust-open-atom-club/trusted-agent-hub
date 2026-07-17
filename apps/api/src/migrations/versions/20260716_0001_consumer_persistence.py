"""Create Consumer persistence tables.

Revision ID: 20260716_0001
Revises:
Create Date: 2026-07-16
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260716_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "packages",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("latest_version", sa.String(length=64), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_packages_name", "packages", ["name"], unique=True)
    op.create_index("ix_packages_status", "packages", ["status"], unique=False)

    op.create_table(
        "package_versions",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("package_id", sa.String(length=64), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["package_id"], ["packages.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("package_id", "version", name="uq_package_version"),
    )
    op.create_index(
        "ix_package_versions_package_id",
        "package_versions",
        ["package_id"],
        unique=False,
    )
    op.create_index(
        "ix_package_versions_status",
        "package_versions",
        ["status"],
        unique=False,
    )
    op.create_index(
        "ix_package_versions_version",
        "package_versions",
        ["version"],
        unique=False,
    )

    op.create_table(
        "trust_levels",
        sa.Column("version_id", sa.String(length=64), nullable=False),
        sa.Column("level", sa.String(length=32), nullable=False),
        sa.Column("install_recommendation", sa.String(length=64), nullable=False),
        sa.Column("top_risks", sa.JSON(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=True),
        sa.Column("model_version", sa.String(length=64), nullable=False),
        sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "level IN ('trusted', 'low_risk', 'medium_risk', "
            "'high_risk', 'untrusted')",
            name="ck_trust_levels_level",
        ),
        sa.ForeignKeyConstraint(
            ["version_id"], ["package_versions.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("version_id"),
    )
    op.create_index(
        "ix_trust_levels_level", "trust_levels", ["level"], unique=False
    )

    op.create_table(
        "install_records",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("version_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=128), nullable=False),
        sa.Column("client", sa.String(length=64), nullable=False),
        sa.Column("install_path", sa.String(length=512), nullable=False),
        sa.Column("integrity_verified", sa.Boolean(), nullable=False),
        sa.Column("installed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["version_id"], ["package_versions.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "version_id",
            "user_id",
            "client",
            "install_path",
            name="uq_install_idempotency",
        ),
    )
    op.create_index(
        "ix_install_records_client", "install_records", ["client"], unique=False
    )
    op.create_index(
        "ix_install_records_user_id",
        "install_records",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_install_records_version_id",
        "install_records",
        ["version_id"],
        unique=False,
    )

    op.create_table(
        "feedback_records",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("package_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=128), nullable=False),
        sa.Column("level", sa.String(length=32), nullable=False),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "level IN ('positive', 'neutral', 'negative')",
            name="ck_feedback_records_level",
        ),
        sa.ForeignKeyConstraint(
            ["package_id"], ["packages.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "package_id", "user_id", name="uq_feedback_user_package"
        ),
    )
    op.create_index(
        "ix_feedback_records_level",
        "feedback_records",
        ["level"],
        unique=False,
    )
    op.create_index(
        "ix_feedback_records_package_id",
        "feedback_records",
        ["package_id"],
        unique=False,
    )
    op.create_index(
        "ix_feedback_records_user_id",
        "feedback_records",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_feedback_records_user_id", table_name="feedback_records")
    op.drop_index("ix_feedback_records_package_id", table_name="feedback_records")
    op.drop_index("ix_feedback_records_level", table_name="feedback_records")
    op.drop_table("feedback_records")
    op.drop_index("ix_install_records_version_id", table_name="install_records")
    op.drop_index("ix_install_records_user_id", table_name="install_records")
    op.drop_index("ix_install_records_client", table_name="install_records")
    op.drop_table("install_records")
    op.drop_index("ix_trust_levels_level", table_name="trust_levels")
    op.drop_table("trust_levels")
    op.drop_index(
        "ix_package_versions_version", table_name="package_versions"
    )
    op.drop_index("ix_package_versions_status", table_name="package_versions")
    op.drop_index(
        "ix_package_versions_package_id", table_name="package_versions"
    )
    op.drop_table("package_versions")
    op.drop_index("ix_packages_status", table_name="packages")
    op.drop_index("ix_packages_name", table_name="packages")
    op.drop_table("packages")
