"""Persist standalone repository scan tasks.

Standalone scans are created before a package/version exists, so their
state and report cannot be represented by the version-scoped ``scan_reports``
table.  This table is also the database ownership boundary for scan status
and result lookups.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "20260912_0001"
down_revision: str | None = "20260910_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the durable scan-task table and its lookup indexes."""
    op.create_table(
        "scan_tasks",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("owner_user_id", sa.String(length=64), nullable=False),
        sa.Column("client_request_id", sa.String(length=128), nullable=False),
        sa.Column("repo_url", sa.String(length=2048), nullable=False),
        sa.Column("version_id", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("package_name", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_token", sa.String(length=64), nullable=True),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "attempt_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "completion_delivered_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("summary", sa.JSON(), nullable=True),
        sa.Column("trust_score", sa.JSON(), nullable=True),
        sa.Column("llm_review", sa.JSON(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("capabilities", sa.JSON(), nullable=True),
        sa.Column("report_json", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["owner_user_id"], ["users.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["version_id"], ["package_versions.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "owner_user_id",
            "client_request_id",
            name="uq_scan_tasks_owner_request",
        ),
    )
    op.create_index(
        "ix_scan_tasks_owner_user_id",
        "scan_tasks",
        ["owner_user_id"],
        unique=False,
    )
    op.create_index(
        "ix_scan_tasks_version_id",
        "scan_tasks",
        ["version_id"],
        unique=False,
    )
    op.create_index(
        "ix_scan_tasks_status",
        "scan_tasks",
        ["status"],
        unique=False,
    )
    op.create_index(
        "ix_scan_tasks_expires_at",
        "scan_tasks",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_scan_tasks_lease_until",
        "scan_tasks",
        ["lease_until"],
        unique=False,
    )


def downgrade() -> None:
    """Remove the durable scan-task table."""
    op.drop_index("ix_scan_tasks_lease_until", table_name="scan_tasks")
    op.drop_index("ix_scan_tasks_expires_at", table_name="scan_tasks")
    op.drop_index("ix_scan_tasks_status", table_name="scan_tasks")
    op.drop_index("ix_scan_tasks_version_id", table_name="scan_tasks")
    op.drop_index("ix_scan_tasks_owner_user_id", table_name="scan_tasks")
    op.drop_table("scan_tasks")
