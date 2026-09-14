"""Persist immutable scan identity and callback delivery state."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "20260912_0002"
down_revision: str | None = "20260912_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the fields needed to resume scans without moving the source."""
    op.add_column(
        "scan_tasks",
        sa.Column("source_ref", sa.String(length=512), nullable=True),
    )
    op.add_column(
        "scan_tasks",
        sa.Column("commit_hash", sa.String(length=40), nullable=True),
    )
    op.add_column(
        "scan_tasks",
        sa.Column("source_subdirectory", sa.String(length=2048), nullable=True),
    )
    op.add_column(
        "scan_tasks",
        sa.Column("callback_status", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "scan_tasks",
        sa.Column(
            "callback_attempt_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.add_column(
        "scan_tasks",
        sa.Column("callback_next_attempt_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "scan_tasks",
        sa.Column("callback_last_error", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_scan_tasks_callback_next_attempt_at",
        "scan_tasks",
        ["callback_next_attempt_at"],
        unique=False,
    )


def downgrade() -> None:
    """Remove immutable identity and callback delivery fields."""
    op.drop_index(
        "ix_scan_tasks_callback_next_attempt_at",
        table_name="scan_tasks",
    )
    op.drop_column("scan_tasks", "callback_last_error")
    op.drop_column("scan_tasks", "callback_next_attempt_at")
    op.drop_column("scan_tasks", "callback_attempt_count")
    op.drop_column("scan_tasks", "callback_status")
    op.drop_column("scan_tasks", "source_subdirectory")
    op.drop_column("scan_tasks", "commit_hash")
    op.drop_column("scan_tasks", "source_ref")
