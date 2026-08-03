"""Normalize audit_logs action values for review conclusions.

Legacy rows written by ProducerService.review_version stored the raw
conclusion ("approved" / "rejected") instead of the AuditAction constants
("approve" / "reject"). This migration rewrites historical rows so the
audit action values are consistent with packages/schema/constants.py and
the frontend filter options.

Revision ID: 20260803_0008
Revises: 20260803_0007
Create Date: 2026-08-03
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260803_0008"
down_revision: str | None = "20260803_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE audit_logs SET action = 'approve' WHERE action = 'approved'"
        )
    )
    op.execute(
        sa.text(
            "UPDATE audit_logs SET action = 'reject' WHERE action = 'rejected'"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE audit_logs SET action = 'approved' WHERE action = 'approve'"
        )
    )
    op.execute(
        sa.text(
            "UPDATE audit_logs SET action = 'rejected' WHERE action = 'reject'"
        )
    )
