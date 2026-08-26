"""Persist the deterministic trust-score model fingerprint.

The legacy ``model_version`` column remains for API compatibility, but score
backfill decisions use ``model_fingerprint`` so source/config changes cannot
be missed because a human forgot to bump a string.

Revision ID: 20260826_0011
Revises: 20260826_0010
Create Date: 2026-08-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "20260826_0011"
down_revision: str | None = "20260826_0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add a nullable identity column for legacy trust-level rows."""
    op.add_column(
        "trust_levels",
        sa.Column("model_fingerprint", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    """Remove the model identity column."""
    op.drop_column("trust_levels", "model_fingerprint")
