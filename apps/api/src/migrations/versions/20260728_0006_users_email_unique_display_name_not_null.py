"""Add UNIQUE constraint on users.email and make display_name NOT NULL.

Revision ID: 20260728_0006
Revises: 20260728_0005
Create Date: 2026-07-28
"""

from collections.abc import Sequence

from alembic import op


revision: str = "20260728_0006"
down_revision: str | None = "20260728_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_unique_constraint("uq_users_email", "users", ["email"])
    op.alter_column("users", "display_name", nullable=False)


def downgrade() -> None:
    op.drop_constraint("uq_users_email", "users", type_="unique")
    op.alter_column("users", "display_name", nullable=True)
