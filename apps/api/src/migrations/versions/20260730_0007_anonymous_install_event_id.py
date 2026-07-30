"""Add event_id unique constraint, make user_id/install_path nullable for anonymous installs.

Revision ID: 20260730_0007
Revises: 20260728_0006
Create Date: 2026-07-30
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260730_0007"
down_revision: str | None = "20260728_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Drop old composite idempotency constraint
    with op.batch_alter_table("install_records") as batch_op:
        batch_op.drop_constraint("uq_install_idempotency", type_="unique")

    # Add event_id column (nullable during migration, then made unique)
    with op.batch_alter_table("install_records") as batch_op:
        batch_op.add_column(
            sa.Column("event_id", sa.String(128), nullable=True)
        )

    # Make user_id and install_path nullable for anonymous users
    with op.batch_alter_table("install_records") as batch_op:
        batch_op.alter_column("user_id", nullable=True)
        batch_op.alter_column("install_path", nullable=True)

    # Add unique constraint on event_id
    with op.batch_alter_table("install_records") as batch_op:
        batch_op.create_unique_constraint("uq_install_event_id", ["event_id"])


def downgrade() -> None:
    with op.batch_alter_table("install_records") as batch_op:
        batch_op.drop_constraint("uq_install_event_id", type_="unique")

    with op.batch_alter_table("install_records") as batch_op:
        batch_op.drop_column("event_id")

    with op.batch_alter_table("install_records") as batch_op:
        batch_op.alter_column("user_id", nullable=False)
        batch_op.alter_column("install_path", nullable=False)

    with op.batch_alter_table("install_records") as batch_op:
        batch_op.create_unique_constraint(
            "uq_install_idempotency",
            ["version_id", "user_id", "client", "install_path"],
        )
