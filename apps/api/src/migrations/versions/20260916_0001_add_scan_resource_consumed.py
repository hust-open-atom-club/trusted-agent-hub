"""Persist whether a scan result has been consumed by submission."""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260916_0001"
down_revision: str | None = "20260913_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scan_tasks",
        sa.Column(
            "resource_consumed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    op.drop_column("scan_tasks", "resource_consumed")
