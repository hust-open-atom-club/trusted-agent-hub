"""Add a per-user authentication version for session invalidation.

Password changes increment ``auth_version`` so previously issued access and
refresh tokens can no longer be used. Existing users start at version zero.
Tokens issued before the typed-token format was deployed must be replaced by
logging in again.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "20260908_0001"
down_revision: str | None = "20260826_0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the authentication version column to users."""
    op.add_column(
        "users",
        sa.Column(
            "auth_version",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )


def downgrade() -> None:
    """Remove the authentication version column."""
    op.drop_column("users", "auth_version")
