"""Persist refresh-token state for one-time rotation.

JWT signatures and expiry are not sufficient to consume a refresh token only
once.  This table records each issued refresh token and its first use so a
replayed token is rejected by the API.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "20260908_0002"
down_revision: str | None = "20260908_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the one-time refresh-token state table."""
    op.create_table(
        "refresh_tokens",
        sa.Column("jti", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("jti"),
    )
    op.create_index(
        "ix_refresh_tokens_user_id",
        "refresh_tokens",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_refresh_tokens_expires_at",
        "refresh_tokens",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_refresh_tokens_used_at",
        "refresh_tokens",
        ["used_at"],
        unique=False,
    )


def downgrade() -> None:
    """Remove the refresh-token state table."""
    op.drop_index("ix_refresh_tokens_used_at", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_expires_at", table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_user_id", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")
