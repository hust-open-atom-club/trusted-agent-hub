"""Invalidate sessions issued before the short-session policy.

The token lifetime encoded in an existing JWT cannot be shortened
retroactively. Incrementing every user's authentication version invalidates
previous access and refresh tokens, while removing the refresh-token rows
prevents the old seven-day sessions from being rotated.

This data migration is intentionally irreversible: restoring an old
``auth_version`` could make a previously issued access token valid again.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "20260910_0001"
down_revision: str | None = "20260908_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Revoke every session issued before this policy was deployed."""
    op.execute(sa.text("UPDATE users SET auth_version = auth_version + 1"))
    op.execute(sa.text("DELETE FROM refresh_tokens"))


def downgrade() -> None:
    """Keep revoked sessions revoked when rolling the application back."""
    pass
