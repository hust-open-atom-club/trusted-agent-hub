"""Drop username column from users (email-based auth).

Revision ID: 20260803_0009
Revises: 20260803_0008
Create Date: 2026-08-03
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "20260803_0009"
down_revision: str | None = "20260803_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """删除 users.username 列及其唯一索引（登录已改为 email）。

    早期库可能已在其他途径移除该列，做存在性检查保证幂等。
    """
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {
        col["name"]
        for col in inspector.get_columns("users")
    }
    indexes = {
        idx["name"]
        for idx in inspector.get_indexes("users")
    }
    if "username" in columns:
        with op.batch_alter_table("users") as batch_op:
            if "ix_users_username" in indexes:
                batch_op.drop_index("ix_users_username")
            batch_op.drop_column("username")


def downgrade() -> None:
    """恢复 username 列（幂等容错）。"""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {
        col["name"]
        for col in inspector.get_columns("users")
    }
    if "username" not in columns:
        with op.batch_alter_table("users") as batch_op:
            batch_op.add_column(
                sa.Column("username", sa.String(length=128), nullable=True)
            )
            batch_op.create_index(
                "ix_users_username",
                ["username"],
                unique=True,
            )
