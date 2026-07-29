"""Add manual_grade columns to package_versions table.

Revision ID: 20260728_0005
Revises: 20260722_0004
Create Date: 2026-07-28
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "20260728_0005"
down_revision: str | None = "20260722_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("package_versions", sa.Column(
        "manual_grade", sa.String(2), nullable=True,
        comment="手动评级: A/B/C/D/E, null=使用自动评分",
    ))
    op.add_column("package_versions", sa.Column(
        "manual_grade_by", sa.String(64), nullable=True,
        comment="最后修改 manual_grade 的用户 ID",
    ))
    op.add_column("package_versions", sa.Column(
        "manual_grade_at", sa.DateTime(timezone=True), nullable=True,
        comment="最后修改 manual_grade 的时间",
    ))
    op.add_column("package_versions", sa.Column(
        "manual_grade_reason", sa.Text, nullable=True,
        comment="手动评级理由",
    ))
    op.create_index(
        "ix_package_versions_manual_grade",
        "package_versions", ["manual_grade"],
    )


def downgrade() -> None:
    op.drop_index("ix_package_versions_manual_grade", table_name="package_versions")
    op.drop_column("package_versions", "manual_grade_reason")
    op.drop_column("package_versions", "manual_grade_at")
    op.drop_column("package_versions", "manual_grade_by")
    op.drop_column("package_versions", "manual_grade")
