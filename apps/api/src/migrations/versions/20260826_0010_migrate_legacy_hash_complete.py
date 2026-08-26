"""Normalize legacy integrity completeness markers in persisted JSON data.

Older records used ``hash_complete`` while the current contract uses
``is_complete``.  The values live inside JSON columns rather than dedicated
database columns, so the rename needs an explicit data migration before the
strict contract models are used against historical rows.

Revision ID: 20260826_0010
Revises: 20260826_0001
Create Date: 2026-08-26
"""

from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op


revision: str = "20260826_0010"
down_revision: str | None = "20260826_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_PACKAGE_VERSION_PATHS: tuple[tuple[str, ...], ...] = (
    ("integrity",),
    ("acquisition_facts", "integrity"),
    ("scan_report", "provenance", "acquisition_facts", "integrity"),
)
_SCAN_REPORT_PATHS: tuple[tuple[str, ...], ...] = (
    ("provenance", "acquisition_facts", "integrity"),
)


def _normalize_integrity(integrity: Any) -> bool:
    """Normalize one integrity object and return whether it changed.

    A valid canonical boolean always wins when both markers are present.  An
    unknown legacy value is explicitly converted to ``False`` so the
    migration never upgrades uncertain data into a trusted completeness
    claim.  Objects with neither marker are left untouched; the current
    contract already treats a missing value as fail-closed.
    """
    if not isinstance(integrity, dict) or "hash_complete" not in integrity:
        return False

    legacy_value = integrity.pop("hash_complete")
    if "is_complete" in integrity:
        # An explicit canonical value, including an unknown/null value, wins
        # over the legacy marker.  Unknown canonical values fail closed.
        if not isinstance(integrity["is_complete"], bool):
            integrity["is_complete"] = False
    else:
        integrity["is_complete"] = (
            legacy_value if isinstance(legacy_value, bool) else False
        )
    return True


def _normalize_document(
    document: Any,
    paths: tuple[tuple[str, ...], ...],
) -> bool:
    """Normalize integrity objects at the specified JSON paths."""
    changed = False
    if not isinstance(document, dict):
        return changed

    for path in paths:
        current: Any = document
        for key in path[:-1]:
            if not isinstance(current, dict):
                current = None
                break
            current = current.get(key)
        if isinstance(current, dict):
            changed = _normalize_integrity(current.get(path[-1])) or changed
    return changed


def _normalize_json_column(
    bind: sa.Connection,
    *,
    table_name: str,
    key_column_name: str,
    json_column_name: str,
    paths: tuple[tuple[str, ...], ...],
) -> None:
    """Rewrite changed JSON documents in one database table.

    Rows are materialized before updates so this remains safe on SQLite and
    PostgreSQL while the same connection is used for the migration
    transaction.
    """
    table = sa.table(
        table_name,
        sa.column(key_column_name, sa.String(length=128)),
        sa.column(json_column_name, sa.JSON()),
    )
    rows = bind.execute(
        sa.select(table.c[key_column_name], table.c[json_column_name])
    ).mappings().all()

    for row in rows:
        document = row[json_column_name]
        if not _normalize_document(document, paths):
            continue
        bind.execute(
            sa.update(table)
            .where(table.c[key_column_name] == row[key_column_name])
            .values({json_column_name: document})
        )


def upgrade() -> None:
    """Convert legacy markers and remove the obsolete JSON key."""
    bind = op.get_bind()
    _normalize_json_column(
        bind,
        table_name="package_versions",
        key_column_name="id",
        json_column_name="data",
        paths=_PACKAGE_VERSION_PATHS,
    )
    _normalize_json_column(
        bind,
        table_name="scan_reports",
        key_column_name="version_id",
        json_column_name="scan_json",
        paths=_SCAN_REPORT_PATHS,
    )


def downgrade() -> None:
    """Leave normalized data unchanged; the legacy key is intentionally removed."""
    # Reconstructing ``hash_complete`` would not be lossless for records that
    # contained both markers, so this data-cleanup migration is intentionally
    # irreversible.
    pass
