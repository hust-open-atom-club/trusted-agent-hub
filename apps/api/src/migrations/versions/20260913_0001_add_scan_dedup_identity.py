"""Add source-level dedup identity to scan tasks."""

from collections.abc import Sequence
import logging

import sqlalchemy as sa
from alembic import op

revision: str = "20260913_0001"
down_revision: str | None = "20260912_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_LOGGER = logging.getLogger("alembic.runtime.migration")


def _canonical_repo_url(url: object) -> str | None:
    """Normalize repository URLs like the runtime dedup helper."""
    if not isinstance(url, str):
        return None
    raw = url.strip()
    if not raw.lower().startswith("https://github.com/"):
        return raw.rstrip("/")
    path = raw[len("https://github.com/"):].strip("/")
    parts = [part for part in path.split("/") if part]
    if len(parts) < 2:
        return raw.rstrip("/")
    owner = parts[0].casefold()
    repo = parts[1].casefold()
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"https://github.com/{owner}/{repo}"


# Prefer a version-attached keeper; delete only detached terminal duplicates.
# Protected duplicates remain for an operator to resolve.
_SAFE_DUPLICATE_DELETE_SQL = """
DELETE FROM scan_tasks
WHERE id IN (
    SELECT id
    FROM (
        SELECT id,
               ROW_NUMBER() OVER (
                   PARTITION BY owner_user_id, dedup_repo_url,
                                COALESCE(source_subdirectory, '')
                   ORDER BY (version_id IS NOT NULL) DESC, id
               ) AS rank_in_group,
               version_id, callback_status, status
        FROM scan_tasks
    ) ranked
    WHERE rank_in_group > 1
      AND version_id IS NULL
      AND (callback_status IS NULL
           OR callback_status IN ('delivered', 'not_required'))
      AND status IN ('error', 'llm_timeout', 'total_timeout', 'complete')
)
"""

# Protected duplicates block the unique index and require manual resolution.
_CONFLICT_DUPLICATE_SQL = """
SELECT id, owner_user_id, dedup_repo_url, source_subdirectory, version_id,
       callback_status, status
FROM scan_tasks
WHERE (owner_user_id, dedup_repo_url, COALESCE(source_subdirectory, ''))
      IN (
          SELECT owner_user_id, dedup_repo_url,
                 COALESCE(source_subdirectory, '')
          FROM scan_tasks
          GROUP BY owner_user_id,
                   dedup_repo_url,
                   COALESCE(source_subdirectory, '')
          HAVING COUNT(*) > 1
      )
ORDER BY owner_user_id, dedup_repo_url, id
"""


def _backfill_dedup_keys(connection: sa.Connection) -> None:
    """Backfill keys, deleting only safe duplicates before index creation."""
    rows = connection.execute(
        sa.text("SELECT id, repo_url FROM scan_tasks")
    ).fetchall()
    for row_id, repo_url in rows:
        connection.execute(
            sa.text(
                "UPDATE scan_tasks SET dedup_repo_url = :key WHERE id = :id"
            ),
            {"key": _canonical_repo_url(repo_url), "id": row_id},
        )
    connection.execute(sa.text(_SAFE_DUPLICATE_DELETE_SQL))

    conflicts = connection.execute(sa.text(_CONFLICT_DUPLICATE_SQL)).fetchall()
    if conflicts:
        conflict_list = [
            {
                "id": row.id,
                "owner_user_id": row.owner_user_id,
                "dedup_repo_url": row.dedup_repo_url,
                "source_subdirectory": row.source_subdirectory,
                "version_id": row.version_id,
                "callback_status": row.callback_status,
                "status": row.status,
            }
            for row in conflicts
        ]
        _LOGGER.warning(
            "scan_tasks rows sharing a source identity that were kept for "
            "manual resolution: %s",
            conflict_list,
        )
        raise RuntimeError(
            "Cannot create the scan-task source-identity unique index: "
            f"{len(conflicts)} retained duplicate scan tasks share a "
            "(owner, repository, subdirectory) identity. Automatic cleanup "
            "only removes detached terminal rows; the rows listed in the "
            "warning above are attached to a version, still executing, or "
            "still owe a completion callback, so the migration refuses to "
            "delete them. Pick one task per identity to keep (the version's "
            "scan report lives in scan_reports and is not affected), "
            "DELETE the others, then rerun the upgrade. No changes were "
            "committed."
        )


def upgrade() -> None:
    """Backfill keys, then enforce uniqueness per owner, repo and subdir."""
    op.add_column(
        "scan_tasks",
        sa.Column(
            "dedup_repo_url",
            sa.String(length=2048),
            nullable=False,
            server_default=sa.text("''"),
        ),
    )
    if op.get_context().as_sql:
        # Offline mode cannot inspect data; duplicate rows intentionally make
        # index creation fail instead of silently deleting protected history.
        op.create_index(
            "uq_scan_tasks_source_identity",
            "scan_tasks",
            [
                "owner_user_id",
                "dedup_repo_url",
                sa.text("COALESCE(source_subdirectory, '')"),
            ],
            unique=True,
        )
        return

    connection = op.get_bind()
    _backfill_dedup_keys(connection)
    # NULL subdirectory sorts differently across engines inside unique
    # indexes; normalize it through the expression instead.
    op.create_index(
        "uq_scan_tasks_source_identity",
        "scan_tasks",
        [
            "owner_user_id",
            "dedup_repo_url",
            sa.text("COALESCE(source_subdirectory, '')"),
        ],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "uq_scan_tasks_source_identity",
        table_name="scan_tasks",
    )
    op.drop_column("scan_tasks", "dedup_repo_url")
