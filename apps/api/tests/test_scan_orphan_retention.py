"""Retention contracts for version-attached and orphaned scan tasks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.repositories.orm import PackageRow, PackageVersionRow
from src.repositories.producer_sqlalchemy import ProducerRepository
from src.routers import trust
from tests.test_scan_task_persistence import scan_repository


DRAFT_VERSION_ID = "atomic-version"
DRAFT_PACKAGE_ID = "atomic-package"
DRAFT_SOURCE_URL = "https://github.com/acme/demo"


def _create_draft_version(repository: ProducerRepository) -> None:
    if repository.get_version(DRAFT_VERSION_ID) is not None:
        return
    with repository.session_factory() as session:
        session.add(
            PackageRow(
                id=DRAFT_PACKAGE_ID,
                name=DRAFT_PACKAGE_ID,
                status="draft",
                latest_version="1.0.0",
                data={"submitter_id": "scan-user-1"},
            )
        )
        session.add(
            PackageVersionRow(
                id="atomic-version",
                package_id="atomic-package",
                version="1.0.0",
                status="draft",
                data={
                    "status": "draft",
                    "source": {
                        "repository_url": "https://github.com/acme/demo"
                    },
                },
            )
        )
        session.commit()


def test_delete_version_backfills_scan_task_retention(
    scan_repository: tuple[ProducerRepository, object],
) -> None:
    """Deleting a version sets expires_at on its attached scan tasks."""
    repository, _ = scan_repository
    _create_draft_version(repository)
    repository.create_scan_task(
        scan_id="scan-orphan-1",
        owner_user_id="scan-user-1",
        client_request_id="request-orphan-1",
        repo_url=DRAFT_SOURCE_URL,
        status="complete",
        callback_status="delivered",
        version_id=DRAFT_VERSION_ID,
    )

    # While attached: no retention deadline, holding the dedup key.
    attached = repository.get_scan_task("scan-orphan-1")
    assert attached is not None
    assert attached["version_id"] == DRAFT_VERSION_ID
    assert attached["expires_at"] is None

    assert repository.delete_version(DRAFT_VERSION_ID) is True

    # The version row is gone; the scan task survives (audit trail) with a
    # retention deadline so the normal expiry cleaner can reclaim it.
    assert repository.get_version(DRAFT_VERSION_ID) is None
    orphaned = repository.get_scan_task("scan-orphan-1")
    assert orphaned is not None
    assert orphaned["version_id"] is None
    assert orphaned["status"] == "complete"
    assert orphaned["expires_at"] is not None

    # The expired orphan is now reclaimable by the standard cleaner.
    deleted = repository.delete_expired_scan_tasks(
        now=datetime.now(timezone.utc) + timedelta(days=31),
    )
    assert deleted == 1
    assert repository.get_scan_task("scan-orphan-1") is None


def test_backfill_orphan_scan_task_retention_reclaims_legacy_orphans(
    scan_repository: tuple[ProducerRepository, object],
) -> None:
    """Maintenance backfills NULL-expires rows detached from versions."""
    repository, _ = scan_repository
    _create_draft_version(repository)
    repository.create_scan_task(
        scan_id="scan-legacy-orphan",
        owner_user_id="scan-user-1",
        client_request_id="request-legacy-orphan",
        repo_url=DRAFT_SOURCE_URL,
        status="complete",
        callback_status="delivered",
        version_id=DRAFT_VERSION_ID,
    )
    # Simulate a version removal that bypassed delete_version (legacy row):
    # FK ondelete=SET NULL leaves expires_at untouched.
    with repository.session_factory() as session:
        from sqlalchemy import delete as sa_delete

        session.execute(
            sa_delete(PackageVersionRow).where(
                PackageVersionRow.id == DRAFT_VERSION_ID
            )
        )
        session.commit()

    orphaned = repository.get_scan_task("scan-legacy-orphan")
    assert orphaned is not None
    assert orphaned["version_id"] is None
    assert orphaned["expires_at"] is None

    # Active tasks and rows still attached to versions must be untouched.
    repository.create_scan_task(
        scan_id="scan-orphan-running",
        owner_user_id="scan-user-1",
        client_request_id="request-orphan-running",
        repo_url="https://github.com/acme/running",
        status="scanning",
        callback_status="not_required",
    )

    count = repository.backfill_orphan_scan_task_retention()
    assert count == 1

    backfilled = repository.get_scan_task("scan-legacy-orphan")
    assert backfilled is not None
    assert backfilled["expires_at"] is not None

    running = repository.get_scan_task("scan-orphan-running")
    assert running is not None
    assert running["expires_at"] is None


def test_run_scan_maintenance_backfills_orphans(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """run_scan_maintenance wires the orphan backfill into its loop."""
    repository, _ = scan_repository
    _create_draft_version(repository)
    repository.create_scan_task(
        scan_id="scan-maintenance-orphan",
        owner_user_id="scan-user-1",
        client_request_id="request-maintenance-orphan",
        repo_url=DRAFT_SOURCE_URL,
        status="complete",
        callback_status="delivered",
        version_id=DRAFT_VERSION_ID,
    )
    with repository.session_factory() as session:
        from sqlalchemy import delete as sa_delete

        session.execute(
            sa_delete(PackageVersionRow).where(
                PackageVersionRow.id == DRAFT_VERSION_ID
            )
        )
        session.commit()
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    monkeypatch.setattr(trust, "_cleanup_orphan_scan_temp_dirs", lambda: None)

    trust.run_scan_maintenance()

    backfilled = repository.get_scan_task("scan-maintenance-orphan")
    assert backfilled is not None
    assert backfilled["expires_at"] is not None
