"""Retention contracts for version-attached and orphaned scan tasks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.repositories.orm import PackageRow, PackageVersionRow
from src.repositories.producer_sqlalchemy import ProducerRepository
from src.routers import trust
from src.version_deletion import VersionDeletionError
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


@pytest.mark.parametrize("scan_status", ["pending", "complete", "error"])
def test_delete_version_removes_attached_scans_immediately(
    scan_repository: tuple[ProducerRepository, object],
    scan_status: str,
) -> None:
    """A deleted version must not leave a 30-day, resubmittable scan."""
    repository, _ = scan_repository
    _create_draft_version(repository)
    repository.create_scan_task(
        scan_id="scan-orphan-1",
        owner_user_id="scan-user-1",
        client_request_id="request-orphan-1",
        repo_url=DRAFT_SOURCE_URL,
        status=scan_status,
        callback_status="delivered",
        version_id=DRAFT_VERSION_ID,
    )

    # While attached: no retention deadline, holding the dedup key.
    attached = repository.get_scan_task("scan-orphan-1")
    assert attached is not None
    assert attached["version_id"] == DRAFT_VERSION_ID
    assert attached["expires_at"] is None

    if scan_status == "pending":
        with pytest.raises(VersionDeletionError):
            repository.delete_version(DRAFT_VERSION_ID, operator_id="scan-user-1", operator_role="submitter", expected_status="draft")
        assert repository.get_scan_task("scan-orphan-1") is not None
        return
    assert repository.delete_version(DRAFT_VERSION_ID, operator_id="scan-user-1", operator_role="submitter", expected_status="draft") is True

    assert repository.get_version(DRAFT_VERSION_ID) is None
    assert repository.get_scan_task("scan-orphan-1") is None
    with pytest.raises(VersionDeletionError) as missing:
        repository.delete_version(DRAFT_VERSION_ID, operator_id="scan-user-1", operator_role="submitter", expected_status="draft")
    assert missing.value.status_code == 404


@pytest.mark.parametrize("version_status", ["pending_review", "approved", "published", "rejected"])
@pytest.mark.parametrize("scan_status", ["complete", "error", "llm_timeout", "total_timeout"])
def test_submitted_scans_never_expire(
    scan_repository: tuple[ProducerRepository, object],
    version_status: str,
    scan_status: str,
) -> None:
    from src.repositories.orm_producer import ScanTaskRow

    repository, _ = scan_repository
    _create_draft_version(repository)
    old = datetime.now(timezone.utc) - timedelta(days=90)
    repository.create_scan_task(
        scan_id="scan-preserved", owner_user_id="scan-user-1",
        client_request_id="preserved", repo_url=DRAFT_SOURCE_URL,
        version_id=DRAFT_VERSION_ID, status=scan_status,
        callback_status="delivered", created_at=old, expires_at=old,
    )
    assert repository.get_scan_task("scan-preserved")["expires_at"] is None
    # A stale deadline from the old policy must not delete submitted records.
    with repository.session_factory() as session:
        session.get(PackageVersionRow, DRAFT_VERSION_ID).status = version_status
        session.get(ScanTaskRow, "scan-preserved").expires_at = old
        session.commit()
    assert repository.delete_expired_scan_tasks() == 0
    task = repository.get_scan_task("scan-preserved")
    assert task is not None
    info = trust._scan_info_from_task(task)
    assert trust._scan_expired(info) is False
    assert trust._scan_expiry_iso(info) is None
    assert repository.list_version_labels([DRAFT_VERSION_ID])[DRAFT_VERSION_ID]["status"] == version_status
    # Even workers explicitly providing an expiry cannot reinstate the TTL.
    repository.update_scan_task("scan-preserved", {"expires_at": old})
    assert repository.get_scan_task("scan-preserved")["expires_at"] is None


def test_service_delete_removes_mirror_keeps_unrelated_scans_and_audit(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy import select
    from src.repositories.orm_producer import AuditLogRow, ScanReportRow
    from src.services.producer import ProducerService

    repository, _ = scan_repository
    _create_draft_version(repository)
    with repository.session_factory() as session:
        session.add(ScanReportRow(version_id=DRAFT_VERSION_ID, scan_json={"summary": {"total": 0}}))
        session.commit()
    for suffix, version_id in [("attached", DRAFT_VERSION_ID), ("standalone", None)]:
        repository.create_scan_task(
            scan_id=f"scan-{suffix}", owner_user_id="scan-user-1",
            client_request_id=suffix, repo_url=f"https://github.com/acme/demo-{suffix}",
            status="complete", callback_status="delivered", version_id=version_id,
        )
    monkeypatch.setattr(trust, "_scans", {
        "scan-attached": {"version_id": DRAFT_VERSION_ID},
        "scan-standalone": {"version_id": None},
    })
    response = ProducerService(repository).delete_version(
        version_id=DRAFT_VERSION_ID, operator_id="scan-user-1",
        operator_role="submitter", expected_status="draft",
    )
    assert response.new_status == "deleted"
    assert repository.get_scan_task("scan-attached") is None
    assert repository.get_scan_report(DRAFT_VERSION_ID) is None
    assert repository.get_scan_task("scan-standalone") is not None
    assert "scan-attached" not in trust._scans
    assert "scan-standalone" in trust._scans
    assert repository.update_scan_task("scan-attached", {"status": "complete"}) is False
    with repository.session_factory() as session:
        audit = session.scalar(select(AuditLogRow).where(AuditLogRow.action == "delete_version"))
        assert audit is not None
        assert audit.target_id == DRAFT_VERSION_ID


@pytest.mark.parametrize("scan_status", ["complete", "error", "llm_timeout", "total_timeout"])
def test_unsubmitted_retention_starts_at_finish_and_expires_at_30_days(
    scan_repository: tuple[ProducerRepository, object],
    scan_status: str,
) -> None:
    repository, _ = scan_repository
    created = datetime(2026, 10, 1, tzinfo=timezone.utc)
    finished = created + timedelta(minutes=20)
    deadline = finished + timedelta(days=30)
    repository.create_scan_task(
        scan_id="scan-deadline", owner_user_id="scan-user-1",
        client_request_id="deadline", repo_url=DRAFT_SOURCE_URL, created_at=created,
    )
    repository.update_scan_task("scan-deadline", {"status": scan_status, "finished_at": finished})
    task = repository.get_scan_task("scan-deadline")
    assert task is not None
    assert task["expires_at"] == deadline.isoformat().replace("+00:00", "Z")
    assert repository.delete_expired_scan_tasks(now=deadline - timedelta(seconds=1)) == 0
    assert repository.delete_expired_scan_tasks(now=deadline) == 1


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
