"""Persistence and ownership contracts for resumable scan tasks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import threading
from types import SimpleNamespace

import pytest
from fastapi import BackgroundTasks, HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError, OperationalError

from src import main as main_module
from src.database import Base, create_engine_from_url, create_session_factory
from src.dependencies import CurrentUser
from src.repositories.orm import PackageRow, PackageVersionRow
from src.repositories.orm_producer import UserRow
from src.repositories.producer_sqlalchemy import (
    ProducerRepository,
    ScanTaskSourceConflictError,
)
from src.routers import producer as producer_router
from src.routers import trust
from src.services import artifacts
from src.services.producer import (
    ProducerPersistenceError,
    ProducerService,
    ProducerSubmissionConflict,
)


@pytest.fixture
def scan_repository() -> tuple[ProducerRepository, object]:
    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)
    with session_factory() as session:
        session.add_all(
            [
                UserRow(
                    id="scan-user-1",
                    email="scan-user-1@example.com",
                    password_hash="hash",
                    role="submitter",
                    display_name="Scan User 1",
                ),
                UserRow(
                    id="scan-user-2",
                    email="scan-user-2@example.com",
                    password_hash="hash",
                    role="submitter",
                    display_name="Scan User 2",
                ),
            ]
        )
        session.commit()
    repository = ProducerRepository(session_factory)
    try:
        yield repository, engine
    finally:
        engine.dispose()


def test_scan_task_creation_is_idempotent_and_owner_scoped(
    scan_repository: tuple[ProducerRepository, object],
) -> None:
    repository, _ = scan_repository
    created_at = datetime(2026, 9, 12, tzinfo=timezone.utc)

    first, created = repository.create_scan_task(
        scan_id="scan-persisted-1",
        owner_user_id="scan-user-1",
        client_request_id="request-1",
        repo_url="https://github.com/acme/demo",
        created_at=created_at,
        expires_at=created_at + timedelta(days=30),
    )
    retry, retry_created = repository.create_scan_task(
        scan_id="scan-persisted-other",
        owner_user_id="scan-user-1",
        client_request_id="request-1",
        repo_url="https://github.com/acme/demo",
    )
    other_owner, other_created = repository.create_scan_task(
        scan_id="scan-persisted-2",
        owner_user_id="scan-user-2",
        client_request_id="request-1",
        repo_url="https://github.com/acme/demo",
    )

    assert created is True
    assert retry_created is False
    assert retry["scan_id"] == first["scan_id"]
    assert other_created is True
    assert other_owner["scan_id"] == "scan-persisted-2"
    assert repository.get_scan_task(
        "scan-persisted-1", owner_user_id="scan-user-2"
    ) is None
    assert repository.get_scan_task_by_request(
        owner_user_id="scan-user-1",
        client_request_id="request-1",
    )["scan_id"] == "scan-persisted-1"


def test_scan_task_updates_and_expiration_cleanup(
    scan_repository: tuple[ProducerRepository, object],
) -> None:
    repository, _ = scan_repository
    now = datetime(2026, 9, 12, tzinfo=timezone.utc)
    repository.create_scan_task(
        scan_id="scan-update-1",
        owner_user_id="scan-user-1",
        client_request_id="request-update",
        repo_url="https://github.com/acme/demo",
        created_at=now,
        expires_at=now + timedelta(days=30),
    )
    repository.update_scan_task(
        "scan-update-1",
        {
            "status": "complete",
            "finished_at": now,
            "summary": {"total": 0},
            "report_json": {"scan_id": "scan-update-1"},
        },
    )

    updated = repository.get_scan_task("scan-update-1")
    assert updated is not None
    assert updated["status"] == "complete"
    assert updated["summary"] == {"total": 0}
    assert updated["finished_at"] == "2026-09-12T00:00:00Z"
    assert repository.delete_expired_scan_tasks(
        now=now + timedelta(days=31)
    ) == 1
    assert repository.get_scan_task("scan-update-1") is None

    with pytest.raises(ValueError, match="Unsupported scan task fields"):
        repository.update_scan_task("scan-update-1", {"owner_user_id": "other"})


DRAFT_VERSION_ID = "atomic-version"
DRAFT_PACKAGE_ID = "atomic-package"


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
                id=DRAFT_VERSION_ID,
                package_id=DRAFT_PACKAGE_ID,
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


def test_version_scan_task_transaction_updates_version_and_audit_together(
    scan_repository: tuple[ProducerRepository, object],
) -> None:
    repository, _ = scan_repository
    _create_draft_version(repository)

    task = repository.create_version_scan_task(
        version_id=DRAFT_VERSION_ID,
        scan_id="scan-atomic-1",
        owner_user_id="scan-user-1",
        client_request_id="atomic-request-1",
        repo_url="https://github.com/acme/demo",
        expected_statuses={"draft"},
        operator_id="scan-user-1",
    )

    assert task["status"] == "pending"
    assert repository.get_version(DRAFT_VERSION_ID)["status"] == "scanning"
    assert repository.get_scan_task("scan-atomic-1")["version_id"] == DRAFT_VERSION_ID
    assert repository.list_audit_logs(target_id=DRAFT_VERSION_ID)[0]["action"] == "submit"


def test_version_scan_task_transaction_rolls_back_version_on_task_failure(
    scan_repository: tuple[ProducerRepository, object],
) -> None:
    repository, _ = scan_repository
    _create_draft_version(repository)
    repository.create_scan_task(
        scan_id="scan-existing-request",
        owner_user_id="scan-user-1",
        client_request_id="atomic-request-duplicate",
        repo_url="https://github.com/acme/preexisting",
    )

    with pytest.raises(IntegrityError):
        repository.create_version_scan_task(
            version_id=DRAFT_VERSION_ID,
            scan_id="scan-atomic-2",
            owner_user_id="scan-user-1",
            client_request_id="atomic-request-duplicate",
            repo_url="https://github.com/acme/demo",
            expected_statuses={"draft"},
            operator_id="scan-user-1",
        )

    assert repository.get_version(DRAFT_VERSION_ID)["status"] == "draft"
    assert repository.get_scan_task("scan-atomic-2") is None
    assert repository.list_audit_logs(target_id=DRAFT_VERSION_ID) == []


def test_submit_service_keeps_draft_retryable_when_task_write_fails(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = scan_repository
    _create_draft_version(repository)
    original_create = repository.create_version_scan_task

    def fail_create(**_kwargs: object) -> dict[str, object]:
        raise OperationalError("insert", {}, RuntimeError("database unavailable"))

    monkeypatch.setattr(repository, "create_version_scan_task", fail_create)
    service = ProducerService(repository)
    scan_task = {
        "owner_user_id": "scan-user-1",
        "source_ref": "main",
        "commit_hash": "a" * 40,
    }

    with pytest.raises(ProducerPersistenceError):
        service.submit_version(
            DRAFT_VERSION_ID,
            user_id="scan-user-1",
            scan_task=scan_task,
        )

    assert repository.get_version(DRAFT_VERSION_ID)["status"] == "draft"
    monkeypatch.setattr(repository, "create_version_scan_task", original_create)
    _, scan_id, status = service.submit_version(
        DRAFT_VERSION_ID,
        user_id="scan-user-1",
        scan_task=scan_task,
    )
    assert status == "scanning"
    assert repository.get_scan_task(str(scan_id)) is not None


def test_reused_scan_is_attached_before_callback_can_be_delivered(
    scan_repository: tuple[ProducerRepository, object],
) -> None:
    repository, _ = scan_repository
    _create_draft_version(repository)
    repository.create_scan_task(
        scan_id="scan-reused-1",
        owner_user_id="scan-user-1",
        client_request_id="request-reused-1",
        repo_url="https://github.com/acme/demo",
        source_ref="main",
        commit_hash="d" * 40,
        status="complete",
        callback_status="not_required",
    )
    repository.update_scan_task(
        "scan-reused-1",
        {"report_json": {"scan_id": "scan-reused-1"}},
    )

    repo_url, scan_id, next_status = ProducerService(
        repository
    ).submit_version(
        DRAFT_VERSION_ID,
        user_id="scan-user-1",
        scan_task={
            "owner_user_id": "scan-user-1",
            "existing_scan_id": "scan-reused-1",
        },
    )

    assert repo_url == "https://github.com/acme/demo"
    assert scan_id == "scan-reused-1"
    assert next_status == "scanning"
    assert repository.get_version(DRAFT_VERSION_ID)["status"] == "scanning"
    reused = repository.get_scan_task("scan-reused-1")
    assert reused["version_id"] == DRAFT_VERSION_ID
    assert reused["callback_status"] == "pending"
    assert reused["completion_delivered_at"] is None


def test_reused_scan_can_be_attached_to_only_one_version(
    scan_repository: tuple[ProducerRepository, object],
) -> None:
    repository, _ = scan_repository
    _create_draft_version(repository)
    second_version_id = "atomic-version-2"
    with repository.session_factory() as session:
        session.add(
            PackageVersionRow(
                id=second_version_id,
                package_id=DRAFT_PACKAGE_ID,
                version="2.0.0",
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
    repository.create_scan_task(
        scan_id="scan-one-time-reuse",
        owner_user_id="scan-user-1",
        client_request_id="request-one-time-reuse",
        repo_url="https://github.com/acme/demo",
        source_ref="main",
        commit_hash="e" * 40,
        status="complete",
        callback_status="not_required",
    )
    repository.update_scan_task(
        "scan-one-time-reuse",
        {"report_json": {"scan_id": "scan-one-time-reuse"}},
    )
    service = ProducerService(repository)
    scan_task = {
        "owner_user_id": "scan-user-1",
        "existing_scan_id": "scan-one-time-reuse",
    }

    service.submit_version(
        DRAFT_VERSION_ID,
        user_id="scan-user-1",
        scan_task=scan_task,
    )
    with pytest.raises(ProducerSubmissionConflict):
        service.submit_version(
            second_version_id,
            user_id="scan-user-1",
            scan_task=scan_task,
        )

    task = repository.get_scan_task("scan-one-time-reuse")
    assert task is not None
    assert task["version_id"] == DRAFT_VERSION_ID
    assert repository.get_version(second_version_id)["status"] == "draft"


def test_scan_task_claim_lease_prevents_duplicate_execution_and_can_recover(
    scan_repository: tuple[ProducerRepository, object],
) -> None:
    repository, _ = scan_repository
    now = datetime(2026, 9, 12, tzinfo=timezone.utc)
    repository.create_scan_task(
        scan_id="scan-lease-1",
        owner_user_id="scan-user-1",
        client_request_id="request-lease",
        repo_url="https://github.com/acme/demo",
        created_at=now,
        expires_at=now + timedelta(days=30),
    )

    claimed = repository.claim_scan_task(
        "scan-lease-1", lease_seconds=120, now=now
    )
    assert claimed is not None
    assert claimed["lease_token"]
    assert claimed["attempt_count"] == 1
    assert repository.claim_scan_task(
        "scan-lease-1", lease_seconds=120, now=now + timedelta(seconds=1)
    ) is None

    lease_token = str(claimed["lease_token"])
    assert repository.renew_scan_task_lease(
        "scan-lease-1",
        lease_token=lease_token,
        lease_seconds=120,
        now=now + timedelta(seconds=30),
    ) is True
    assert repository.release_scan_task_lease(
        "scan-lease-1", lease_token=lease_token, now=now + timedelta(seconds=31)
    ) is True
    recovered = repository.claim_recoverable_scan_tasks(
        lease_seconds=120, now=now + timedelta(seconds=32)
    )
    assert [task["scan_id"] for task in recovered] == ["scan-lease-1"]
    assert recovered[0]["attempt_count"] == 2


def test_submit_route_claims_persisted_task_before_background_dispatch(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = scan_repository
    _create_draft_version(repository)
    commit_hash = "b" * 40
    monkeypatch.setattr(
        producer_router,
        "_get_producer_repository",
        lambda: repository,
    )
    monkeypatch.setattr(
        trust,
        "_get_scan_task_repository",
        lambda: repository,
    )
    monkeypatch.setattr(
        trust,
        "_resolve_default_branch_source",
        lambda parsed: {
            **parsed,
            "ref": "main",
            "subdir": None,
            "repository_resolved": True,
        },
    )
    monkeypatch.setattr(
        trust,
        "_pin_resolved_source",
        lambda parsed: {**parsed, "commit_hash": commit_hash},
    )
    monkeypatch.setattr(
        "src.services.signals.collect_platform_signals",
        lambda *_args, **_kwargs: {},
    )
    trust._scans.clear()

    try:
        background_tasks = BackgroundTasks()
        response = producer_router.submit_version(
            DRAFT_VERSION_ID,
            background_tasks,
            _user=CurrentUser(id="scan-user-1", role="submitter"),
        )

        task = repository.get_scan_task(str(response.scan_id))
        assert response.status == "scanning"
        assert task is not None
        assert task["status"] == "pending"
        assert task["lease_token"] is not None
        assert task["attempt_count"] == 1
        assert len(background_tasks.tasks) == 1
        assert repository.claim_recoverable_scan_tasks(
            lease_seconds=120,
            now=datetime.now(timezone.utc),
        ) == []
    finally:
        trust._scans.clear()


def test_submit_route_pipeline_keeps_successful_version_pending_review(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = scan_repository
    _create_draft_version(repository)
    commit_hash = "c" * 40
    monkeypatch.setattr(
        producer_router,
        "_get_producer_repository",
        lambda: repository,
    )
    monkeypatch.setattr(
        trust,
        "_get_scan_task_repository",
        lambda: repository,
    )
    monkeypatch.setattr(
        trust,
        "_resolve_default_branch_source",
        lambda parsed: {
            **parsed,
            "ref": "main",
            "subdir": None,
            "repository_resolved": True,
        },
    )
    monkeypatch.setattr(
        trust,
        "_pin_resolved_source",
        lambda parsed: {**parsed, "commit_hash": commit_hash},
    )
    monkeypatch.setattr(
        "src.services.signals.collect_platform_signals",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        trust,
        "_prepare_scan_callback_report",
        lambda _scan_id, report: (dict(report), None),
    )

    def complete(
        service: ProducerService,
        version_id: str,
        _report: dict[str, object],
    ) -> bool:
        service.repository.update_version_status(version_id, "pending_review")
        return True

    def run_body(
        scan_id: str,
        source: str,
        *,
        on_complete: object = None,
        lease_token: str | None = None,
        **_kwargs: object,
    ) -> None:
        finished_at = datetime.now(timezone.utc)
        report = {
            "scan_id": scan_id,
            "repo_url": source,
            "source_ref": "main",
            "commit_hash": commit_hash,
            "scan_report": {},
            "trust_score": {},
        }
        trust._update_scan_state(
            scan_id,
            {
                "status": "complete",
                "full_report": report,
                "finished_at": finished_at,
                "callback_status": "pending",
            },
            required=True,
        )
        assert callable(on_complete)
        assert trust._deliver_scan_callback(
            scan_id,
            report,
            None,
            on_complete,
            lease_token=lease_token,
        ) is True

    monkeypatch.setattr(ProducerService, "handle_scan_complete", complete)
    monkeypatch.setattr(trust, "_run_scan_task_body", run_body)
    trust._scans.clear()

    try:
        background_tasks = BackgroundTasks()
        response = producer_router.submit_version(
            DRAFT_VERSION_ID,
            background_tasks,
            _user=CurrentUser(id="scan-user-1", role="submitter"),
        )
        task = background_tasks.tasks[0]
        task.func(*task.args, **task.kwargs)

        version = repository.get_version(DRAFT_VERSION_ID)
        persisted_scan = repository.get_scan_task(str(response.scan_id))
        assert version is not None
        assert version["status"] == "pending_review"
        assert persisted_scan is not None
        assert persisted_scan["status"] == "complete"
        assert persisted_scan["callback_status"] == "delivered"
        assert persisted_scan["resource_consumed"] is True
    finally:
        trust._scans.clear()


def test_required_scan_state_persistence_failure_is_surfaced(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingRepository:
        def update_scan_task(self, *_args: object, **_kwargs: object) -> bool:
            raise RuntimeError("database unavailable")

    scan_id = "scan-required-write"
    trust._scans[scan_id] = {
        "scan_id": scan_id,
        "status": "saving",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "lease_token": "lease-required-write",
    }
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: FailingRepository())
    monkeypatch.setattr(trust, "_SCAN_PERSIST_RETRY_DELAY_SECONDS", 0)
    try:
        with pytest.raises(trust.ScanTaskPersistenceError):
            trust._update_scan_state(
                scan_id,
                {"status": "complete", "full_report": {"scan_id": scan_id}},
                required=True,
            )
        assert trust._scans[scan_id]["status"] == "saving"
    finally:
        trust._scans.pop(scan_id, None)


def test_terminal_status_and_llm_progress_share_required_write(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = scan_repository
    scan_id = "scan-terminal-llm-atomic"
    repository.create_scan_task(
        scan_id=scan_id,
        owner_user_id="scan-user-1",
        client_request_id="terminal-llm-atomic",
        repo_url="https://github.com/acme/atomic",
    )
    trust._scans[scan_id] = trust._scan_info_from_task(
        repository.get_scan_task(scan_id)
    )
    terminal_progress = {
        "status": "completed",
        "phase": "complete",
        "attempt": 1,
        "max_attempts": 3,
        "findings_total": 2,
        "findings_reviewed": 2,
        "findings_pending": 0,
    }
    original_update = repository.update_scan_task
    persisted_updates: list[dict[str, object]] = []

    def record_update(
        target_scan_id: str,
        updates: dict[str, object],
        **options: object,
    ) -> bool:
        persisted_updates.append(dict(updates))
        return original_update(target_scan_id, updates, **options)

    monkeypatch.setattr(repository, "update_scan_task", record_update)
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    try:
        assert trust._update_scan_state(
            scan_id,
            {
                "status": "complete",
                "finished_at": datetime.now(timezone.utc),
                "llm_review": terminal_progress,
            },
            required=True,
        )
        assert len(persisted_updates) == 1
        assert persisted_updates[0]["status"] == "complete"
        assert persisted_updates[0]["llm_review"] == terminal_progress
        persisted = repository.get_scan_task(scan_id)
        assert persisted is not None
        assert persisted["status"] == "complete"
        assert persisted["llm_review"] == terminal_progress
    finally:
        trust._scans.pop(scan_id, None)


def test_startup_recovery_claims_persisted_pending_tasks(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = scan_repository
    repository.create_scan_task(
        scan_id="scan-recovery-1",
        owner_user_id="scan-user-1",
        client_request_id="request-recovery",
        repo_url="https://github.com/acme/demo",
    )
    recovered_ids: list[str] = []
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    monkeypatch.setattr(
        trust,
        "_enqueue_claimed_scan_thread",
        lambda info, **_kwargs: recovered_ids.append(str(info["scan_id"])),
    )
    monkeypatch.setattr(
        trust,
        "_cleanup_orphan_scan_temp_dirs",
        lambda: pytest.fail("recovery must not run filesystem maintenance"),
    )
    trust._scans.clear()

    assert trust.recover_persisted_scan_tasks() == 1
    assert recovered_ids == ["scan-recovery-1"]
    assert repository.get_scan_task("scan-recovery-1")["attempt_count"] == 1


def test_startup_recovery_drains_more_than_one_batch(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = scan_repository
    batch_size = trust._SCAN_RECOVERY_BATCH_SIZE
    for index in range(batch_size + 1):
        repository.create_scan_task(
            scan_id=f"scan-recovery-batch-{index}",
            owner_user_id="scan-user-1",
            client_request_id=f"request-recovery-batch-{index}",
            repo_url=f"https://github.com/acme/demo-batch-{index}",
        )
    recovered_ids: list[str] = []
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    monkeypatch.setattr(
        trust,
        "_enqueue_claimed_scan_thread",
        lambda info, **_kwargs: recovered_ids.append(str(info["scan_id"])),
    )
    trust._scans.clear()

    try:
        assert trust.recover_persisted_scan_tasks() == batch_size + 1
        assert len(recovered_ids) == batch_size + 1
    finally:
        trust._scans.clear()


def test_periodic_recovery_loop_wakes_after_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stop_event = threading.Event()
    calls: list[int] = []

    def recover_once() -> int:
        calls.append(1)
        stop_event.set()
        return 0

    monkeypatch.setattr(trust, "recover_persisted_scan_tasks", recover_once)
    trust.run_persisted_scan_recovery_loop(
        stop_event,
        interval_seconds=0.01,
    )

    assert calls == [1]


def test_scan_maintenance_cleans_database_and_orphan_directories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class Repository:
        def delete_expired_scan_tasks(self) -> int:
            calls.append("database")
            return 0

    monkeypatch.setattr(trust, "_get_scan_task_repository", Repository)
    monkeypatch.setattr(
        trust,
        "_cleanup_expired_scans",
        lambda: calls.append("memory"),
    )
    monkeypatch.setattr(
        trust,
        "_cleanup_orphan_scan_temp_dirs",
        lambda: calls.append("filesystem"),
    )

    trust.run_scan_maintenance()

    assert calls == ["memory", "database", "filesystem"]


def test_scan_maintenance_loop_continues_after_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts: list[int] = []
    logged: list[str] = []

    class ControlledStopEvent:
        def __init__(self) -> None:
            self.wait_count = 0

        def wait(self, timeout: float) -> bool:
            assert timeout == 1.0
            self.wait_count += 1
            return self.wait_count > 2

    def run_maintenance() -> None:
        attempts.append(len(attempts) + 1)
        if len(attempts) == 1:
            raise OSError("temporary cleanup failure")

    monkeypatch.setattr(trust, "run_scan_maintenance", run_maintenance)
    monkeypatch.setattr(
        trust._logger,
        "exception",
        lambda message: logged.append(message),
    )

    trust.run_scan_maintenance_loop(
        ControlledStopEvent(),
        interval_seconds=0.0,
    )

    assert attempts == [1, 2]
    assert logged == ["Periodic scan maintenance failed"]


def test_startup_survives_scan_maintenance_database_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logged: list[str] = []

    class UnavailableRepository:
        def delete_expired_scan_tasks(self) -> int:
            raise OperationalError(
                "DELETE FROM scan_tasks",
                {},
                RuntimeError("no such table: scan_tasks"),
            )

    monkeypatch.setattr(
        trust,
        "_get_scan_task_repository",
        UnavailableRepository,
    )
    monkeypatch.setattr(trust, "_cleanup_expired_scans", lambda: None)
    monkeypatch.setattr(trust, "recover_persisted_scan_tasks", lambda: 0)
    monkeypatch.setattr(
        trust,
        "run_persisted_scan_recovery_loop",
        lambda stop_event: stop_event.wait(),
    )
    monkeypatch.setattr(
        trust,
        "run_scan_maintenance_loop",
        lambda stop_event: stop_event.wait(),
    )
    monkeypatch.setattr(
        main_module._logger,
        "exception",
        lambda message: logged.append(message),
    )

    with TestClient(main_module.create_app()) as client:
        response = client.get("/api/v0/health")

    assert response.status_code == 200
    assert logged == ["Initial scan maintenance failed"]


def test_scan_list_keeps_legacy_array_and_v1_pagination(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = scan_repository
    for index in range(3):
        repository.create_scan_task(
            scan_id=f"scan-list-{index}",
            owner_user_id="scan-user-1",
            client_request_id=f"request-list-{index}",
            repo_url=f"https://github.com/acme/demo-list-{index}",
        )
    repository.create_scan_task(
        scan_id="scan-list-other-owner",
        owner_user_id="scan-user-2",
        client_request_id="request-list-other-owner",
        repo_url="https://github.com/acme/demo",
        status="complete",
        callback_status="not_required",
    )
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    monkeypatch.setattr(
        repository,
        "delete_expired_scan_tasks",
        lambda **_kwargs: pytest.fail("list requests must not write to the database"),
    )
    monkeypatch.setattr(
        trust,
        "_cleanup_orphan_scan_temp_dirs",
        lambda: pytest.fail("list requests must not scan the temporary directory"),
    )
    trust._scans.clear()

    try:
        legacy_response = trust.list_scans(
            _user=CurrentUser(id="scan-user-1", role="submitter"),
        )
        assert isinstance(legacy_response, list)
        assert len(legacy_response) == 3
        assert all(
            item["scan_id"] != "scan-list-other-owner"
            for item in legacy_response
        )

        response = trust.list_scans_v1(
            limit=2,
            offset=1,
            _user=CurrentUser(id="scan-user-1", role="submitter"),
        )
        assert response["total"] == 3
        assert response["limit"] == 2
        assert response["offset"] == 1
        assert response["has_more"] is False
        assert len(response["items"]) == 2
        assert all(
            item["scan_id"] != "scan-list-other-owner"
            for item in response["items"]
        )

        reviewer_legacy = trust.list_scans(
            _user=CurrentUser(id="reviewer-1", role="reviewer"),
        )
        assert reviewer_legacy == []

        admin_legacy = trust.list_scans(
            _user=CurrentUser(id="admin-1", role="admin"),
        )
        assert len(admin_legacy) == 4
        assert next(
            item
            for item in admin_legacy
            if item["scan_id"] == "scan-list-other-owner"
        )["delete_allowed"] is True

        reviewer_page = trust.list_scans_v1(
            limit=50,
            offset=0,
            _user=CurrentUser(id="reviewer-1", role="reviewer"),
        )
        assert reviewer_page["total"] == 4
        assert len(reviewer_page["items"]) == 4
        assert any(
            item["scan_id"] == "scan-list-other-owner"
            for item in reviewer_page["items"]
        )
        assert {
            item["owner_user_id"] for item in reviewer_page["items"]
        } == {"scan-user-1", "scan-user-2"}
        assert all(
            item["delete_allowed"] is False
            for item in reviewer_page["items"]
        )

        admin_page = trust.list_scans_v1(
            limit=50,
            offset=0,
            _user=CurrentUser(id="admin-1", role="admin"),
        )
        assert next(
            item
            for item in admin_page["items"]
            if item["scan_id"] == "scan-list-other-owner"
        )["delete_allowed"] is True

        reviewer_status = trust.get_scan_status(
            "scan-list-other-owner",
            _user=CurrentUser(id="reviewer-1", role="reviewer"),
        )
        admin_status = trust.get_scan_status(
            "scan-list-other-owner",
            _user=CurrentUser(id="admin-1", role="admin"),
        )
        assert reviewer_status["delete_allowed"] is False
        assert admin_status["delete_allowed"] is True
        assert "owner_user_id" in trust.ScanListItem.model_fields
    finally:
        trust._scans.clear()


def test_reviewer_reuses_foreign_scan_owner_and_reports_callback_error(
    scan_repository: tuple[ProducerRepository, object],
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = scan_repository
    _create_draft_version(repository)
    commit_hash = "e" * 40
    source_url = "https://github.com/acme/demo"
    repository.update_version_data(
        DRAFT_VERSION_ID,
        {
            "source": {
                "repository_url": source_url,
                "subdirectory": "Skills/Hello",
            }
        },
    )
    scan_id = "scan-foreign-owner"
    repository.create_scan_task(
        scan_id=scan_id,
        owner_user_id="scan-user-1",
        client_request_id="request-foreign-owner",
        repo_url=source_url,
        source_ref="main",
        commit_hash=commit_hash,
        source_subdirectory="Skills/Hello",
        status="complete",
        callback_status="not_required",
    )
    repository.update_scan_task(
        scan_id,
        {
            "report_json": {
                "scan_id": scan_id,
                "repo_url": source_url,
                "commit_hash": commit_hash,
                "source_subdirectory": "Skills/Hello",
            }
        },
    )
    monkeypatch.setattr(
        producer_router,
        "_get_producer_repository",
        lambda: repository,
    )
    monkeypatch.setattr(
        trust,
        "_get_scan_task_repository",
        lambda: repository,
    )
    monkeypatch.setattr(
        trust,
        "_resolve_default_branch_source",
        lambda parsed: {
            **parsed,
            "ref": "main",
            "subdir": None,
            "repository_resolved": True,
        },
    )
    monkeypatch.setattr(
        trust,
        "_pin_resolved_source",
        lambda parsed: {
            **parsed,
            "commit_hash": commit_hash,
        },
    )

    def callback_factory(version_id: str):
        def callback(_scan_id: str, _report: dict[str, object], _error: str | None):
            repository.update_version_status(version_id, "error")

        return callback

    monkeypatch.setattr(
        trust,
        "_version_scan_completion_callback",
        callback_factory,
    )
    callback_root = tmp_path / "scan-repositories"
    callback_root.mkdir()
    acquired_source = callback_root / "tah_repo_callback"
    acquired_source.mkdir()
    monkeypatch.setattr(trust, "_SCAN_TEMP_ROOT", callback_root)
    monkeypatch.setattr(
        trust,
        "_acquire_repo_source",
        lambda _parsed, **_kwargs: (str(acquired_source), "zip", commit_hash),
    )
    trust._scans.clear()

    try:
        response = producer_router.submit_version(
            DRAFT_VERSION_ID,
            BackgroundTasks(),
            body=producer_router.SubmitVersionRequest(
                initial_scan_id=scan_id,
            ),
            _user=CurrentUser(id="scan-user-2", role="reviewer"),
        )
        assert response.status == "error"
        attached = repository.get_scan_task(scan_id)
        assert attached["owner_user_id"] == "scan-user-1"
        assert attached["version_id"] == DRAFT_VERSION_ID
        submit_audits = repository.list_audit_logs(
            target_id=DRAFT_VERSION_ID,
            action="submit",
        )
        assert submit_audits[-1]["operator_id"] == "scan-user-2"
    finally:
        trust._scans.clear()


def test_recovery_uses_persisted_immutable_source_identity(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = scan_repository
    commit_hash = "c" * 40
    repository.create_scan_task(
        scan_id="scan-fixed-source",
        owner_user_id="scan-user-1",
        client_request_id="request-fixed-source",
        repo_url="https://github.com/Acme/Demo",
        source_ref="Release/Main",
        commit_hash=commit_hash,
        source_subdirectory="Skills/Hello",
    )
    recovered: list[dict[str, object]] = []
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    monkeypatch.setattr(
        trust,
        "_resolve_default_branch_source",
        lambda _parsed: pytest.fail("recovery must not resolve the default branch"),
    )
    monkeypatch.setattr(
        trust,
        "_enqueue_claimed_scan_thread",
        lambda info, **_kwargs: recovered.append(info),
    )
    trust._scans.clear()

    try:
        assert trust.recover_persisted_scan_tasks() == 1
        assert recovered[0]["source_ref"] == "Release/Main"
        assert recovered[0]["commit_hash"] == commit_hash
        assert recovered[0]["source_subdirectory"] == "Skills/Hello"
        resolved = trust._resolved_source_from_scan_info(recovered[0])
        assert resolved is not None
        assert resolved["ref"] == "Release/Main"
        assert resolved["commit_hash"] == commit_hash
        assert resolved["subdir"] == "Skills/Hello"
    finally:
        trust._scans.clear()


def test_callback_failure_is_persisted_until_a_later_success(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = scan_repository
    scan_id = "scan-callback-retry"
    repository.create_scan_task(
        scan_id=scan_id,
        owner_user_id="scan-user-1",
        client_request_id="request-callback-retry",
        repo_url="https://github.com/acme/demo",
        status="complete",
        callback_status="pending",
    )
    lease_token = "callback-lease-1"
    repository.update_scan_task(
        scan_id,
        {
            "report_json": {"scan_id": scan_id},
            "lease_token": lease_token,
            "lease_until": datetime.now(timezone.utc) + timedelta(minutes=5),
        },
    )
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    monkeypatch.setattr(trust, "_SCAN_CALLBACK_INLINE_ATTEMPTS", 1)
    monkeypatch.setattr(trust, "_SCAN_PERSIST_RETRY_DELAY_SECONDS", 0)
    monkeypatch.setattr(trust, "_SCAN_CALLBACK_RETRY_BASE_SECONDS", 1)
    info = trust._scan_info_from_task(repository.get_scan_task(scan_id))
    trust._scans[scan_id] = info
    callbacks = 0

    def fail_callback(*_args: object) -> None:
        nonlocal callbacks
        callbacks += 1
        raise RuntimeError("producer database unavailable")

    try:
        assert trust._deliver_scan_callback(
            scan_id,
            {"scan_id": scan_id},
            None,
            fail_callback,
            lease_token=lease_token,
        ) is False
        failed = repository.get_scan_task(scan_id)
        assert failed["callback_status"] == "pending"
        assert failed["callback_attempt_count"] == 1
        assert failed["completion_delivered_at"] is None
        assert failed["callback_next_attempt_at"] is not None
        assert "producer database unavailable" in failed["callback_last_error"]

        repository.release_scan_task_lease(
            scan_id,
            lease_token=lease_token,
        )
        success_lease = "callback-lease-2"
        repository.update_scan_task(
            scan_id,
            {
                "lease_token": success_lease,
                "lease_until": datetime.now(timezone.utc) + timedelta(minutes=5),
            },
        )
        trust._scans[scan_id] = trust._scan_info_from_task(
            repository.get_scan_task(scan_id)
        )
        assert trust._deliver_scan_callback(
            scan_id,
            {"scan_id": scan_id},
            None,
            lambda *_args: None,
            lease_token=success_lease,
        ) is True
        delivered = repository.get_scan_task(scan_id)
        assert delivered["callback_status"] == "delivered"
        assert delivered["callback_attempt_count"] == 2
        assert delivered["completion_delivered_at"] is not None
        assert delivered["resource_consumed"] is True
        projected = trust._scan_info_from_task(delivered)
        assert projected["callback_finished"] is True
        assert projected["resource_consumed"] is True
        assert callbacks == 1
    finally:
        trust._scans.pop(scan_id, None)


def test_database_projection_allows_expired_terminal_mirror_cleanup(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = scan_repository
    scan_id = "scan-expired-database-mirror"
    repository.create_scan_task(
        scan_id=scan_id,
        owner_user_id="scan-user-1",
        client_request_id="request-expired-database-mirror",
        repo_url="https://github.com/acme/demo",
        status="complete",
        callback_status="not_required",
    )
    repository.update_scan_task(
        scan_id,
        {
            "finished_at": datetime.now(timezone.utc) - timedelta(days=31),
            "expires_at": datetime.now(timezone.utc) - timedelta(seconds=1),
        },
    )
    task = repository.get_scan_task(scan_id)
    assert task is not None
    info = trust._scan_info_from_task(task)
    assert info["callback_finished"] is True
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    trust._scans[scan_id] = trust._memory_scan_info(info)

    try:
        assert trust._cleanup_expired_scans() == 1
        assert scan_id not in trust._scans
    finally:
        trust._scans.pop(scan_id, None)


@pytest.mark.parametrize(
    "status_value",
    ("error", "llm_timeout", "total_timeout"),
)
def test_expired_attached_failure_with_pending_callback_remains_recoverable(
    scan_repository: tuple[ProducerRepository, object],
    status_value: str,
) -> None:
    repository, _ = scan_repository
    _create_draft_version(repository)
    now = datetime(2026, 9, 14, tzinfo=timezone.utc)
    created_at = now - timedelta(days=31)
    expired_at = now - timedelta(days=1)
    pending_scan_id = f"scan-expired-{status_value}-pending"
    delivered_scan_id = f"scan-expired-{status_value}-delivered"

    repository.create_scan_task(
        scan_id=pending_scan_id,
        owner_user_id="scan-user-1",
        client_request_id=f"request-expired-{status_value}-pending",
        repo_url=f"https://github.com/acme/{status_value}-pending",
        version_id=DRAFT_VERSION_ID,
        status=status_value,
        callback_status="pending",
        created_at=created_at,
        expires_at=expired_at,
    )
    repository.create_scan_task(
        scan_id=delivered_scan_id,
        owner_user_id="scan-user-1",
        client_request_id=f"request-expired-{status_value}-delivered",
        repo_url=f"https://github.com/acme/{status_value}-delivered",
        version_id=DRAFT_VERSION_ID,
        status=status_value,
        callback_status="delivered",
        created_at=created_at,
        expires_at=expired_at,
    )

    assert repository.delete_expired_scan_tasks(now=now) == 1
    assert repository.get_scan_task(delivered_scan_id) is None
    assert repository.get_scan_task(pending_scan_id) is not None

    recovered = repository.claim_recoverable_scan_tasks(
        lease_seconds=120,
        now=now,
    )
    assert [task["scan_id"] for task in recovered] == [pending_scan_id]


def test_callback_reacquires_persisted_source_after_runtime_cache_loss(
    scan_repository: tuple[ProducerRepository, object],
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = scan_repository
    scan_id = "scan-callback-rehydrate"
    commit_hash = "f" * 40
    repository.create_scan_task(
        scan_id=scan_id,
        owner_user_id="scan-user-1",
        client_request_id="request-callback-rehydrate",
        repo_url="https://github.com/acme/demo",
        source_ref="main",
        commit_hash=commit_hash,
        source_subdirectory="skills/demo",
        status="complete",
        callback_status="pending",
    )
    repository.update_scan_task(
        scan_id,
        {
            "report_json": {
                "scan_id": scan_id,
                "repo_url": "https://github.com/acme/demo",
                "source_ref": "main",
                "commit_hash": commit_hash,
                "source_subdirectory": "skills/demo",
            },
            "lease_token": "callback-rehydrate-lease",
            "lease_until": datetime.now(timezone.utc) + timedelta(minutes=5),
        },
    )
    root = tmp_path / "scan-repositories"
    root.mkdir()
    reacquired = root / "tah_repo_reacquired"
    reacquired.mkdir()
    (reacquired / "SKILL.md").write_text("# demo\n", encoding="utf-8")
    monkeypatch.setattr(trust, "_SCAN_TEMP_ROOT", root)
    monkeypatch.setattr(trust, "_SCAN_CALLBACK_INLINE_ATTEMPTS", 1)
    monkeypatch.setattr(trust, "_SCAN_PERSIST_RETRY_DELAY_SECONDS", 0)
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)

    observed_sources: list[dict[str, object]] = []

    def fake_acquire(
        parsed: dict[str, object],
        *,
        temp_dir_callback=None,
    ) -> tuple[str, str, str]:
        observed_sources.append(parsed)
        return str(reacquired), "zip", commit_hash

    monkeypatch.setattr(trust, "_acquire_repo_source", fake_acquire)
    info = trust._scan_info_from_task(repository.get_scan_task(scan_id))
    trust._scans[scan_id] = info
    received: list[dict[str, object]] = []

    try:
        assert trust._deliver_scan_callback(
            scan_id,
            info["full_report"],
            None,
            lambda _scan_id, report, _error: received.append(report or {}),
            lease_token="callback-rehydrate-lease",
        ) is True
        assert observed_sources[0]["ref"] == "main"
        assert observed_sources[0]["commit_hash"] == commit_hash
        assert observed_sources[0]["subdir"] == "skills/demo"
        assert received[0]["local_source_dir"] == str(reacquired.resolve())
        assert not reacquired.exists()
    finally:
        trust._scans.pop(scan_id, None)


def test_scan_status_recovers_from_database_and_rejects_other_user(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = scan_repository
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    monkeypatch.setattr(
        trust,
        "_resolve_default_branch_source",
        lambda parsed: {
            **parsed,
            "ref": "main",
            "subdir": None,
            "repository_resolved": True,
        },
    )
    monkeypatch.setattr(
        trust,
        "_fetch_repository_commit_hash",
        lambda _parsed: "a" * 40,
    )
    trust._scans.clear()

    background_tasks = BackgroundTasks()
    response = trust.submit_scan(
        background_tasks,
        repo_url="https://github.com/acme/demo",
        idempotency_key="request-refresh",
        _user=SimpleNamespace(id="scan-user-1", role="submitter"),
    )
    scan_id = response["scan_id"]
    assert len(background_tasks.tasks) == 1

    # The process-local cache is not required for a later status request.
    trust._scans.clear()
    status_response = trust.get_scan_status(
        scan_id,
        _user=CurrentUser(id="scan-user-1", role="submitter"),
    )
    assert status_response["scan_id"] == scan_id
    assert status_response["client_request_id"] == "request-refresh"
    assert status_response["status"] == "pending"

    with pytest.raises(HTTPException) as raised:
        trust.get_scan_status(
            scan_id,
            _user=CurrentUser(id="scan-user-2", role="submitter"),
        )
    assert raised.value.status_code == 403

    finished_at = datetime(2026, 9, 12, 1, tzinfo=timezone.utc)
    repository.update_scan_task(
        scan_id,
        {
            "status": "complete",
            "finished_at": finished_at,
            "package_name": "demo",
            "summary": {"total": 0},
            "metadata_json": {"name": "demo", "version": "1.0.0"},
            "capabilities": [{"path": "skills/demo"}],
            "report_json": {
                "scan_id": scan_id,
                "repo_url": "https://github.com/acme/demo",
                "local_source_dir": "C:/private/source",
                "source_snapshot_sha256": "private-hash",
                "scan_report": {"file_contents": {"secret.py": "secret"}},
            },
        },
    )
    trust._scans.clear()
    persisted_task = repository.get_scan_task(scan_id)
    assert persisted_task is not None
    report = trust._persistable_scan_report(persisted_task["report_json"])
    assert report is not None
    assert report["scan_id"] == scan_id
    assert "local_source_dir" not in report
    assert "source_snapshot_sha256" not in report
    assert "file_contents" not in report["scan_report"]
    metadata = trust.get_scan_metadata(
        scan_id,
        _user=CurrentUser(id="scan-user-1", role="submitter"),
    )
    assert metadata["metadata"]["name"] == "demo"
    assert metadata["capabilities"] == [{"path": "skills/demo"}]

    # Retrying the same request returns the original task and does not enqueue
    # a second scanner execution.  Default-branch resolution is not repeated.
    retry_tasks = BackgroundTasks()
    retry_response = trust.submit_scan(
        retry_tasks,
        repo_url="https://github.com/acme/demo",
        idempotency_key="request-refresh",
        _user=SimpleNamespace(id="scan-user-1", role="submitter"),
    )
    assert retry_response["scan_id"] == scan_id
    assert retry_tasks.tasks == []


def test_scan_lifecycle_retention_and_cleanup_follow_policy(
    scan_repository: tuple[ProducerRepository, object],
) -> None:
    repository, _ = scan_repository
    now = datetime(2026, 9, 13, tzinfo=timezone.utc)
    old = now - timedelta(days=31)

    # Active work is controlled by the execution deadline, never by the
    # post-terminal retention field. The explicit expiry simulates a legacy
    # row that must not be deleted while it is still executable.
    repository.create_scan_task(
        scan_id="scan-policy-active",
        owner_user_id="scan-user-1",
        client_request_id="policy-active",
        repo_url="https://github.com/acme/active",
        created_at=old,
        expires_at=old + timedelta(days=1),
    )
    with repository.session_factory() as session:
        from src.repositories.orm_producer import ScanTaskRow

        active_row = session.get(ScanTaskRow, "scan-policy-active")
        assert active_row is not None
        active_row.expires_at = old + timedelta(days=1)
        session.commit()

    for status_value in ("error", "llm_timeout", "total_timeout"):
        repository.create_scan_task(
            scan_id=f"scan-policy-{status_value}",
            owner_user_id="scan-user-1",
            client_request_id=f"policy-{status_value}",
            repo_url=f"https://github.com/acme/{status_value}",
            status=status_value,
            created_at=old,
        )
    repository.create_scan_task(
        scan_id="scan-policy-complete",
        owner_user_id="scan-user-1",
        client_request_id="policy-complete",
        repo_url="https://github.com/acme/complete",
        status="complete",
        created_at=old,
    )

    _create_draft_version(repository)
    repository.create_scan_task(
        scan_id="scan-policy-attached",
        owner_user_id="scan-user-1",
        client_request_id="policy-attached",
        repo_url="https://github.com/acme/attached",
        version_id=DRAFT_VERSION_ID,
        status="complete",
        callback_status="delivered",
        created_at=old,
        expires_at=old + timedelta(days=1),
    )
    with repository.session_factory() as session:
        from src.repositories.orm_producer import ScanTaskRow

        attached_row = session.get(ScanTaskRow, "scan-policy-attached")
        assert attached_row is not None
        attached_row.expires_at = old + timedelta(days=1)
        session.commit()

    assert repository.get_scan_task("scan-policy-active")["expires_at"] == (
        old + timedelta(days=1)
    ).isoformat().replace("+00:00", "Z")
    assert repository.delete_expired_scan_tasks(now=now) == 4
    assert repository.get_scan_task("scan-policy-active") is not None
    assert repository.get_scan_task("scan-policy-attached") is not None
    assert repository.get_scan_task("scan-policy-complete") is None
    for status_value in ("error", "llm_timeout", "total_timeout"):
        assert repository.get_scan_task(f"scan-policy-{status_value}") is None

    # A legacy active row with a stale expiry is still recoverable; its
    # execution deadline is enforced by the worker after it is claimed.
    recovered = repository.claim_recoverable_scan_tasks(
        lease_seconds=120,
        now=now,
    )
    assert [task["scan_id"] for task in recovered] == ["scan-policy-active"]


def test_scan_task_delete_is_terminal_only_and_preserves_attached_version(
    scan_repository: tuple[ProducerRepository, object],
) -> None:
    repository, _ = scan_repository
    now = datetime(2026, 9, 13, tzinfo=timezone.utc)
    repository.create_scan_task(
        scan_id="scan-delete-active",
        owner_user_id="scan-user-1",
        client_request_id="delete-active",
        repo_url="https://github.com/acme/delete-active",
    )
    with pytest.raises(ValueError, match="处理中"):
        repository.delete_scan_task(
            "scan-delete-active",
            owner_user_id="scan-user-1",
            now=now,
        )

    for status_value in ("llm_timeout", "total_timeout", "error", "complete"):
        scan_id = f"scan-delete-{status_value}"
        repository.create_scan_task(
            scan_id=scan_id,
            owner_user_id="scan-user-1",
            client_request_id=f"delete-{status_value}",
            repo_url=f"https://github.com/acme/delete-{status_value}",
            status=status_value,
            created_at=now,
        )
        assert repository.delete_scan_task(
            scan_id,
            owner_user_id="scan-user-1",
            now=now,
        )["scan_id"] == scan_id
        assert repository.get_scan_task(scan_id) is None

    _create_draft_version(repository)
    repository.create_scan_task(
        scan_id="scan-delete-attached",
        owner_user_id="scan-user-1",
        client_request_id="delete-attached",
        repo_url="https://github.com/acme/delete-attached",
        version_id=DRAFT_VERSION_ID,
        status="complete",
        callback_status="delivered",
        created_at=now,
    )
    repository.update_scan_task(
        "scan-delete-attached",
        {"report_json": {"scan_id": "scan-delete-attached"}},
    )
    deleted = repository.delete_scan_task(
        "scan-delete-attached",
        owner_user_id="scan-user-1",
        now=now,
    )
    assert deleted is not None
    assert repository.get_scan_task("scan-delete-attached") is None
    assert repository.get_version(DRAFT_VERSION_ID)["status"] == "draft"


def test_scan_status_projection_exposes_each_policy_row() -> None:
    created_at = datetime(2026, 9, 13, tzinfo=timezone.utc).isoformat()
    finished_at = datetime(2026, 9, 13, 1, tzinfo=timezone.utc).isoformat()
    requester = CurrentUser(id="scan-user-1", role="submitter")
    common = {
        "scan_id": "projection",
        "owner_user_id": requester.id,
        "created_at": created_at,
        "finished_at": finished_at,
        "callback_status": "not_required",
    }

    active = trust._scan_list_item(
        "active",
        {**common, "status": "scanning", "expires_at": None},
        requester=requester,
    )
    assert active["lifecycle"] == "scanning"
    assert active["auto_refresh"] is True
    assert active["delete_allowed"] is False
    assert active["expires_at"] is None
    assert active["execution_deadline_at"] == (
        datetime(2026, 9, 13, 0, 30, tzinfo=timezone.utc).isoformat()
    )

    for status_value in ("llm_timeout", "total_timeout", "error"):
        failure = trust._scan_list_item(
            status_value,
            {
                **common,
                "status": status_value,
                "expires_at": finished_at,
            },
            requester=requester,
        )
        assert failure["lifecycle"] == status_value
        assert failure["auto_refresh"] is False
        assert failure["delete_allowed"] is True
        assert failure["expires_at"] == finished_at

    standalone = trust._scan_list_item(
        "complete",
        {**common, "status": "complete", "version_id": None, "expires_at": finished_at},
        requester=requester,
    )
    assert standalone["lifecycle"] == "complete_unsubmitted"
    assert standalone["auto_refresh"] is False
    assert standalone["delete_allowed"] is True
    assert standalone["expires_at"] == finished_at

    attached = trust._scan_list_item(
        "attached",
        {
            **common,
            "status": "complete",
            "version_id": "version-1",
            "callback_status": "delivered",
            "expires_at": finished_at,
        },
        requester=requester,
    )
    assert attached["lifecycle"] == "submitted_reviewing"
    assert attached["auto_refresh"] is False
    assert attached["delete_allowed"] is True
    assert attached["expires_at"] is None


def test_new_request_id_cannot_duplicate_a_retained_source(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = scan_repository
    repository.create_scan_task(
        scan_id="scan-duplicate-source",
        owner_user_id="scan-user-1",
        client_request_id="duplicate-source-original",
        repo_url="https://github.com/acme/demo",
    )
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    trust._scans.clear()

    with pytest.raises(HTTPException) as raised:
        trust.submit_scan(
            BackgroundTasks(),
            repo_url="https://github.com/acme/demo",
            idempotency_key="duplicate-source-new-request",
            _user=SimpleNamespace(id="scan-user-1", role="submitter"),
        )
    assert raised.value.status_code == 409
    assert "不允许重复扫描" in str(raised.value.detail)


def test_sibling_subdirectories_of_one_repository_scan_independently(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retained task only guards its own (repository, subdirectory).

    Two capability packages that live in different directories of one
    repository are distinct sources: the second one must be able to start
    its own scan instead of colliding with the first task.
    """
    repository, _ = scan_repository
    repository.create_scan_task(
        scan_id="scan-subdir-alpha",
        owner_user_id="scan-user-1",
        client_request_id="subdir-alpha-original",
        repo_url="https://github.com/acme/demo/tree/main/skills/alpha",
        source_subdirectory="skills/alpha",
    )
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    monkeypatch.setattr(
        trust,
        "_resolve_default_branch_source",
        lambda parsed: {
            **parsed,
            "ref": "main",
            "subdir": "skills/beta",
            "repository_resolved": True,
        },
    )
    monkeypatch.setattr(
        trust,
        "_fetch_repository_commit_hash",
        lambda _parsed: "a" * 40,
    )
    trust._scans.clear()

    response = trust.submit_scan(
        BackgroundTasks(),
        repo_url="https://github.com/acme/demo/tree/main/skills/beta",
        idempotency_key="subdir-beta-request",
        _user=SimpleNamespace(id="scan-user-1", role="submitter"),
    )

    assert response["scan_id"] != "scan-subdir-alpha"
    assert {
        task["source_subdirectory"]
        for task in repository.list_scan_tasks(owner_user_id="scan-user-1")
    } == {"skills/alpha", "skills/beta"}


def test_scan_list_exposes_the_attached_submission(
    scan_repository: tuple[ProducerRepository, object],
) -> None:
    """Attached scans carry the version they were submitted with."""
    repository, _ = scan_repository
    _create_draft_version(repository)
    repository.create_scan_task(
        scan_id="scan-attached",
        owner_user_id="scan-user-1",
        client_request_id="attached-request",
        repo_url="https://github.com/acme/demo",
        version_id=DRAFT_VERSION_ID,
        status="complete",
    )

    labels = repository.list_version_labels([DRAFT_VERSION_ID])
    assert labels == {
        DRAFT_VERSION_ID: {
            "package_name": DRAFT_PACKAGE_ID,
            "version": "1.0.0",
        }
    }

    record = repository.get_scan_task("scan-attached")
    assert record is not None
    item = trust._scan_list_item(
        "scan-attached",
        trust._scan_info_from_task(record),
        requester=CurrentUser(id="scan-user-1", role="submitter"),
        version_labels=labels,
    )
    assert item["submission"] == {
        "version_id": DRAFT_VERSION_ID,
        "package_name": DRAFT_PACKAGE_ID,
        "version": "1.0.0",
    }

    detached = trust._scan_list_item(
        "scan-detached",
        {"scan_id": "scan-detached", "status": "complete", "expires_at": None},
        requester=CurrentUser(id="scan-user-1", role="submitter"),
        version_labels=labels,
    )
    assert detached["submission"] is None


def test_concurrent_source_insert_conflict_returns_409_not_500(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A losing concurrent insert surfaces as 409, not a NameError/500."""
    repository, _ = scan_repository
    repository.create_scan_task(
        scan_id="scan-race-original",
        owner_user_id="scan-user-1",
        client_request_id="race-original",
        repo_url="https://github.com/acme/demo",
    )
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    # Simulate the race window: the pre-insert dedup query misses the
    # concurrent task, so registration reaches the unique source index.
    monkeypatch.setattr(
        trust,
        "_find_scan_task_by_source_identity",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        trust,
        "_resolve_default_branch_source",
        lambda parsed: {
            **parsed,
            "ref": "main",
            "subdir": None,
            "repository_resolved": True,
        },
    )
    monkeypatch.setattr(
        trust,
        "_fetch_repository_commit_hash",
        lambda _parsed: "a" * 40,
    )
    trust._scans.clear()

    with pytest.raises(HTTPException) as raised:
        trust.submit_scan(
            BackgroundTasks(),
            repo_url="https://github.com/acme/demo",
            idempotency_key="race-second-request",
            _user=SimpleNamespace(id="scan-user-1", role="submitter"),
        )
    assert raised.value.status_code == 409
    assert "不允许重复扫描" in str(raised.value.detail)


def test_slashed_ref_dedup_miss_still_returns_409(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A default branch containing ``/`` must not break dedup into a 500."""
    repository, _ = scan_repository
    repository.create_scan_task(
        scan_id="scan-slashed-ref",
        owner_user_id="scan-user-1",
        client_request_id="slashed-ref-original",
        repo_url="https://github.com/acme/demo/tree/release/1.0",
        source_ref="release/1.0",
    )
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    monkeypatch.setattr(
        trust,
        "_resolve_default_branch_source",
        lambda parsed: {
            **parsed,
            "ref": "release/1.0",
            "subdir": None,
            "repository_resolved": True,
        },
    )
    monkeypatch.setattr(
        trust,
        "_fetch_repository_commit_hash",
        lambda _parsed: "b" * 40,
    )
    trust._scans.clear()

    # With the ref known, the whole ``tree/<ref>`` prefix is stripped, so a
    # slashed default branch no longer masquerades as a subdirectory.
    assert trust._scan_dedup_identity(
        "https://github.com/acme/demo/tree/release/1.0",
        None,
        "release/1.0",
    ) == trust._scan_dedup_identity("https://github.com/acme/demo")
    assert trust._scan_dedup_identity(
        "https://github.com/acme/demo/tree/release/1.0/skills/x",
        None,
        "release/1.0",
    ) == trust._scan_dedup_identity("https://github.com/acme/demo", "skills/x")

    # The second scan of the bare repository URL misses the URL-only
    # pre-check (the slashed ref still looks like a subdirectory there) and
    # must fall back to a 409 conflict instead of a 500.
    with pytest.raises(HTTPException) as raised:
        trust.submit_scan(
            BackgroundTasks(),
            repo_url="https://github.com/acme/demo",
            idempotency_key="slashed-ref-second",
            _user=SimpleNamespace(id="scan-user-1", role="submitter"),
        )
    assert raised.value.status_code == 409
    assert "不允许重复扫描" in str(raised.value.detail)


def test_total_timeout_marks_active_task_and_sets_failure_retention(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, _ = scan_repository
    scan_id = "scan-total-timeout-marker"
    repository.create_scan_task(
        scan_id=scan_id,
        owner_user_id="scan-user-1",
        client_request_id="total-timeout-marker",
        repo_url="https://github.com/acme/timeout",
    )
    running_llm_review = {
        "status": "running",
        "phase": "judge_b",
        "attempt": 2,
        "max_attempts": 3,
        "findings_total": 5,
        "findings_reviewed": 2,
        "findings_pending": 3,
    }
    assert repository.update_scan_task(
        scan_id,
        {"status": "llm_review", "llm_review": running_llm_review},
    )
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    trust._scans[scan_id] = trust._scan_info_from_task(
        repository.get_scan_task(scan_id)
    )
    try:
        assert trust._mark_total_scan_timeout(scan_id, lease_token=None) is True
        task = repository.get_scan_task(scan_id)
        assert task is not None
        assert task["status"] == "total_timeout"
        assert task["error"] == (
            "Scan failed: ScanTotalTimeoutError: total scan deadline exceeded"
        )
        assert task["finished_at"] is not None
        assert task["expires_at"] is not None
        assert {
            key: value
            for key, value in task["llm_review"].items()
            if key != "last_update_at"
        } == {
            **running_llm_review,
            "status": "timeout",
            "reason_code": "scan_budget_exhausted",
            "fallback": "manual_review_for_unresolved",
        }
        assert datetime.fromisoformat(
            task["llm_review"]["last_update_at"].replace("Z", "+00:00")
        ) == datetime.fromisoformat(
            task["finished_at"].replace("Z", "+00:00")
        )
        assert trust._scans[scan_id]["llm_review"] == task["llm_review"]
        assert repository.update_scan_task(
            scan_id,
            {"llm_review": {**running_llm_review, "phase": "arbitration"}},
            expected_statuses=trust._SCAN_EXECUTING_STATUSES,
        ) is False
        monkeypatch.setattr(trust, "_SCAN_PERSIST_RETRY_DELAY_SECONDS", 0)
        assert trust._update_scan_state(
            scan_id,
            {"llm_review": {**running_llm_review, "phase": "arbitration"}},
        ) is False
        assert trust._scans[scan_id]["llm_review"] == task["llm_review"]
        assert trust._scan_list_item(
            scan_id,
            trust._scans[scan_id],
            requester=CurrentUser(id="scan-user-1", role="submitter"),
        )["auto_refresh"] is False
    finally:
        trust._scans.pop(scan_id, None)


def test_total_timeout_watch_waits_until_near_deadline_before_database_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "scan-total-timeout-wait"
    trust._scans[scan_id] = {
        "scan_id": scan_id,
        "status": "scanning",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    waits: list[float] = []

    class StopOnWait:
        def is_set(self) -> bool:
            return False

        def wait(self, timeout: float) -> bool:
            waits.append(timeout)
            return True

    monkeypatch.setattr(
        trust,
        "_load_scan_info",
        lambda _scan_id: pytest.fail("database read happened before deadline"),
    )
    try:
        trust._watch_scan_total_timeout(
            scan_id,
            None,
            StopOnWait(),
            threading.Event(),
            threading.Event(),
            None,
        )
    finally:
        trust._scans.pop(scan_id, None)

    assert len(waits) == 1
    assert waits[0] > trust._SCAN_TIMEOUT_DATABASE_REFRESH_SECONDS


def test_packaging_failure_demotes_complete_task_atomically(
    scan_repository: tuple[ProducerRepository, object],
) -> None:
    repository, _ = scan_repository
    scan_id = "scan-packaging-failure"
    repository.create_scan_task(
        scan_id=scan_id,
        owner_user_id="scan-user-1",
        client_request_id="request-packaging-failure",
        repo_url="https://github.com/acme/demo",
        status="complete",
        callback_status="pending",
    )
    repository.update_scan_task(
        scan_id,
        {"report_json": {"scan_id": scan_id}, "finished_at": datetime.now(timezone.utc)},
    )

    # The generic update path deliberately rejects complete -> error:
    # a late worker must not resurrect a terminalized task.
    assert repository.update_scan_task(scan_id, {"status": "error"}) is False

    demoted = repository.terminalize_scan_task_after_packaging_failure(
        scan_id, "安装产物打包失败: forced"
    )
    assert demoted is True
    task = repository.get_scan_task(scan_id)
    assert task is not None
    assert task["status"] == "error"
    assert task["error"] == "安装产物打包失败: forced"
    assert task["callback_status"] == "delivered"
    assert task["callback_next_attempt_at"] is None
    assert task["callback_last_error"] is None
    assert task["completion_delivered_at"] is not None
    assert task["resource_consumed"] is True
    assert task["expires_at"] is not None

    # A replayed delivery attempt after a successful demotion is a no-op.
    assert (
        repository.terminalize_scan_task_after_packaging_failure(
            scan_id, "安装产物打包失败: replay"
        )
        is False
    )
    replay = repository.get_scan_task(scan_id)
    assert replay is not None
    assert replay["error"] == "安装产物打包失败: forced"


def _seed_packaging_failure_scan(
    repository: ProducerRepository,
    *,
    scan_id: str,
    package_id: str,
    version_id: str,
    report: dict[str, object],
) -> None:
    """Seed package/version/scan rows plus the runtime mirror for packaging failures.

    get_version/get_package 只返回 data JSON，因此 name/version/package_id
    也必须写在 data 里（真实 create_package / 版本 data 就是这么写的）。
    调用方必须先执行 `_patch_packaging_failure`：DB-first 模式下
    `_update_scan_state` 会写环境数据库，而不是测试用的那一份。
    """
    with repository.session_factory() as session:
        session.add(
            PackageRow(
                id=package_id,
                name="demo",
                status="draft",
                latest_version="1.0.0",
                data={"submitter_id": "scan-user-1", "name": "demo"},
            )
        )
        session.add(
            PackageVersionRow(
                id=version_id,
                package_id=package_id,
                version="1.0.0",
                status="scanning",
                data={
                    "status": "scanning",
                    "version": "1.0.0",
                    "package_id": package_id,
                    "source": {"repository_url": "https://github.com/acme/demo"},
                },
            )
        )
        session.commit()
    repository.create_scan_task(
        scan_id=scan_id,
        owner_user_id="scan-user-1",
        client_request_id=f"request-{scan_id}",
        repo_url="https://github.com/acme/demo",
        status="complete",
        callback_status="pending",
        version_id=version_id,
    )
    trust._register_scan(
        scan_id,
        {
            "scan_id": scan_id,
            "status": "complete",
            "callback_status": "pending",
            "callback_finished": False,
            "created_at": "now",
            "finished_at": None,
            "package_name": None,
            "summary": None,
            "trust_score": None,
            "expires_at": None,
            "full_report": report,
            "user_id": "scan-user-1",
            "owner_user_id": "scan-user-1",
            "source_owner_id": "scan-user-1",
            "version_id": version_id,
        },
    )
    trust._update_scan_state(
        scan_id,
        {
            "status": "complete",
            "callback_status": "pending",
            "finished_at": datetime.now(timezone.utc).isoformat(),
        },
        required=True,
    )


def _patch_packaging_failure(
    monkeypatch: pytest.MonkeyPatch, repository: ProducerRepository
) -> None:
    """Pin both repositories to the test one and make artifact packaging fail."""

    def fail_build(**_kwargs: object) -> dict[str, object]:
        raise artifacts.ArtifactError("invalid package layout")

    monkeypatch.setattr(
        producer_router, "_get_producer_repository", lambda: repository
    )
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    monkeypatch.setattr(
        trust,
        "_prepare_scan_callback_report",
        lambda _scan_id, report: (dict(report), None),
    )
    monkeypatch.setattr(trust, "_SCAN_CALLBACK_RETRY_BASE_SECONDS", 0.0)
    monkeypatch.setattr(
        trust, "_schedule_scan_callback_retry", lambda _scan_id: None
    )
    monkeypatch.setattr(artifacts, "build_artifact", fail_build)


def _drive_packaging_failure_callback(
    repository: ProducerRepository,
    *,
    scan_id: str,
    version_id: str,
    report: dict[str, object],
) -> tuple[bool, dict[str, object] | None, dict[str, object] | None]:
    try:
        delivered = trust._deliver_scan_callback(
            scan_id,
            report,
            None,
            trust._version_scan_completion_callback(version_id),
            lease_token=None,
        )
        return (
            delivered,
            repository.get_scan_task(scan_id),
            trust._get_scan(scan_id),
        )
    finally:
        with trust._SCAN_PROGRESS_LOCK:
            trust._scans.pop(scan_id, None)


def test_packaging_failure_end_to_end_keeps_detailed_error_and_demotes_scan(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """打包失败端到端：DB 行与运行时镜像都终结为 error，且保留详细错误文案。"""
    repository, _ = scan_repository
    scan_id = "scan-packaging-e2e"
    version_id = "packaging-version"
    local_dir = tmp_path / "packaging-source"
    local_dir.mkdir()
    report: dict[str, object] = {
        "scan_id": scan_id,
        "repo_url": "https://github.com/acme/demo",
        "source_ref": "main",
        "commit_hash": "c" * 40,
        "scan_report": {"summary": {"total": 0}},
        "trust_score": {},
        "local_source_dir": str(local_dir),
    }
    _patch_packaging_failure(monkeypatch, repository)
    _seed_packaging_failure_scan(
        repository,
        scan_id=scan_id,
        package_id="packaging-package",
        version_id=version_id,
        report=report,
    )

    delivered, task, mirror = _drive_packaging_failure_callback(
        repository, scan_id=scan_id, version_id=version_id, report=report
    )

    assert delivered is True
    assert task is not None
    assert task["status"] == "error"
    assert "invalid package layout" in str(task["error"])
    assert task["callback_status"] == "delivered"
    assert task["resource_consumed"] is True
    assert task["expires_at"] is not None
    assert mirror is not None
    assert mirror["status"] == "error"
    assert trust._scan_lifecycle(mirror) == "error"
    version = repository.get_version(version_id)
    assert version is not None
    assert version["status"] == "error"


def test_packaging_failure_backstop_terminalizes_db_row_without_report_scan_id(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """报告缺 scan_id 时 producer 跳过降级，回调兜底在 DB 模式也必须终结扫描行。"""
    repository, _ = scan_repository
    scan_id = "scan-backstop-e2e"
    version_id = "backstop-version"
    local_dir = tmp_path / "backstop-source"
    local_dir.mkdir()
    report: dict[str, object] = {
        "repo_url": "https://github.com/acme/demo",
        "source_ref": "main",
        "commit_hash": "c" * 40,
        "scan_report": {"summary": {"total": 0}},
        "trust_score": {},
        "local_source_dir": str(local_dir),
    }
    _patch_packaging_failure(monkeypatch, repository)
    _seed_packaging_failure_scan(
        repository,
        scan_id=scan_id,
        package_id="backstop-package",
        version_id=version_id,
        report=report,
    )

    delivered, task, mirror = _drive_packaging_failure_callback(
        repository, scan_id=scan_id, version_id=version_id, report=report
    )

    assert delivered is True
    assert task is not None
    assert task["status"] == "error"
    assert "源码目录已保留待重试" in str(task["error"])
    assert task["callback_status"] == "delivered"
    assert task["resource_consumed"] is True
    assert task["expires_at"] is not None
    assert mirror is not None
    assert mirror["status"] == "error"
    assert trust._scan_lifecycle(mirror) == "error"


def test_tree_ref_url_shares_the_bare_repository_dedup_identity(
    scan_repository: tuple[ProducerRepository, object],
) -> None:
    repository, _ = scan_repository
    repository.create_scan_task(
        scan_id="scan-bare-repo",
        owner_user_id="scan-user-1",
        client_request_id="request-bare-repo",
        repo_url="https://github.com/acme/demo",
    )

    # A /tree/<ref> spelling of the same repository must collide with the
    # bare-URL task instead of bypassing the unique index: the unique
    # index rejects it and the repository surfaces the conflict as
    # ScanTaskSourceConflictError.
    with pytest.raises(ScanTaskSourceConflictError):
        repository.create_scan_task(
            scan_id="scan-tree-ref",
            owner_user_id="scan-user-1",
            client_request_id="request-tree-ref",
            repo_url="https://github.com/acme/demo/tree/main",
        )

    # The runtime identity comparison agrees for both spellings, and a
    # genuine subdirectory still forms its own identity.
    assert trust._scan_dedup_identity(
        "https://github.com/acme/demo/tree/main"
    ) == trust._scan_dedup_identity("https://github.com/acme/demo")
    assert trust._scan_dedup_identity(
        "https://github.com/acme/demo/tree/main/skills/hello"
    ) == trust._scan_dedup_identity(
        "https://github.com/acme/demo", "skills/hello"
    )


def test_auto_refresh_covers_terminal_tasks_with_pending_callbacks() -> None:
    requester = CurrentUser(id="scan-user-1", role="submitter")
    common = {
        "scan_id": "projection",
        "owner_user_id": requester.id,
        "callback_status": "pending",
        "version_id": "version-1",
    }

    # A failed task that still owes its version a completion callback must
    # keep refreshing: the delete button stays locked until the callback
    # settles, so freezing the list would strand the user.
    for status_value in ("error", "llm_timeout", "total_timeout", "complete"):
        item = trust._scan_list_item(
            status_value,
            {**common, "status": status_value, "expires_at": None},
            requester=requester,
        )
        assert item["auto_refresh"] is True
        assert item["delete_allowed"] is False

    settled = trust._scan_list_item(
        "settled",
        {**common, "status": "error", "callback_status": "delivered"},
        requester=requester,
    )
    assert settled["auto_refresh"] is False


def test_raise_scan_source_conflict_raises_instead_of_returning() -> None:
    from src.repositories.producer_sqlalchemy import (
        _raise_scan_source_conflict,
    )

    with pytest.raises(ScanTaskSourceConflictError):
        _raise_scan_source_conflict("https://github.com/acme/demo")
