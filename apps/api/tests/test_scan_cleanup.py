"""Regression coverage for process-local scan cleanup and lifecycle handling."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import threading
import time

import pytest
from fastapi import HTTPException

import src.routers.producer as producer_router
import src.routers.trust as trust
from src.dependencies import CurrentUser
from src.services import artifacts
from src.services.producer import ProducerService, ProducerSubmissionConflict


@pytest.fixture(autouse=True)
def clear_scan_state():
    with trust._SCAN_PROGRESS_LOCK:
        trust._scans.clear()
        trust._SCAN_EXECUTION_THREADS.clear()
        trust._SCAN_ERROR_CALLBACKS.clear()
    yield
    with trust._SCAN_PROGRESS_LOCK:
        trust._scans.clear()
        trust._SCAN_EXECUTION_THREADS.clear()
        trust._SCAN_ERROR_CALLBACKS.clear()


def _register(
    scan_id: str,
    *,
    status: str = "complete",
    expires_at: float | None = None,
    callback_finished: bool = True,
    local_source_dir: Path | None = None,
    user_id: str = "user",
    source_owner_id: str | None = None,
    full_report: dict[str, object] | None = None,
) -> None:
    stored_report = full_report
    if stored_report is None:
        stored_report = (
            {"local_source_dir": str(local_source_dir)}
            if local_source_dir is not None
            else None
        )
    trust._register_scan(
        scan_id,
        {
            "status": status,
            "callback_finished": callback_finished,
            "created_at": "now",
            "finished_at": None,
            "package_name": None,
            "summary": None,
            "trust_score": None,
            "expires_at": (
                time.time() - 1 if expires_at is None else expires_at
            ),
            "full_report": stored_report,
            "user_id": user_id,
            "source_owner_id": source_owner_id or user_id,
        },
    )


def _reusable_report() -> dict[str, object]:
    return {
        "repo_url": "https://github.com/acme/demo",
        "source_ref": "main",
        "commit_hash": "a" * 40,
        "source_subdirectory": None,
    }


class _ReuseRepository:
    def __init__(self) -> None:
        self.version: dict[str, object] = {
            "id": "version-1",
            "package_id": None,
            "status": "draft",
            "source": {
                "type": "github",
                "repository_url": "https://github.com/acme/demo",
                "ref": "main",
                "commit_hash": "a" * 40,
            },
        }
        self.package: dict[str, object] = {"name": "demo", "submitter_id": "user"}
        self.status_updates: list[str] = []
        self.audit_logs: list[dict[str, object]] = []
        self.create_calls = 0

    def get_version(self, _version_id: str) -> dict[str, object]:
        return self.version

    def get_package(self, _package_id: str) -> dict[str, object]:
        return self.package

    def update_version_status(self, _version_id: str, value: str) -> None:
        self.status_updates.append(value)
        self.version["status"] = value

    def update_version_data(
        self,
        _version_id: str,
        values: dict[str, object],
    ) -> None:
        self.version.update(values)

    def save_scan_report(self, **_kwargs: object) -> None:
        return None

    def attach_scan_task_to_version(
        self,
        *,
        scan_id: str,
        version_id: str,
        owner_user_id: str,
        expected_statuses: object = None,
        operator_id: str | None = None,
    ) -> dict[str, object]:
        self.create_calls += 1
        if self.version.get("status") not in set(expected_statuses or ()):
            raise ValueError("version changed state while being submitted")
        self.version["status"] = "scanning"
        self.attached_scan_task = {
            "scan_id": scan_id,
            "version_id": version_id,
            "owner_user_id": owner_user_id,
        }
        return {"scan_id": scan_id}

    def create_version_scan_task(
        self,
        *,
        version_id: str,
        scan_id: str,
        owner_user_id: str,
        client_request_id: str | None = None,
        repo_url: str | None = None,
        source_ref: str | None = None,
        commit_hash: str | None = None,
        source_subdirectory: str | None = None,
        expected_statuses: object = None,
        operator_id: str | None = None,
        expires_at: object = None,
    ) -> dict[str, object]:
        self.create_calls += 1
        if self.version.get("status") not in set(expected_statuses or ()):
            raise ValueError("version changed state while being submitted")
        self.version["status"] = "scanning"
        self.created_scan_task = {
            "scan_id": scan_id,
            "version_id": version_id,
            "owner_user_id": owner_user_id,
        }
        trust._register_scan(
            scan_id,
            {
                "scan_id": scan_id,
                "status": "pending",
                "callback_status": "pending",
                "callback_finished": False,
                "repo_url": repo_url,
                "source_ref": source_ref,
                "commit_hash": commit_hash,
                "source_subdirectory": source_subdirectory,
                "version_id": version_id,
                "owner_user_id": owner_user_id,
                "user_id": owner_user_id,
                "created_at": "now",
                "expires_at": None,
            },
        )
        return {"scan_id": scan_id}

    def get_scan_report(self, _version_id: str = "", **_kwargs: object) -> None:
        return None

    def create_audit_log(self, **kwargs: object) -> None:
        self.audit_logs.append(kwargs)


class _ConditionalReuseRepository(_ReuseRepository):
    def create_version_scan_task(self, **_kwargs: object) -> dict[str, object]:
        raise ValueError("version changed state while being submitted")


class _AttachConflictRepository(_ReuseRepository):
    def attach_scan_task_to_version(self, **_kwargs: object) -> dict[str, object]:
        raise ValueError("scan task is already attached to another version")


class _AuditFailureRepository(_ReuseRepository):
    def create_audit_log(self, **_kwargs: object) -> None:
        raise RuntimeError("audit store unavailable")


class _CompletionAuditFailureRepository(_ReuseRepository):
    def create_audit_log(self, **_kwargs: object) -> None:
        raise RuntimeError("completion audit unavailable")


def _patch_reuse_submit_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    repository: _ReuseRepository,
) -> None:
    monkeypatch.setattr(
        producer_router,
        "_get_producer_repository",
        lambda: repository,
    )
    monkeypatch.setattr(
        trust,
        "_fetch_repository_default_branch",
        lambda _parsed: "main",
    )
    # 仓库解析的网络路径（默认分支 / 不可变 commit 固定）在测试中全部本地化。
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
        lambda parsed: {**parsed, "commit_hash": "a" * 40},
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
    monkeypatch.setattr(trust, "_SCAN_CALLBACK_RETRY_BASE_SECONDS", 0.0)
    monkeypatch.setattr(trust, "_schedule_scan_callback_retry", lambda _scan_id: None)
    # CI promotes TEST_DATABASE_URL into the DB-first scan store while these
    # endpoint tests build their records in the process-local mirror, so pin
    # the store to memory-only (same guard the cleanup tests use).
    _use_memory_only_scan_store(monkeypatch)


def _use_memory_only_scan_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin endpoint-level tests to the in-memory scan store.

    CI promotes TEST_DATABASE_URL to DATABASE_URL (tests/conftest.py), which
    switches the scan store to DB-first mode; memory-only records would then
    disappear from endpoint reads.  These tests exercise memory-mode semantics,
    so keep the repository unset regardless of the environment.
    """
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: None)


def test_expired_scan_is_cleaned_without_a_follow_up_request(
    tmp_path: Path,
) -> None:
    local_dir = tmp_path / "scan-source"
    local_dir.mkdir()
    (local_dir / "SKILL.md").write_text("content", encoding="utf-8")
    _register("scan-expired", local_source_dir=local_dir)

    assert trust._cleanup_expired_scans() == 1
    assert trust._get_scan("scan-expired") is None
    assert not local_dir.exists()


def test_cleanup_processes_at_most_fifty_oldest_records() -> None:
    base = time.time() - 1_000
    for index in range(51):
        _register(
            f"scan-{index:02d}",
            expires_at=base + index,
        )

    assert trust._cleanup_expired_scans() == 50
    assert all(trust._get_scan(f"scan-{index:02d}") is None for index in range(50))
    assert trust._get_scan("scan-50") is not None


def test_scan_status_does_not_return_an_expired_backlog_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_memory_only_scan_store(monkeypatch)
    base = time.time() - 1_000
    for index in range(51):
        _register(f"scan-{index:02d}", expires_at=base + index)

    with pytest.raises(HTTPException) as exc_info:
        trust.get_scan_status("scan-50", CurrentUser(id="user"))

    assert exc_info.value.status_code == 404
    # The request's lazy pass removed only the oldest batch; the endpoint still
    # rejects the remaining expired record instead of returning its status.
    assert trust._get_scan("scan-50") is not None


def test_running_and_unfinished_callback_scans_are_retained() -> None:
    _register("scan-running", status="scanning")
    _register("scan-finalizing", callback_finished=False)
    _register("scan-error-finalizing", status="error", callback_finished=False)

    assert trust._cleanup_expired_scans() == 0
    assert trust._get_scan("scan-running") is not None
    assert trust._get_scan("scan-finalizing") is not None
    assert trust._get_scan("scan-error-finalizing") is not None


def test_stopped_timed_out_scan_is_marked_error_before_directory_cleanup(
    tmp_path: Path,
) -> None:
    local_dir = tmp_path / "timed-out-source"
    local_dir.mkdir()
    failures: list[tuple[str, str]] = []
    scan_id = "scan-timed-out-stopped"
    now = time.time()
    trust._register_scan(
        scan_id,
        {
            "status": "scanning",
            "execution_started": True,
            "execution_finished": False,
            "execution_deadline_at": now - 1,
            "callback_finished": False,
            "resource_consumed": False,
            "created_at": "now",
            "finished_at": None,
            "full_report": {"local_source_dir": str(local_dir)},
            "expires_at": now - 1,
        },
        on_error=lambda scan_id, error: failures.append((scan_id, error)),
    )
    finished_thread = threading.Thread(target=lambda: None)
    finished_thread.start()
    finished_thread.join()
    with trust._SCAN_PROGRESS_LOCK:
        trust._SCAN_EXECUTION_THREADS[scan_id] = finished_thread

    assert trust._cleanup_expired_scans() == 1
    assert failures == [
        (scan_id, "Scan exceeded the maximum execution time"),
    ]
    assert trust._get_scan(scan_id) is None
    assert not local_dir.exists()


def test_live_timed_out_scan_is_retained_until_worker_stops(
    tmp_path: Path,
) -> None:
    local_dir = tmp_path / "live-timed-out-source"
    local_dir.mkdir()
    scan_id = "scan-timed-out-live"
    now = time.time()
    trust._register_scan(
        scan_id,
        {
            "status": "scanning",
            "execution_started": True,
            "execution_finished": False,
            "execution_deadline_at": now - 1,
            "callback_finished": False,
            "resource_consumed": False,
            "created_at": "now",
            "finished_at": None,
            "full_report": {"local_source_dir": str(local_dir)},
            "expires_at": now - 1,
        },
    )
    stop_thread = threading.Event()
    live_thread = threading.Thread(target=stop_thread.wait)
    live_thread.start()
    with trust._SCAN_PROGRESS_LOCK:
        trust._SCAN_EXECUTION_THREADS[scan_id] = live_thread

    try:
        assert trust._cleanup_expired_scans() == 0
        info = trust._get_scan(scan_id)
        assert info is not None
        assert info["status"] == "scanning"
        assert local_dir.exists()
    finally:
        stop_thread.set()
        live_thread.join()


def test_finish_scan_execution_marks_error_and_invokes_failure_callback() -> None:
    """执行收尾时扫描未完成：记录置 error 并触发 on_error（生产路径契约）。"""
    scan_id = "scan-execution-stopped"
    failures: list[tuple[str, str]] = []
    trust._register_scan(
        scan_id,
        {
            "status": "scanning",
            "execution_started": True,
            "execution_finished": False,
            "callback_finished": False,
            "resource_consumed": False,
            "created_at": "now",
            "finished_at": None,
            "full_report": None,
            "expires_at": time.time() + 100,
        },
        on_error=lambda sid, error: failures.append((sid, error)),
    )

    trust._finish_scan_execution(scan_id)

    info = trust._get_scan(scan_id)
    assert info is not None
    assert info["status"] == "error"
    assert info["execution_finished"] is True
    assert info["callback_finished"] is True
    assert failures == [(scan_id, "扫描任务在完成收尾前停止")]


def test_finish_scan_execution_preserves_delivered_success() -> None:
    scan_id = "scan-execution-complete"
    trust._register_scan(
        scan_id,
        {
            "status": "complete",
            "execution_started": True,
            "execution_finished": False,
            "callback_finished": False,
            "callback_status": "delivered",
            "completion_delivered_at": "2026-09-16T00:00:00Z",
            "created_at": "now",
            "finished_at": "now",
            "expires_at": time.time() + 100,
        },
    )

    trust._finish_scan_execution(scan_id)

    info = trust._get_scan(scan_id)
    assert info is not None
    assert info["status"] == "complete"
    assert info["execution_finished"] is True
    assert info.get("error") is None
    assert trust._scan_finished(info) is True


def test_cleanup_lock_prevents_overlap_and_duplicate_directory_deletion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shared_dir = tmp_path / "shared-source"
    shared_dir.mkdir()
    _register("scan-a", local_source_dir=shared_dir)
    _register("scan-b", local_source_dir=shared_dir)

    calls: list[str] = []
    calls_lock = threading.Lock()

    def record_delete(path: str) -> None:
        with calls_lock:
            calls.append(path)
        time.sleep(0.05)
        Path(path).rmdir()

    def delete_directories(paths: dict[str, str]) -> dict[str, bool]:
        result: dict[str, bool] = {}
        for key, path in paths.items():
            record_delete(path)
            result[key] = not Path(path).exists()
        return result

    monkeypatch.setattr(trust, "_remove_scan_directories_with_timeout", delete_directories)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: trust._cleanup_expired_scans(), range(2)))

    assert sorted(results) == [0, 2]
    assert len(calls) == 1
    assert trust._get_scan("scan-a") is None
    assert trust._get_scan("scan-b") is None


def test_one_directory_failure_does_not_block_the_rest_of_the_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _register("scan-fails")
    _register("scan-succeeds-a")
    _register("scan-succeeds-b")
    calls: list[str] = []

    def cleanup_directories(paths: dict[str, str]) -> dict[str, bool]:
        result: dict[str, bool] = {}
        for key, path in paths.items():
            calls.append(path)
            result[key] = path != "fail"
        return result

    with trust._SCAN_PROGRESS_LOCK:
        trust._scans["scan-fails"]["full_report"] = {
            "local_source_dir": "fail"
        }
        trust._scans["scan-succeeds-a"]["full_report"] = {
            "local_source_dir": "ok-a"
        }
        trust._scans["scan-succeeds-b"]["full_report"] = {
            "local_source_dir": "ok-b"
        }
    monkeypatch.setattr(
        trust,
        "_remove_scan_directories_with_timeout",
        cleanup_directories,
    )

    assert trust._cleanup_expired_scans() == 2
    assert trust._get_scan("scan-fails") is not None
    assert trust._get_scan("scan-succeeds-a") is None
    assert trust._get_scan("scan-succeeds-b") is None
    assert calls == ["fail", "ok-a", "ok-b"]


def test_failed_directory_removal_retains_record_for_a_later_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local_dir = tmp_path / "retry-source"
    local_dir.mkdir()
    _register("scan-retry", local_source_dir=local_dir)

    monkeypatch.setattr(
        trust,
        "_remove_scan_directories_with_timeout",
        lambda paths: {key: False for key in paths},
    )
    assert trust._cleanup_expired_scans() == 0
    assert trust._get_scan("scan-retry") is not None
    assert local_dir.exists()

    def remove_directories(paths: dict[str, str]) -> dict[str, bool]:
        result: dict[str, bool] = {}
        for key, path in paths.items():
            Path(path).rmdir()
            result[key] = not Path(path).exists()
        return result

    monkeypatch.setattr(
        trust,
        "_remove_scan_directories_with_timeout",
        remove_directories,
    )
    assert trust._cleanup_expired_scans() == 1
    assert trust._get_scan("scan-retry") is None
    assert not local_dir.exists()


def test_expired_running_scan_remains_queryable_and_listed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_memory_only_scan_store(monkeypatch)
    _register(
        "scan-running-expired",
        status="scanning",
        expires_at=time.time() - 1,
        callback_finished=False,
    )

    status_result = trust.get_scan_status(
        "scan-running-expired",
        CurrentUser(id="user"),
    )
    assert status_result["status"] == "scanning"
    assert "scan-running-expired" in {
        row["scan_id"]
        for row in trust.list_scans(CurrentUser(id="user"))
    }


def test_initial_scan_binding_rejection_happens_before_version_state_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _ReuseRepository()
    _register(
        "scan-owned-by-someone-else",
        expires_at=time.time() + 100,
        user_id="another-user",
        source_owner_id="another-user",
        full_report=_reusable_report(),
    )
    _patch_reuse_submit_dependencies(monkeypatch, repository)

    with pytest.raises(HTTPException) as raised:
        producer_router.submit_version(
            "version-1",
            producer_router.BackgroundTasks(),
            producer_router.SubmitVersionRequest(
                initial_scan_id="scan-owned-by-someone-else",
            ),
            _user=CurrentUser(id="user", role="submitter"),
        )

    assert raised.value.status_code == 403
    assert repository.status_updates == []
    assert repository.version["status"] == "draft"


def test_initial_scan_source_binding_rejection_happens_before_version_state_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _ReuseRepository()
    report = _reusable_report()
    report["repo_url"] = "https://github.com/acme/other"
    _register(
        "scan-for-other-repository",
        expires_at=time.time() + 100,
        full_report=report,
    )
    _patch_reuse_submit_dependencies(monkeypatch, repository)

    with pytest.raises(HTTPException) as raised:
        producer_router.submit_version(
            "version-1",
            producer_router.BackgroundTasks(),
            producer_router.SubmitVersionRequest(
                initial_scan_id="scan-for-other-repository",
            ),
            _user=CurrentUser(id="user", role="submitter"),
        )

    assert raised.value.status_code == 400
    assert repository.status_updates == []
    assert repository.version["status"] == "draft"


def test_reviewer_can_reuse_a_scan_they_initiated_for_another_users_package(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _ReuseRepository()
    repository.version["package_id"] = "package-1"
    repository.package = {"name": "demo", "submitter_id": "package-owner"}
    _register(
        "scan-started-by-reviewer",
        expires_at=time.time() + 100,
        user_id="reviewer",
        source_owner_id="reviewer",
        full_report=_reusable_report(),
    )
    _patch_reuse_submit_dependencies(monkeypatch, repository)

    def complete(self, version_id: str, _full_report: dict[str, object]) -> bool:
        self.repository.update_version_status(version_id, "pending_review")
        return True

    monkeypatch.setattr(
        producer_router.ProducerService,
        "handle_scan_complete",
        complete,
    )

    result = producer_router.submit_version(
        "version-1",
        producer_router.BackgroundTasks(),
        producer_router.SubmitVersionRequest(
            initial_scan_id="scan-started-by-reviewer",
        ),
        _user=CurrentUser(id="reviewer", role="reviewer"),
    )

    assert result.status == "pending_review"
    assert repository.version["status"] == "pending_review"


def test_same_version_cannot_start_two_scans_concurrently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _ReuseRepository()
    _patch_reuse_submit_dependencies(monkeypatch, repository)

    def invoke():
        try:
            return producer_router.submit_version(
                "version-1",
                producer_router.BackgroundTasks(),
                _user=CurrentUser(id="user", role="submitter"),
            )
        except HTTPException as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _index: invoke(), range(2)))

    assert sum(isinstance(result, producer_router.SubmitResponse) for result in results) == 1
    conflicts = [result for result in results if isinstance(result, HTTPException)]
    assert len(conflicts) == 1
    assert conflicts[0].status_code == 409
    assert repository.create_calls == 1


def test_signal_collection_failure_keeps_durable_scan_recoverable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _ReuseRepository()
    _patch_reuse_submit_dependencies(monkeypatch, repository)

    def fail_signals(*_args, **_kwargs):
        raise RuntimeError("signal store unavailable")

    monkeypatch.setattr(
        "src.services.signals.collect_platform_signals",
        fail_signals,
    )

    response = producer_router.submit_version(
        "version-1",
        producer_router.BackgroundTasks(),
        _user=CurrentUser(id="user", role="submitter"),
    )

    assert response.status == "scanning"
    assert repository.version["status"] == "scanning"
    assert "scan_error" not in repository.version


def test_scan_start_audit_failure_keeps_durable_scan_recoverable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _AuditFailureRepository()
    _patch_reuse_submit_dependencies(monkeypatch, repository)

    response = producer_router.submit_version(
        "version-1",
        producer_router.BackgroundTasks(),
        _user=CurrentUser(id="user", role="submitter"),
    )

    assert response.status == "scanning"
    assert repository.version["status"] == "scanning"


def test_initial_scan_callback_failure_stays_pending_for_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _ReuseRepository()
    _register(
        "scan-handoff-fails",
        expires_at=time.time() + 100,
        full_report=_reusable_report(),
    )
    _patch_reuse_submit_dependencies(monkeypatch, repository)

    def fail_handoff(*_args, **_kwargs):
        raise RuntimeError("handoff failed")

    monkeypatch.setattr(
        producer_router.ProducerService,
        "handle_scan_complete",
        fail_handoff,
    )

    response = producer_router.submit_version(
        "version-1",
        producer_router.BackgroundTasks(),
        producer_router.SubmitVersionRequest(
            initial_scan_id="scan-handoff-fails",
        ),
        _user=CurrentUser(id="user", role="submitter"),
    )

    assert response.status == "scanning"
    assert repository.version["status"] == "scanning"
    info = trust._get_scan("scan-handoff-fails")
    assert info is not None
    assert info["callback_status"] == "pending"
    assert info.get("resource_consumed") is not True


def test_scan_completion_audit_failure_compensates_pending_review(
    tmp_path: Path,
) -> None:
    repository = _CompletionAuditFailureRepository()
    repository.version.update(
        {
            "status": "scanning",
            "version": "1.0.0",
            "installation": {
                "method": "manual",
                "target_client": "claude-code",
            },
        }
    )
    local_dir = tmp_path / "completion-retry-source"
    local_dir.mkdir()

    with pytest.raises(RuntimeError, match="completion audit unavailable"):
        ProducerService(repository).handle_scan_complete(
            "version-1",
            {
                "scan_id": "scan-completion-audit-fails",
                "repo_url": "https://github.com/acme/demo",
                "commit_hash": "a" * 40,
                "scan_report": {},
                "trust_score": {},
                "local_source_dir": str(local_dir),
            },
        )

    assert repository.version["status"] == "error"
    assert "completion audit unavailable" in str(
        repository.version["scan_error"]
    )
    assert local_dir.exists()


def test_initial_scan_callback_failure_after_version_update_remains_retryable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _ReuseRepository()
    _register(
        "scan-pending-review-fails",
        expires_at=time.time() + 100,
        full_report=_reusable_report(),
    )
    _patch_reuse_submit_dependencies(monkeypatch, repository)

    def mark_pending_then_fail(self, version_id: str, _full_report) -> bool:
        self.repository.update_version_status(version_id, "pending_review")
        raise RuntimeError("completion failed after pending review")

    monkeypatch.setattr(
        producer_router.ProducerService,
        "handle_scan_complete",
        mark_pending_then_fail,
    )

    response = producer_router.submit_version(
        "version-1",
        producer_router.BackgroundTasks(),
        producer_router.SubmitVersionRequest(
            initial_scan_id="scan-pending-review-fails",
        ),
        _user=CurrentUser(id="user", role="submitter"),
    )

    assert response.status == "pending_review"
    assert repository.version["status"] == "pending_review"
    info = trust._get_scan("scan-pending-review-fails")
    assert info is not None
    assert info["callback_status"] == "pending"
    assert info.get("resource_consumed") is not True


def test_background_dispatch_failure_leaves_leased_scan_recoverable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _ReuseRepository()
    _patch_reuse_submit_dependencies(monkeypatch, repository)

    class FailingBackgroundTasks:
        def add_task(self, *_args, **_kwargs) -> None:
            raise RuntimeError("background task unavailable")

    with pytest.raises(RuntimeError, match="background task unavailable"):
        producer_router.submit_version(
            "version-1",
            FailingBackgroundTasks(),
            _user=CurrentUser(id="user", role="submitter"),
        )

    assert repository.version["status"] == "scanning"
    scan_rows = trust._list_scan_snapshots()
    assert len(scan_rows) == 1
    _scan_id, scan_info = scan_rows[0]
    assert scan_info["status"] == "pending"
    assert scan_info["lease_token"] is not None
    assert scan_info["callback_finished"] is False


def test_persisted_reuse_conflict_is_not_downgraded_to_a_new_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _AttachConflictRepository()
    _register(
        "scan-already-claimed",
        expires_at=time.time() + 100,
        full_report=_reusable_report(),
    )
    _patch_reuse_submit_dependencies(monkeypatch, repository)

    with pytest.raises(HTTPException) as raised:
        producer_router.submit_version(
            "version-1",
            producer_router.BackgroundTasks(),
            producer_router.SubmitVersionRequest(
                initial_scan_id="scan-already-claimed",
            ),
            _user=CurrentUser(id="user", role="submitter"),
        )

    assert raised.value.status_code == 409
    assert repository.version["status"] == "draft"
    assert repository.status_updates == []


def test_consumed_initial_scan_is_rejected_on_reuse_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """已消费的扫描（未过期）在回落复用路径上必须被显式拒绝（409）。"""
    repository = _ReuseRepository()
    _register(
        "scan-consumed",
        expires_at=time.time() + 100,
        full_report=_reusable_report(),
    )
    trust._update_scan("scan-consumed", resource_consumed=True)
    _use_memory_only_scan_store(monkeypatch)
    _patch_reuse_submit_dependencies(monkeypatch, repository)

    with pytest.raises(HTTPException) as raised:
        producer_router.submit_version(
            "version-1",
            producer_router.BackgroundTasks(),
            producer_router.SubmitVersionRequest(initial_scan_id="scan-consumed"),
            _user=CurrentUser(id="user", role="submitter"),
        )

    assert raised.value.status_code == 409
    assert "已被消费" in str(raised.value.detail)
    assert repository.status_updates == []


def test_conditional_version_transition_rejects_a_lost_submission_race() -> None:
    repository = _ConditionalReuseRepository()

    with pytest.raises(ProducerSubmissionConflict):
        ProducerService(repository).submit_version(
            "version-1",
            user_id="user",
            scan_task={
                "owner_user_id": "user",
                "source_ref": "main",
                "commit_hash": "a" * 40,
            },
        )

    assert repository.version["status"] == "draft"


def test_initial_scan_is_consumed_only_after_pending_review_is_persisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _ReuseRepository()
    _register(
        "scan-to-reuse",
        expires_at=time.time() + 100,
        full_report=_reusable_report(),
    )
    _patch_reuse_submit_dependencies(monkeypatch, repository)

    def complete(self, version_id: str, _full_report: dict[str, object]) -> bool:
        self.repository.update_version_status(version_id, "pending_review")
        return True

    monkeypatch.setattr(
        producer_router.ProducerService,
        "handle_scan_complete",
        complete,
    )

    result = producer_router.submit_version(
        "version-1",
        producer_router.BackgroundTasks(),
        producer_router.SubmitVersionRequest(initial_scan_id="scan-to-reuse"),
        _user=CurrentUser(id="user", role="submitter"),
    )

    assert result.status == "pending_review"
    assert repository.version["status"] == "pending_review"
    info = trust._get_scan("scan-to-reuse")
    assert info is not None
    assert info["resource_consumed"] is True
    assert info["callback_status"] == "delivered"


def test_packaging_failure_is_terminal_and_does_not_retry_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _ReuseRepository()
    _register(
        "scan-consumer-fails",
        expires_at=time.time() + 100,
        full_report=_reusable_report(),
    )
    _patch_reuse_submit_dependencies(monkeypatch, repository)
    calls = 0

    def packaging_failure(self, version_id: str, _report: object) -> bool:
        nonlocal calls
        calls += 1
        self.repository.update_version_status(version_id, "error")
        return False

    monkeypatch.setattr(
        producer_router.ProducerService,
        "handle_scan_complete",
        packaging_failure,
    )

    response = producer_router.submit_version(
        "version-1",
        producer_router.BackgroundTasks(),
        producer_router.SubmitVersionRequest(initial_scan_id="scan-consumer-fails"),
        _user=CurrentUser(id="user", role="submitter"),
    )

    assert response.status == "error"
    assert calls == 1
    info = trust._get_scan("scan-consumer-fails")
    assert info is not None
    assert info["status"] == "error"
    assert info["error"]
    assert trust._scan_lifecycle(info) == "error"
    assert info["callback_status"] == "delivered"
    assert info["resource_consumed"] is True


def test_packaging_failure_without_version_row_still_marks_scan_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """版本行缺失也是终态失败：producer 直接终结扫描任务。"""

    class _MissingVersionRepository(_ReuseRepository):
        def get_version(self, _version_id: str) -> None:
            return None

    repository = _MissingVersionRepository()
    _patch_reuse_submit_dependencies(monkeypatch, repository)
    scan_id = "scan-missing-version"
    local_dir = tmp_path / "missing-version-source"
    local_dir.mkdir()
    report = {
        **_reusable_report(),
        "scan_id": scan_id,
        "scan_report": {"summary": {"total": 0}},
        "trust_score": {},
        "local_source_dir": str(local_dir),
    }
    _register(scan_id, expires_at=None, full_report=report)
    trust._update_scan_state(
        scan_id,
        {"status": "complete", "callback_status": "pending"},
        required=True,
    )

    delivered = trust._deliver_scan_callback(
        scan_id,
        report,
        None,
        trust._version_scan_completion_callback("version-1"),
        lease_token=None,
    )

    assert delivered is True
    info = trust._get_scan(scan_id)
    assert info is not None
    assert info["status"] == "error"
    assert "版本记录不存在" in str(info["error"])
    assert trust._scan_lifecycle(info) == "error"


def test_packaging_failure_without_report_scan_id_still_marks_scan_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """报告缺少 scan_id 时 producer 侧跳过降级，回调兜底必须置 error。"""
    repository = _ReuseRepository()
    repository.version.update(
        {
            "package_id": "package-1",
            "version": "1.0.0",
            "installation": {"method": "copy_directory"},
        }
    )
    _patch_reuse_submit_dependencies(monkeypatch, repository)

    def fail_build(**_kwargs: object) -> dict[str, object]:
        raise artifacts.ArtifactError("invalid package layout")

    monkeypatch.setattr(artifacts, "build_artifact", fail_build)
    scan_id = "scan-without-report-id"
    local_dir = tmp_path / "missing-scan-id-source"
    local_dir.mkdir()
    report = {
        "repo_url": "https://github.com/acme/demo",
        "source_ref": "main",
        "commit_hash": "a" * 40,
        "scan_report": {"summary": {"total": 0}},
        "trust_score": {},
        "local_source_dir": str(local_dir),
    }
    _register(scan_id, expires_at=None, full_report=report)
    trust._update_scan_state(
        scan_id,
        {"status": "complete", "callback_status": "pending"},
        required=True,
    )

    delivered = trust._deliver_scan_callback(
        scan_id,
        report,
        None,
        trust._version_scan_completion_callback("version-1"),
        lease_token=None,
    )

    assert delivered is True
    info = trust._get_scan(scan_id)
    assert info is not None
    assert info["status"] == "error"
    assert "源码目录已保留待重试" in str(info["error"])
    assert trust._scan_lifecycle(info) == "error"


def test_artifact_packaging_failure_keeps_source_directory_retryable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = _ReuseRepository()
    repository.version.update(
        {
            "package_id": "package-1",
            "version": "1.0.0",
            "installation": {"method": "copy_directory"},
        }
    )
    local_dir = tmp_path / "packaging-failure-source"
    local_dir.mkdir()
    removed: list[object] = []

    def fail_build(**_kwargs: object) -> dict[str, object]:
        raise artifacts.ArtifactError("invalid package layout")

    monkeypatch.setattr(artifacts, "build_artifact", fail_build)
    monkeypatch.setattr(artifacts, "force_rmtree", removed.append)

    result = ProducerService(repository).handle_scan_complete(
        "version-1",
        {
            "scan_report": {"summary": {"total": 0}},
            "trust_score": {},
            "commit_hash": "a" * 40,
            "local_source_dir": str(local_dir),
        },
    )

    assert result is False
    assert repository.version["status"] == "error"
    assert local_dir.exists()
    assert removed == []


def test_acquisition_publishes_temp_directory_before_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    acquired_dir = tmp_path / "acquired-source"
    acquired_dir.mkdir()
    paths: list[str] = []

    monkeypatch.setattr(
        trust.tempfile,
        "mkdtemp",
        lambda *, prefix, **_kwargs: str(acquired_dir),
    )

    def fail_commit_resolution(*_args, **_kwargs):
        raise RuntimeError("temporary network failure")

    monkeypatch.setattr(
        trust,
        "_fetch_repository_commit_hash",
        fail_commit_resolution,
    )
    monkeypatch.setattr(trust, "force_rmtree", lambda _path: None)

    result = trust._acquire_repo_source(
        {"owner": "acme", "repo": "demo", "ref": "main"},
        temp_dir_callback=paths.append,
    )

    assert result == (None, "", "")
    assert paths == [str(acquired_dir)]
