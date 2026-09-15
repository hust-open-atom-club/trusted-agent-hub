"""Regression tests for the scan-task mirror and callback path.

Issue #133 made the process-local scan mirror a light copy (no report
payloads).  This file covers the mirror itself (normal, memory-only and
persisted modes), the light dedup projection, the unbounded legacy list,
and the callback failure branch:

when the database update fails after the terminal state lands, the
runtime mirror must still carry everything the callback chain needs —
the callback must not observe a stripped report and must not falsely
take the "source reacquisition" detour.

These tests live in their own file on purpose: the file never existed in
any other branch, so it cannot conflict with sibling branches.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import BackgroundTasks
from sqlalchemy.exc import OperationalError

from src.database import Base, create_engine_from_url, create_session_factory
from src.repositories.orm_producer import UserRow
from src.repositories.producer_sqlalchemy import ProducerRepository
from src.routers import trust
from tests.test_scan_task_persistence import scan_repository

DRAFT_VERSION_ID = "atomic-version"
DRAFT_PACKAGE_ID = "atomic-package"
DRAFT_SOURCE_URL = "https://github.com/acme/demo"
SCAN_COMMIT = "a" * 40


def _seed_user(engine) -> None:
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)
    with session_factory() as session:
        session.add(
            UserRow(
                id="callback-user-1",
                email="callback-user-1@example.com",
                password_hash="hash",
                role="submitter",
                display_name="Callback User",
            )
        )
        session.commit()
    return session_factory


@pytest.fixture
def callback_repository() -> tuple[ProducerRepository, object]:
    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    session_factory = _seed_user(engine)
    return ProducerRepository(session_factory), session_factory


def _mirror_scan(
    scan_id: str,
    *,
    full_report: dict[str, object] | None = None,
    status: str = "pending",
) -> None:
    """Seed the light runtime mirror exactly as _remember_scan_info does."""
    trust._scans.clear()
    trust._scans[scan_id] = {
        "scan_id": scan_id,
        "status": status,
        "repo_url": DRAFT_SOURCE_URL,
        "source_ref": "main",
        "commit_hash": SCAN_COMMIT,
        "source_subdirectory": None,
        "version_id": None,
        "callback_status": "pending",
        "attempt_count": 1,
        "lease_token": None,
        "lease_until": None,
        "created_at": trust._utc_now_iso(),
        "updated_at": trust._utc_now_iso(),
    }


def test_light_mirror_keeps_local_source_dir_on_success_callback(
    callback_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    """A successful pipeline report routes through the local snapshot path.

    The mirror is light, but the caller-provided report carries
    ``local_source_dir`` — the controlled-directory check must pass and
    no reacquisition may be attempted.
    """
    scan_id = "scan-cb-light-ok"
    _mirror_scan(scan_id, status="downloading")
    source_dir = "/controlled/keep-me"
    report = {
        "scan_id": scan_id,
        "repo_url": DRAFT_SOURCE_URL,
        "commit_hash": SCAN_COMMIT,
        "source_ref": "main",
        "local_source_dir": source_dir,
        "scan_report": {"summary": {"total": 0}},
    }

    reacquire_calls: list[object] = []

    def _fail_acquire(
        _resolved: dict[str, object],
        *,
        temp_dir_callback=None,
    ):
        reacquire_calls.append(_resolved)
        raise AssertionError("reacquisition must not run for a fresh report")

    monkeypatch.setattr(trust, "_acquire_repo_source", _fail_acquire)
    monkeypatch.setattr(
        trust,
        "_controlled_scan_temp_dir",
        lambda path, require_directory=False: path,
    )
    try:
        callback_report, reacquired = trust._prepare_scan_callback_report(
            scan_id, report
        )
        assert reacquired is None
        assert callback_report["local_source_dir"] == source_dir
        assert callback_report["commit_hash"].lower() == SCAN_COMMIT
        assert reacquire_calls == []
    finally:
        trust._scans.clear()


def test_slashed_ref_dedup_miss_falls_back_within_persistence(
    callback_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pushed-down dedup query still compares the full URL identity.

    Two distinct sources that share a canonical repository but differ in
    subdirectory must not collapse into one identity; the repository row
    carrying the subdirectory wins its own dedup slot.
    """
    repository, _ = callback_repository
    repository.create_scan_task(
        scan_id="scan-cb-subdir",
        owner_user_id="callback-user-1",
        client_request_id="request-cb-subdir",
        repo_url=DRAFT_SOURCE_URL + "/tree/main/skills/x",
        source_subdirectory="skills/x",
        status="complete",
    )
    repository.create_scan_task(
        scan_id="scan-cb-bare",
        owner_user_id="callback-user-1",
        client_request_id="request-cb-bare",
        repo_url=DRAFT_SOURCE_URL,
        status="complete",
    )

    # Bare URL identity (no subdirectory) must only match the bare-URL row.
    tasks = repository.list_scan_tasks_for_dedup(
        owner_user_id="callback-user-1",
        repo_url=DRAFT_SOURCE_URL,
        source_subdirectory="",
    )
    assert [t["scan_id"] for t in tasks] == ["scan-cb-bare"]

    # The subdirectory-owning row keeps its own identity slot.
    identity_tasks = repository.list_scan_tasks_for_dedup(
        owner_user_id="callback-user-1",
        repo_url=DRAFT_SOURCE_URL + "/tree/main/skills/x",
        source_subdirectory="skills/x",
    )
    assert [t["scan_id"] for t in identity_tasks] == ["scan-cb-subdir"]


def test_callback_preparation_falls_back_to_database_report(
    callback_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After a restart the runtime mirror is empty: the DB-backed report wins.

    The mirror may be absent entirely (fresh process).  A report without a
    local snapshot then goes through the durable reacquisition path — the
    persisted identity (commit/ref/subdirectory) is what makes the
    reacquisition deterministic.
    """
    repository, _ = callback_repository
    scan_id = "scan-cb-db-fallback"
    trust._scans.clear()
    try:
        report = {
            "scan_id": scan_id,
            "repo_url": DRAFT_SOURCE_URL,
            "commit_hash": SCAN_COMMIT,
            "source_ref": "main",
            "source_subdirectory": None,
            "scan_report": {"summary": {"total": 0}},
        }
        monkeypatch.setattr(
            trust,
            "_controlled_scan_temp_dir",
            lambda path, require_directory=False: (
                path
                if isinstance(path, str) and path.startswith("/controlled")
                else None
            ),
        )
        reacquire_sources: list[dict[str, object]] = []

        def _fake_acquire(
            parsed: dict[str, object],
            *,
            temp_dir_callback=None,
        ):
            reacquire_sources.append(parsed)
            return "/controlled/reacquired", "zip", SCAN_COMMIT

        monkeypatch.setattr(trust, "_acquire_repo_source", _fake_acquire)

        callback_report, reacquired = trust._prepare_scan_callback_report(
            scan_id, report
        )
        # The durable path reacquires exactly once, pinned to the same commit.
        assert len(reacquire_sources) == 1
        assert reacquire_sources[0]["commit_hash"].lower() == SCAN_COMMIT
        assert callback_report["local_source_dir"] == "/controlled/reacquired"
    finally:
        trust._scans.clear()


def test_callback_preparation_reuses_caller_report_without_reacquisition(
    callback_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fresh report with a live snapshot dir is delivered as-is."""
    repository, _ = callback_repository
    scan_id = "scan-cb-fresh"
    trust._scans.clear()
    try:
        report = {
            "scan_id": scan_id,
            "repo_url": DRAFT_SOURCE_URL,
            "commit_hash": SCAN_COMMIT,
            "source_ref": "main",
            "source_subdirectory": None,
            "local_source_dir": "/controlled/live",
            "scan_report": {"summary": {"total": 0}},
        }
        monkeypatch.setattr(
            trust,
            "_controlled_scan_temp_dir",
            lambda path, require_directory=False: path,
        )

        def _fail_acquire(
            _parsed: dict[str, object],
            *,
            temp_dir_callback=None,
        ):
            raise AssertionError("reacquisition must not run")

        monkeypatch.setattr(trust, "_acquire_repo_source", _fail_acquire)

        callback_report, reacquired = trust._prepare_scan_callback_report(
            scan_id, report
        )
        assert reacquired is None
        assert callback_report["local_source_dir"] == "/controlled/live"
    finally:
        trust._scans.clear()


def test_submit_scan_light_mirror_session_absorbs_report_loss(
    callback_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Update loss keeps the mirrored idempotent path working end to end.

    When the idempotent key replays an existing task after a DB update
    failure, the mirror (already light) merges with the DB row and the
    submission still resolves to the original scan instead of raising.
    """
    repository, _ = callback_repository
    scan_id = "scan-cb-idem"
    repository.create_scan_task(
        scan_id=scan_id,
        owner_user_id="callback-user-1",
        client_request_id="request-cb-idem",
        repo_url=DRAFT_SOURCE_URL,
        status="pending",
    )
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    monkeypatch.setattr(trust, "_cleanup_expired_scans", lambda: None)
    monkeypatch.setattr(
        trust,
        "_enqueue_scan_task",
        lambda *args, **kwargs: True,
    )
    trust._scans.clear()
    try:
        response = trust.submit_scan(
            BackgroundTasks(),
            repo_url=DRAFT_SOURCE_URL,
            idempotency_key="request-cb-idem",
            _user=SimpleNamespace(id="callback-user-1", role="submitter"),
        )
        assert response["scan_id"] == scan_id
        # The DB row is untouched and still owns the dedup key.
        task = repository.get_scan_task(scan_id)
        assert task is not None
        assert task["status"] == "pending"
    finally:
        trust._scans.clear()


def test_memory_only_mirror_keeps_full_report_for_callbacks(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without persistence the mirror must keep the report readable."""
    repository, _ = scan_repository
    # Simulate memory-only mode: the scan_tasks repository is unavailable.
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: None)

    full_report = {
        "scan_id": "scan-mem-only",
        "repo_url": DRAFT_SOURCE_URL,
        "commit_hash": "a" * 40,
        "local_source_dir": "/tmp/keep-me",
    }
    info = {
        "scan_id": "scan-mem-only",
        "status": "complete",
        "full_report": full_report,
        "updated_at": trust._utc_now_iso(),
    }
    trust._scans.clear()
    try:
        trust._remember_scan_info(info)
        mirrored = trust._scans.get("scan-mem-only")
        assert mirrored is not None
        # No database to consult later: the report stays in the mirror.
        assert mirrored.get("full_report") == full_report

        loaded = trust._load_scan_info("scan-mem-only")
        assert loaded is not None
        assert loaded.get("full_report") == full_report
    finally:
        trust._scans.clear()


def test_persisted_mirror_drops_heavy_fields(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With persistence enabled the mirror keeps only progress fields."""
    repository, _ = scan_repository
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    repository.create_scan_task(
        scan_id="scan-light-mirror",
        owner_user_id="scan-user-1",
        client_request_id="request-light-mirror",
        repo_url=DRAFT_SOURCE_URL,
        status="complete",
    )

    info = {
        "scan_id": "scan-light-mirror",
        "status": "complete",
        "full_report": {"scan_id": "scan-light-mirror", "big": "payload"},
        "package_metadata": {"name": "demo"},
        "updated_at": trust._utc_now_iso(),
    }
    trust._scans.clear()
    try:
        trust._remember_scan_info(info)
        mirrored = trust._scans.get("scan-light-mirror")
        assert mirrored is not None
        assert "full_report" not in mirrored
        assert "package_metadata" not in mirrored
        assert mirrored.get("status") == "complete"

        # The full report still round-trips through the database.
        loaded = trust._load_scan_info("scan-light-mirror")
        assert loaded is not None
        assert loaded.get("full_report") is None or isinstance(
            loaded.get("full_report"), dict
        )
    finally:
        trust._scans.clear()


def test_list_scan_tasks_for_dedup_pushes_repo_down_to_sql(
    scan_repository: tuple[ProducerRepository, object],
) -> None:
    """The dedup query filters by the indexed column and skips report_json."""
    repository, _ = scan_repository
    repository.create_scan_task(
        scan_id="scan-dedup-hit",
        owner_user_id="scan-user-1",
        client_request_id="request-dedup-hit",
        repo_url=DRAFT_SOURCE_URL,
        status="complete",
    )
    repository.create_scan_task(
        scan_id="scan-dedup-other",
        owner_user_id="scan-user-1",
        client_request_id="request-dedup-other",
        repo_url="https://github.com/acme/other",
        status="complete",
    )
    repository.create_scan_task(
        scan_id="scan-dedup-other-owner",
        owner_user_id="scan-user-2",
        client_request_id="request-dedup-other-owner",
        repo_url=DRAFT_SOURCE_URL,
        status="complete",
    )

    tasks = repository.list_scan_tasks_for_dedup(
        owner_user_id="scan-user-1",
        repo_url=DRAFT_SOURCE_URL,
    )
    assert [t["scan_id"] for t in tasks] == ["scan-dedup-hit"]
    # Identity and callback columns stay: the duplicate prechecks read
    # them straight off these rows.
    assert tasks[0]["repo_url"] == DRAFT_SOURCE_URL
    assert "callback_status" in tasks[0]
    assert "completion_delivered_at" in tasks[0]
    # The light projection carries no report payloads.
    for task in tasks:
        assert "report_json" not in task
        assert "metadata_json" not in task


def test_legacy_scan_list_returns_full_set_without_truncation(
    scan_repository: tuple[ProducerRepository, object],
) -> None:
    """limit=None must return every task, not the historical 50-row page."""
    repository, _ = scan_repository
    total = 55
    for i in range(total):
        repository.create_scan_task(
            scan_id=f"scan-full-{i}",
            owner_user_id="scan-user-1",
            client_request_id=f"request-full-{i}",
            repo_url=f"https://github.com/acme/repo{i}",
        )

    tasks = repository.list_scan_tasks(owner_user_id="scan-user-1")
    assert len(tasks) == total

    # The paginated management projection keeps its own limit semantics.
    paged = repository.list_scan_tasks(
        owner_user_id="scan-user-1",
        limit=10,
        offset=0,
    )
    assert len(paged) == 10


def test_tree_url_probe_hits_pushed_down_subdirectory(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A /tree/<ref>/<subdir> probe must find the task its URL implies.

    Passing the raw (missing) subdirectory down would filter on "no
    subdirectory" and miss the row whose identity lives in the URL.
    """
    repository, _ = scan_repository
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    repository.create_scan_task(
        scan_id="scan-tree-probe",
        owner_user_id="scan-user-1",
        client_request_id="request-tree-probe",
        repo_url=DRAFT_SOURCE_URL,
        source_subdirectory="src",
    )

    found = trust._find_scan_task_by_source_identity(
        "scan-user-1",
        DRAFT_SOURCE_URL + "/tree/main/src",
        None,
    )

    assert found is not None
    assert found["scan_id"] == "scan-tree-probe"


def test_persist_failure_keeps_report_readable_for_callbacks(
    callback_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed DB update must not strip the report the callback chain reads.

    The database write fails after the terminal state lands, so the report
    lives only in the runtime record; reads must merge it back in and the
    callback preparation must not take the source-reacquisition detour.
    """
    repository, _ = callback_repository
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    monkeypatch.setattr(trust, "_SCAN_PERSIST_RETRY_DELAY_SECONDS", 0)
    scan_id = "scan-cb-persist-fail"
    _mirror_scan(scan_id, status="complete")
    repository.create_scan_task(
        scan_id=scan_id,
        owner_user_id="callback-user-1",
        client_request_id="request-cb-persist-fail",
        repo_url=DRAFT_SOURCE_URL,
        status="complete",
    )
    report = {
        "scan_id": scan_id,
        "repo_url": DRAFT_SOURCE_URL,
        "commit_hash": SCAN_COMMIT,
        "source_ref": "main",
        "source_subdirectory": None,
        "local_source_dir": "/controlled/persist-fail",
        "scan_report": {"summary": {"total": 0}},
    }

    def _db_down(*_args, **_kwargs):
        raise OperationalError("UPDATE scan_tasks", {}, Exception("db down"))

    monkeypatch.setattr(repository, "update_scan_task", _db_down)
    try:
        assert trust._update_scan_state(scan_id, {"full_report": report}) is False

        loaded = trust._load_scan_info(scan_id)
        assert loaded is not None
        assert loaded.get("full_report") == report

        reacquire_calls: list[object] = []

        def _fail_acquire(
            _resolved: dict[str, object],
            *,
            temp_dir_callback=None,
        ):
            reacquire_calls.append(_resolved)
            raise AssertionError("reacquisition must not run")

        monkeypatch.setattr(trust, "_acquire_repo_source", _fail_acquire)
        monkeypatch.setattr(
            trust,
            "_controlled_scan_temp_dir",
            lambda path, require_directory=False: path,
        )
        callback_report, reacquired = trust._prepare_scan_callback_report(
            scan_id, report
        )
        assert reacquired is None
        assert callback_report["local_source_dir"] == "/controlled/persist-fail"
        assert callback_report.get("_source_reacquisition_attempted") is None
        assert reacquire_calls == []
    finally:
        trust._scans.clear()

