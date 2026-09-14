"""Conflict-detail contracts for duplicate-source scan requests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import BackgroundTasks, HTTPException

from src.dependencies import CurrentUser
from src.repositories.producer_sqlalchemy import ProducerRepository
from src.routers import producer as producer_router
from src.routers import trust
from tests.test_scan_task_persistence import (
    DRAFT_VERSION_ID,
    _create_draft_version,
    scan_repository,
)


def _seed_conflict_task(
    repository: ProducerRepository,
    *,
    scan_id: str,
    client_request_id: str,
    status: str,
    callback_status: str,
    repo_url: str = "https://github.com/acme/demo",
    version_id: str | None = DRAFT_VERSION_ID,
) -> None:
    """Create a settled duplicate-source task for conflict-detail tests."""
    if version_id is not None:
        # The submitted_reviewing lifecycle requires a version reference,
        # and scan_tasks.version_id is a foreign key.
        _create_draft_version(repository)
    repository.create_scan_task(
        scan_id=scan_id,
        owner_user_id="scan-user-1",
        client_request_id=client_request_id,
        repo_url=repo_url,
        status=status,
        callback_status=callback_status,
        version_id=version_id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )


def test_scan_conflict_detail_marks_deletable_lifetimes(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every delete-allowed lifecycle gets a delete-first 409 message."""
    repository, _ = scan_repository
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)

    for scan_id, repo_url, status, callback in (
        (
            "scan-conflict-error",
            "https://github.com/acme/errored",
            "error",
            "delivered",
        ),
        (
            "scan-conflict-complete",
            "https://github.com/acme/standalone",
            "complete",
            "not_required",
        ),
        (
            "scan-conflict-submitted",
            "https://github.com/acme/submitted",
            "complete",
            "delivered",
        ),
    ):
        _seed_conflict_task(
            repository,
            scan_id=scan_id,
            client_request_id=f"request-{scan_id}",
            repo_url=repo_url,
            status=status,
            callback_status=callback,
        )
        task = repository.get_scan_task(scan_id)
        assert task is not None
        detail = trust.scan_conflict_detail(trust._scan_info_from_task(task))
        assert detail["conflict_scan_id"] == scan_id
        assert detail["delete_allowed"] is True
        assert "请先删除任务" in detail["message"]
        assert scan_id in detail["message"]


def test_scan_conflict_detail_blocks_active_lifetimes(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Active or callback-pending lifetimes keep the plain conflict message."""
    repository, _ = scan_repository
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)

    _seed_conflict_task(
        repository,
        scan_id="scan-conflict-scanning",
        client_request_id="request-conflict-scanning",
        status="scanning",
        callback_status="not_required",
    )
    task = repository.get_scan_task("scan-conflict-scanning")
    assert task is not None
    detail = trust.scan_conflict_detail(trust._scan_info_from_task(task))
    assert detail["delete_allowed"] is False
    assert "请先删除任务" not in detail["message"]
    assert "不允许重复扫描" in detail["message"]


def test_submit_scan_conflict_returns_structured_delete_allowed_detail(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """POST /scan surfaces a structured 409 for a deletable old task."""
    repository, _ = scan_repository
    _seed_conflict_task(
        repository,
        scan_id="scan-conflict-submitted",
        client_request_id="request-conflict-submitted",
        status="complete",
        callback_status="delivered",
    )
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)
    trust._scans.clear()

    with pytest.raises(HTTPException) as raised:
        trust.submit_scan(
            BackgroundTasks(),
            repo_url="https://github.com/acme/demo",
            idempotency_key="conflict-structured-new",
            _user=SimpleNamespace(id="scan-user-1", role="submitter"),
        )
    assert raised.value.status_code == 409
    detail = raised.value.detail
    assert isinstance(detail, dict)
    assert detail["conflict_scan_id"] == "scan-conflict-submitted"
    assert detail["delete_allowed"] is True
    assert detail["lifecycle"] == "submitted_reviewing"
    assert "请先删除任务" in detail["message"]


def test_delete_conflicted_task_then_rescan_succeeds(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The delete-then-retry loop closes: 409 → DELETE → POST succeeds."""
    repository, _ = scan_repository
    _seed_conflict_task(
        repository,
        scan_id="scan-conflict-loop",
        client_request_id="request-conflict-loop",
        status="complete",
        callback_status="delivered",
    )
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
        lambda _parsed: "c" * 40,
    )
    trust._scans.clear()
    requester = SimpleNamespace(id="scan-user-1", role="submitter")

    with pytest.raises(HTTPException) as raised:
        trust.submit_scan(
            BackgroundTasks(),
            repo_url="https://github.com/acme/demo",
            idempotency_key="conflict-loop-first",
            _user=requester,
        )
    detail = raised.value.detail
    assert isinstance(detail, dict) and detail["delete_allowed"] is True

    trust.delete_scan_task(
        detail["conflict_scan_id"],
        _user=CurrentUser(id="scan-user-1", role="submitter"),
    )

    retry = trust.submit_scan(
        BackgroundTasks(),
        repo_url="https://github.com/acme/demo",
        idempotency_key="conflict-loop-second",
        _user=requester,
    )
    assert retry["status"] == "pending"
    assert retry["scan_id"] != detail["conflict_scan_id"]


def test_submit_version_conflict_returns_structured_delete_allowed_detail(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """submit_version surfaces the same structured 409 for old tasks."""
    repository, _ = scan_repository
    _create_draft_version(repository)
    _seed_conflict_task(
        repository,
        scan_id="scan-conflict-producer",
        client_request_id="request-conflict-producer",
        status="complete",
        callback_status="delivered",
    )
    monkeypatch.setattr(
        producer_router,
        "_get_producer_repository",
        lambda: repository,
    )
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
        "_pin_resolved_source",
        lambda parsed: {**parsed, "commit_hash": "d" * 40},
    )

    with pytest.raises(HTTPException) as raised:
        producer_router.submit_version(
            DRAFT_VERSION_ID,
            BackgroundTasks(),
            _user=CurrentUser(id="scan-user-1", role="submitter"),
        )
    assert raised.value.status_code == 409
    detail = raised.value.detail
    assert isinstance(detail, dict)
    assert detail["conflict_scan_id"] == "scan-conflict-producer"
    assert detail["delete_allowed"] is True
    assert detail["lifecycle"] == "submitted_reviewing"
