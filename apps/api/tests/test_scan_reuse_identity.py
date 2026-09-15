"""Reuse-identity contracts for completed scan tasks."""

from __future__ import annotations

from fastapi import BackgroundTasks

from src.dependencies import CurrentUser
from src.repositories.orm import PackageRow, PackageVersionRow
from src.repositories.producer_sqlalchemy import ProducerRepository
from src.routers import producer as producer_router
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
                id=DRAFT_VERSION_ID,
                package_id=DRAFT_PACKAGE_ID,
                version="1.0.0",
                status="draft",
                data={
                    "status": "draft",
                    "source": {
                        "repository_url": DRAFT_SOURCE_URL
                    },
                },
            )
        )
        session.commit()


def test_reuse_survives_new_upstream_commit(
    scan_repository: tuple[ProducerRepository, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reusing a completed scan must not fail when upstream moved HEAD."""
    repository, _ = scan_repository
    _create_draft_version(repository)
    scan_commit = "a" * 40
    repository.create_scan_task(
        scan_id="scan-reuse-stale",
        owner_user_id="scan-user-1",
        client_request_id="request-reuse-stale",
        repo_url=DRAFT_SOURCE_URL,
        source_ref="main",
        commit_hash=scan_commit,
        status="complete",
        callback_status="not_required",
    )
    report: dict[str, object] = {
        "scan_id": "scan-reuse-stale",
        "repo_url": DRAFT_SOURCE_URL,
        "source_ref": "main",
        "commit_hash": scan_commit,
        "source_subdirectory": None,
    }
    repository.update_scan_task(
        "scan-reuse-stale",
        {"report_json": report},
    )
    monkeypatch.setattr(
        producer_router,
        "_get_producer_repository",
        lambda: repository,
    )
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: repository)

    # The upstream repository has moved HEAD since the scan completed.  A
    # live GitHub lookup would resolve a brand-new commit and must not be
    # consulted for the reuse identity check.
    def _fail_if_called(_parsed: dict[str, object]) -> dict[str, object]:
        raise AssertionError("live GitHub lookup must not run on reuse")

    monkeypatch.setattr(
        trust,
        "_resolve_default_branch_source",
        _fail_if_called,
    )
    monkeypatch.setattr(trust, "_pin_resolved_source", _fail_if_called)

    response = producer_router.submit_version(
        DRAFT_VERSION_ID,
        BackgroundTasks(),
        body=producer_router.SubmitVersionRequest(
            initial_scan_id="scan-reuse-stale",
        ),
        _user=CurrentUser(id="scan-user-1", role="submitter"),
    )
    assert response.scan_id == "scan-reuse-stale"
    assert response.status == "scanning"
