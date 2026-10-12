"""Review lifecycle regressions against isolated relational persistence."""

from copy import deepcopy

import pytest
from sqlalchemy import event

from src.database import Base, create_engine_from_url, create_session_factory
from src.repositories.orm import PackageRow, PackageVersionRow
from src.repositories.orm_producer import UserRow
from src.repositories.producer_sqlalchemy import ProducerRepository
from src.services.producer import ProducerService, ProducerServiceError


@pytest.fixture
def repository():
    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    with factory() as session:
        session.add(UserRow(
            id="submitter", email="submitter@example.com", password_hash="unused",
            role="submitter", display_name="Submitter",
        ))
        session.commit()
    yield ProducerRepository(factory)
    engine.dispose()


def _version(repository, *, number="1.0.0", package_id=None, status="published"):
    if package_id is None:
        package_id = repository.create_package(
            name="lifecycle-demo", type="skill", description="Review lifecycle",
            submitter_id="submitter",
        )["id"]
    version = repository.create_version(
        package_id=package_id, version=number, submitter_id="submitter",
        repo_url="https://github.com/acme/demo",
    )
    repository.update_version_status(version["id"], status)
    repository.update_version_data(version["id"], {
        "review_conclusion": "approved", "published_at": "2026-10-11T16:45:18+00:00",
        "yank_reason": "old reason",
    })
    repository.create_review_record(
        version_id=version["id"], reviewer_id="reviewer", conclusion="approved",
    )
    if status == "published":
        repository.update_package_status(package_id, "published", latest_version=number)
    return repository.get_version(version["id"])


def test_re_review_clears_current_conclusion_and_withdraws_latest_package(repository):
    version = _version(repository)
    before_reviews = repository.list_review_records(version["id"])
    untouched = repository.create_package(
        name="unrelated", type="skill", description="Unrelated package",
    )

    result = ProducerService(repository).re_review_version(
        version_id=version["id"], operator_id="admin",
    )

    assert result.new_status == "pending_review"
    current = repository.get_version(version["id"])
    assert current["status"] == "pending_review"
    assert current.get("review_conclusion") is None
    assert current.get("yank_reason") is None
    assert current["published_at"] == version["published_at"]
    assert repository.list_review_records(version["id"]) == before_reviews
    assert repository.get_package(untouched["id"])["status"] == "draft"
    with repository.session_factory() as session:
        row = session.get(PackageVersionRow, version["id"])
        package = session.get(PackageRow, version["package_id"])
        assert row.status == row.data["status"] == "pending_review"
        assert package.status == package.data["status"] == "pending_review"
        assert package.latest_version == package.data["latest_version"] == "1.0.0"
    queue = repository.list_versions_by_status(status="pending_review")
    assert [item["version_id"] for item in queue] == [version["id"]]
    logs = repository.list_audit_logs(target_id=version["id"], action="re_review")
    assert len(logs) == 1
    assert logs[0]["operator_id"] == "admin"
    with pytest.raises(ProducerServiceError):
        ProducerService(repository).re_review_version(version_id=version["id"])
    assert len(repository.list_audit_logs(action="re_review")) == 1


def test_re_review_of_older_version_preserves_other_published_latest(repository):
    older = _version(repository)
    latest = _version(repository, number="2.0.0", package_id=older["package_id"])
    package_before = repository.get_package(older["package_id"])

    ProducerService(repository).re_review_version(version_id=older["id"])

    assert repository.get_package(older["package_id"]) == package_before
    assert repository.get_version(latest["id"]) == latest
    assert repository.get_version(older["id"]).get("review_conclusion") is None


def test_re_review_does_not_automatically_promote_an_older_release(repository):
    older = _version(repository)
    latest = _version(repository, number="2.0.0", package_id=older["package_id"])

    ProducerService(repository).re_review_version(version_id=latest["id"])

    package = repository.get_package(older["package_id"])
    assert package["status"] == "pending_review"
    assert package["latest_version"] == "2.0.0"
    assert repository.get_version(older["id"]) == older


def test_re_review_rolls_back_version_package_and_audit_together(repository):
    version = _version(repository)
    package_before = repository.get_package(version["package_id"])
    engine = repository.session_factory.kw["bind"]

    def fail_audit(_conn, _cursor, statement, _parameters, _context, _many):
        if statement.startswith("INSERT INTO audit_logs"):
            raise RuntimeError("audit storage unavailable")

    event.listen(engine, "before_cursor_execute", fail_audit)
    try:
        with pytest.raises(RuntimeError, match="audit storage unavailable"):
            ProducerService(repository).re_review_version(version_id=version["id"])
    finally:
        event.remove(engine, "before_cursor_execute", fail_audit)

    assert repository.get_version(version["id"]) == version
    assert repository.get_package(version["package_id"]) == package_before
    assert repository.list_audit_logs(action="re_review") == []


def test_re_review_rechecks_relational_status_before_writing(repository, monkeypatch):
    version = _version(repository)
    repository.update_version_status(version["id"], "yanked")
    monkeypatch.setattr(repository, "get_version", lambda _id: deepcopy(version))

    with pytest.raises(ProducerServiceError):
        ProducerService(repository).re_review_version(version_id=version["id"])

    with repository.session_factory() as session:
        row = session.get(PackageVersionRow, version["id"])
        assert row.status == row.data["status"] == "yanked"
    assert repository.list_audit_logs(action="re_review") == []


def test_reopened_version_requires_new_approval_before_publication(repository, monkeypatch):
    version = _version(repository)
    service = ProducerService(repository)
    service.re_review_version(version_id=version["id"])
    with pytest.raises(ProducerServiceError):
        service.publish_version(version_id=version["id"])

    service.review_version(version_id=version["id"], conclusion="approved")
    assert repository.get_version(version["id"])["review_conclusion"] == "approved"
    assert repository.get_package(version["package_id"])["status"] == "pending_review"
    assert len(repository.list_review_records(version["id"])) == 2

    # Artifact readiness and score calculation have their own tests; exercise
    # the real publication writes without downloading or constructing an archive.
    monkeypatch.setattr("src.services.producer._validate_install_readiness", lambda *_: [])
    monkeypatch.setattr("src.services.trust_refresh.TrustScoreRefreshService.refresh", lambda *_: None)
    service.publish_version(version_id=version["id"])

    with repository.session_factory() as session:
        row = session.get(PackageVersionRow, version["id"])
        package = session.get(PackageRow, version["package_id"])
        assert row.status == row.data["status"] == "published"
        assert package.status == package.data["status"] == "published"


@pytest.mark.parametrize("reuse", [False, True])
def test_resubmission_clears_current_conclusion_but_keeps_review_history(repository, reuse):
    version = _version(repository, status="changes_requested")
    repository.update_version_data(version["id"], {"review_conclusion": "changes_requested"})
    history = repository.list_review_records(version["id"])
    task = {
        "owner_user_id": "submitter", "source_ref": "main", "commit_hash": "a" * 40,
    }
    if reuse:
        repository.create_scan_task(
            scan_id="scan-reused", owner_user_id="submitter", client_request_id="reuse",
            repo_url="https://github.com/acme/demo", status="complete",
        )
        repository.update_scan_task(
            "scan-reused", {"report_json": {"scan_report": {"findings": []}}},
        )
        task["existing_scan_id"] = "scan-reused"

    ProducerService(repository).submit_version(
        version["id"], user_id="submitter", scan_task=task,
    )

    current = repository.get_version(version["id"])
    assert current["status"] == "scanning"
    assert current.get("review_conclusion") is None
    assert repository.list_review_records(version["id"]) == history


@pytest.mark.parametrize("status", [
    "pending_review", "approved", "published", "yanked", "rejected", "changes_requested",
    "resubmitted",
])
def test_completed_scan_replay_cannot_undo_later_review_state(repository, status, monkeypatch):
    def unexpected_build(**_kwargs):
        pytest.fail("A completed scan replay must not rebuild artifacts")

    monkeypatch.setattr("src.services.artifacts.build_artifact", unexpected_build)
    version = _version(repository, status=status)
    scan_id = "scan-already-completed"
    repository.save_scan_report(
        version_id=version["id"], scan_json={"scan_id": scan_id, "findings": []},
    )
    repository.create_audit_log(
        action="scan_complete", target_type="version", target_id=version["id"],
        operator_id="system", detail={"scan_id": scan_id},
        idempotency_key=f"scan-complete:{scan_id}",
    )
    before_report = repository.get_scan_report(version["id"])
    package_before = repository.get_package(version["package_id"])

    # Deliberately different metadata proves a replay does not reapply the scan.
    assert ProducerService(repository).handle_scan_complete(version["id"], {
        "scan_id": scan_id, "scan_report": {"findings": [{"id": "replayed"}]},
        "trust_score": {"score": 99},
    }) is True

    assert repository.get_version(version["id"]) == version
    assert repository.get_package(version["package_id"]) == package_before
    assert repository.get_scan_report(version["id"]) == before_report
    assert len(repository.list_audit_logs(action="scan_complete")) == 1
