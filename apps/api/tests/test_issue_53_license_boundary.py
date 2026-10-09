"""The API must scope nested-package license discovery to the acquired snapshot."""

import json

import pytest

from scanners.risk_scanner.dependency_parsers.osv_client import OSVClient
from scanners.risk_scanner.scanner import RiskScanner
from src.routers import trust
from src.services.source_snapshots import SourceSnapshotStore


@pytest.mark.parametrize("repository_has_license", [False, True])
def test_scan_task_uses_acquisition_root_for_license(tmp_path, monkeypatch, repository_has_license):
    # GitHub ZIP/API snapshots do not have a .git directory. The host workspace
    # may be licensed, but it is not part of the acquired repository.
    (tmp_path / "LICENSE").write_text("MIT License", encoding="utf-8")
    repository = tmp_path / "acquired"
    package = repository / "skills" / "demo"
    package.mkdir(parents=True)
    if repository_has_license:
        (repository / "LICENSE").write_text("MIT License", encoding="utf-8")
    (package / "manifest.json").write_text(
        json.dumps({
            "name": "demo", "version": "1.0.0", "type": "skill",
            "description": "A safe nested package", "author": "tester", "license": "",
        }),
        encoding="utf-8",
    )
    (package / "SKILL.md").write_text("# Demo\n", encoding="utf-8")

    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: None)
    monkeypatch.setattr(trust, "_load_scanner", lambda: RiskScanner)
    monkeypatch.setattr(
        trust, "_load_scorer",
        lambda: lambda **_kwargs: {"risk_summary": {"grade": "A"}},
    )
    monkeypatch.setattr(
        trust, "_acquire_repo_source", lambda _parsed: (str(repository), "zip", "a" * 40),
    )
    monkeypatch.setattr(trust, "_acquire_dependency_artifacts_for_scan", lambda *_args: None)
    monkeypatch.setattr(trust, "OSVClient", lambda **_kwargs: OSVClient(enabled=False))
    monkeypatch.setattr(
        trust, "_SOURCE_SNAPSHOT_STORE", SourceSnapshotStore(tmp_path / "snapshots"),
    )
    scan_id = "license-boundary-fixture"
    monkeypatch.setitem(trust._scans, scan_id, {"status": "pending", "error": None})

    trust._run_scan_task_body(
        scan_id,
        "https://github.com/acme/demo/tree/main/skills/demo",
        resolved_source={
            "owner": "acme", "repo": "demo", "base_url": "https://github.com/acme/demo",
            "ref": "main", "subdir": "skills/demo", "commit_hash": "a" * 40,
        },
    )

    assert trust._scans[scan_id]["status"] == "complete", trust._scans[scan_id].get("error")
    report = trust._scans[scan_id]["full_report"]["scan_report"]
    assert any(
        item["code"] == "metadata_incomplete" and "license" in item["description"]
        for item in report["review_advisories"]
    ) is (not repository_has_license)
