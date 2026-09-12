"""Static benchmark resilience fixtures and their expected outcomes.

These cases deliberately stay outside the all-complete v2 corpus.  They verify
that a bounded or degraded scan is explicit, never silently scored as benign,
while a deterministic OSV no-result remains a complete benign control.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from scanners.risk_scanner.dependency_parsers.osv_client import OSVQueryResult
from scanners.risk_scanner.policy import ScanPolicy
from scanners.risk_scanner.scanner import RiskScanner


SOURCE_COMMIT = "a" * 40


def _write_skill(root: Path, *, license_value: str = "Apache-2.0") -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "manifest.json").write_text(
        json.dumps({
            "name": "resilience-fixture",
            "version": "1.0.0",
            "type": "skill",
            "description": "A self-contained static scanner resilience fixture.",
            "author": "benchmark",
            "license": license_value,
        }),
        encoding="utf-8",
    )
    (root / "SKILL.md").write_text("# Static resilience fixture\n", encoding="utf-8")


def _write_dependency_fixture(root: Path) -> None:
    _write_skill(root)
    (root / "package.json").write_text(
        json.dumps({
            "name": "resilience-fixture",
            "version": "1.0.0",
            "dependencies": {"alpha": "1.0.0", "beta": "1.0.0"},
        }),
        encoding="utf-8",
    )


def _finding() -> dict[str, object]:
    return {
        "id": "finding-1",
        "rule_id": "SR-001",
        "severity": "high",
        "effective_severity": "high",
        "category": "prompt_injection",
        "location": {"file": "SKILL.md", "line": 1},
        "description": "Static prompt-injection candidate",
        "evidence": "untrusted text",
    }


def test_malformed_metadata_is_reported_without_making_scan_incomplete(tmp_path: Path) -> None:
    _write_skill(tmp_path)
    (tmp_path / "manifest.json").write_text('{"name": "broken",', encoding="utf-8")

    scanner = RiskScanner(tmp_path, source_commit_hash=SOURCE_COMMIT)
    report = scanner.scan()

    assert report["metadata_validation"]["valid"] is False
    assert report["scan_status"]["state"] == "complete"
    assert report["rule_execution"]["failed"] == 0
    assert any(
        finding["rule_id"] == "SR-010"
        and "manifest.json" in finding["title"]
        for finding in report["findings"]
    )


def test_parent_files_do_not_supply_benchmark_fixture_metadata(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "LICENSE").write_text("Apache License", encoding="utf-8")
    (repository / "README.md").write_text("parent-only text", encoding="utf-8")
    fixture = repository / "packages" / "nested-skill"
    _write_skill(fixture, license_value="")

    report = RiskScanner(
        fixture,
        source_commit_hash=SOURCE_COMMIT,
        policy=ScanPolicy(allow_parent_license_files=False),
    ).scan()

    assert report["scan_status"]["state"] == "complete"
    assert report["metadata_validation"]["valid"] is False
    assert any(
        item["field"] == "license"
        for item in report["metadata_validation"]["errors"]
    )
    assert any(
        "license" in item["description"].lower()
        and item["code"] == "metadata_incomplete"
        for item in report["review_advisories"]
    )
    assert all(
        not path.startswith("../")
        for path in report["scan_limits"]["skipped"]["samples"]
    )


def test_external_symlink_is_not_followed_and_is_reported_as_integrity_risk(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "fixture"
    outside = tmp_path / "outside.txt"
    _write_skill(fixture)
    outside.write_text("outside secret", encoding="utf-8")
    link = fixture / "linked.txt"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    report = RiskScanner(fixture, source_commit_hash=SOURCE_COMMIT).scan()

    assert report["scan_status"]["state"] == "partial"
    assert "symlink_outside_root" in report["scan_status"]["reasons"]
    assert "outside secret" not in json.dumps(report["structural_analysis"])
    assert any(
        finding["rule_id"] == "SR-009"
        and finding["location"].get("file") == "linked.txt"
        for finding in report["findings"]
    )


def test_large_file_and_directory_are_inconclusive(tmp_path: Path) -> None:
    large_file_root = tmp_path / "large-file"
    _write_skill(large_file_root)
    (large_file_root / "README.md").write_text("x" * 512, encoding="utf-8")
    large_file_report = RiskScanner(
        large_file_root,
        source_commit_hash=SOURCE_COMMIT,
        policy=ScanPolicy(max_file_bytes=256),
    ).scan()

    large_directory_root = tmp_path / "large-directory"
    _write_skill(large_directory_root)
    for index in range(3):
        (large_directory_root / f"extra-{index}.txt").write_text("x", encoding="utf-8")
    large_directory_report = RiskScanner(
        large_directory_root,
        source_commit_hash=SOURCE_COMMIT,
        policy=ScanPolicy(max_files=3),
    ).scan()

    assert large_file_report["scan_status"]["conclusion"] == "inconclusive"
    assert "max_file_bytes" in large_file_report["scan_limits"]["exceeded"]
    assert large_directory_report["scan_status"]["conclusion"] == "inconclusive"
    assert "max_files" in large_directory_report["scan_limits"]["exceeded"]


def test_rule_exception_is_partial_and_quality_gate_input(tmp_path: Path, monkeypatch) -> None:
    _write_skill(tmp_path)
    from scanners.risk_scanner import rule_runner

    real_import = rule_runner.importlib.import_module

    def fake_import(name: str):
        if name.endswith(".prompt_injection"):
            def broken(_scanner: object) -> None:
                raise RuntimeError("synthetic rule fixture failure")

            return SimpleNamespace(run=broken)
        return real_import(name)

    monkeypatch.setattr(rule_runner.importlib, "import_module", fake_import)
    report = RiskScanner(tmp_path, source_commit_hash=SOURCE_COMMIT).scan()

    assert report["scan_status"]["state"] == "partial"
    assert "rule_execution_errors" in report["scan_status"]["reasons"]
    assert report["rule_execution"]["failed"] == 1
    assert any(error["rule_id"] == "SR-001" for error in report["scanner_errors"])


def test_osv_no_result_is_complete_but_failure_and_limit_are_partial(tmp_path: Path) -> None:
    class NoResultClient:
        max_queries = 10

        def __init__(self) -> None:
            self.queried = 0

        def query(self, _dependency: object) -> OSVQueryResult:
            self.queried += 1
            return OSVQueryResult([], None)

    class FailedClient(NoResultClient):
        def query(self, _dependency: object) -> OSVQueryResult:
            self.queried += 1
            return OSVQueryResult([], "TimeoutError")

    class LimitedClient(NoResultClient):
        max_queries = 1

        def query(self, _dependency: object) -> OSVQueryResult:
            if self.queried >= self.max_queries:
                return OSVQueryResult([], "query_limit_exceeded")
            self.queried += 1
            return OSVQueryResult([], None)

    reports: list[dict[str, object]] = []
    for client in (NoResultClient(), FailedClient(), LimitedClient()):
        fixture = tmp_path / client.__class__.__name__
        _write_dependency_fixture(fixture)
        scanner = RiskScanner(fixture, source_commit_hash=SOURCE_COMMIT)
        scanner.osv_client = client
        reports.append(scanner.scan())

    no_result, failed, limited = reports
    assert no_result["dependency_scan"]["status"] == "complete"
    assert no_result["scan_status"]["state"] == "complete"
    assert failed["dependency_scan"]["status"] == "partial"
    assert failed["scan_status"]["state"] == "partial"
    assert limited["dependency_scan"]["status"] == "partial"
    assert limited["dependency_scan"]["query_limit"] == 1
    assert limited["scan_status"]["state"] == "partial"


def test_llm_unavailable_and_timeout_use_deterministic_manual_fallback(monkeypatch) -> None:
    from scanners.risk_scanner import llm_reviewer

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(llm_reviewer, "_call_llm", llm_reviewer._NETWORK_CALL_LLM)
    not_configured = llm_reviewer.run_llm_review(
        [_finding()],
        {"finding-1": "1: untrusted text"},
        {"name": "resilience-fixture"},
    )

    assert not_configured["status"] == "not_configured"
    assert not_configured["fallback"] == "manual_review_required"
    assert not_configured["findings_pending"] == 1

    def injected(_prompt: str) -> dict[str, object]:
        return {}

    monkeypatch.setattr(llm_reviewer, "_call_llm", injected)
    timed_out = llm_reviewer.run_llm_review(
        [_finding()],
        {"finding-1": "1: untrusted text"},
        {"name": "resilience-fixture"},
        deadline_monotonic=time.monotonic() - 1,
    )

    assert timed_out["status"] == "timeout"
    assert timed_out["fallback"] == "manual_review_for_unresolved"
    assert timed_out["labels"]["finding-1"] == "llm:unavailable"
