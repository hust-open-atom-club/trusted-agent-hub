"""Evidence coverage must survive the real scan task's phase gate and progress."""

from copy import deepcopy

import pytest

from scanners.risk_scanner import llm_reviewer
from scanners.risk_scanner.reporting import build_findings_summary
from scanners.risk_scanner.scanner import RiskScanner
from src.routers import trust
from src.services.source_snapshots import SourceSnapshotStore


@pytest.mark.parametrize(("location", "reason"), [
    ({}, "source_missing"),
    ({"file": "absent.json", "line": 3}, "source_missing"),
    ({"file": "SKILL.md"}, "location_unresolved"),
])
@pytest.mark.parametrize("mixed", [False, True])
def test_scan_phase_counts_all_semantic_candidates(
    tmp_path, monkeypatch, location, reason, mixed,
):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "SKILL.md").write_text(
        "---\nname: demo\ndescription: A safe evidence fixture\n---\n# Safe example\n",
        encoding="utf-8",
    )
    missing = {
        "id": "missing", "rule_id": "SR-001", "severity": "high",
        "category": "prompt_injection", "title": "Needs evidence",
        "description": "Fixture", "location": location,
        "requires_llm_validation": True,
    }
    findings = [missing]
    if mixed:
        findings.append({
            **missing, "id": "ready",
            "location": {"file": "SKILL.md", "line": 5},
        })

    class FixtureScanner(RiskScanner):
        def scan(self):
            report = super().scan()
            report["findings"] = deepcopy(findings)
            report["summary"] = build_findings_summary(report["findings"])
            return report

    calls = []

    def judge(prompt):
        calls.append(prompt)
        return {
            "is_vulnerability": False, "harmful": False, "impact": "none",
            "intent": "benign", "context_role": "example", "confidence": 0.99,
            "evidence_sufficient": True, "missing_context": [],
            "supporting_evidence": [{
                "file": "SKILL.md", "line": 5, "quote": "# Safe example",
            }],
            "explanation": "Verified delivered evidence",
        }

    monkeypatch.setattr(llm_reviewer, "_call_llm", judge)
    monkeypatch.setattr(trust, "_load_llm_reviewer", lambda: llm_reviewer)
    monkeypatch.setattr(trust, "_get_scan_task_repository", lambda: None)
    monkeypatch.setattr(trust, "_load_scanner", lambda: FixtureScanner)
    monkeypatch.setattr(
        trust, "_load_scorer",
        lambda: lambda **_kwargs: {"risk_summary": {"grade": "C"}},
    )
    monkeypatch.setattr(
        trust, "_acquire_repo_source", lambda _parsed: (str(repo), "git", "a" * 40),
    )
    monkeypatch.setattr(trust, "_acquire_dependency_artifacts_for_scan", lambda *_args: None)
    monkeypatch.setattr(
        trust, "_SOURCE_SNAPSHOT_STORE", SourceSnapshotStore(tmp_path / "snapshots"),
    )
    scan_id = "evidence-phase-fixture"
    monkeypatch.setitem(trust._scans, scan_id, {"status": "pending", "error": None})
    trust._run_scan_task_body(
        scan_id,
        "https://github.com/acme/evidence-fixture",
        resolved_source={
            "owner": "acme", "repo": "evidence-fixture",
            "base_url": "https://github.com/acme/evidence-fixture",
            "ref": "main", "subdir": None, "commit_hash": "a" * 40,
        },
    )

    assert trust._scans[scan_id]["status"] == "complete", trust._scans[scan_id].get("error")
    full_report = trust._scans[scan_id]["full_report"]
    report = full_report["scan_report"]
    review = report["llm_review"]
    progress = trust._scans[scan_id]["llm_review"]
    assert review["status"] != "not_required"
    assert review["findings_total"] == len(findings) == progress["findings_total"]
    assert review["findings_reviewed"] == int(mixed) == progress["findings_reviewed"]
    assert review["findings_pending"] == 1 == progress["findings_pending"]
    assert review["context_coverage"][reason] == 1
    assert len(calls) == (2 if mixed else 0)
    missing_result = next(f for f in report["findings"] if f["id"] == "missing")
    assert missing_result["requires_manual_review"] is True
    assert reason in missing_result["llm_context_reasons"]
    assert missing_result.get("llm_label") != "llm:likely-benign"
    if location.get("file"):
        assert review["context_coverage"]["top_finding_files"][location["file"]] >= 1
