from pathlib import Path
from types import SimpleNamespace

from packages.schema.extract_skills import extract_single_skill
from scanners.risk_scanner import llm_reviewer
from scanners.risk_scanner.permission_consistency import (
    reconcile_permission_advisories,
)
from scanners.risk_scanner.redaction import build_finding_contexts
from scanners.risk_scanner.reporting import refresh_report_summaries
from scanners.risk_scanner.scanner import RiskScanner
from src.routers import trust


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _candidate() -> dict[str, object]:
    return {
        "id": "semantic-1",
        "rule_id": "SR-001",
        "severity": "info",
        "candidate_severity": "critical",
        "category": "prompt_injection",
        "title": "Prompt injection candidate",
        "location": {"file": "SKILL.md", "line": 8},
        "requires_llm_validation": True,
        "llm_review_state": "pending",
        "requires_manual_review": True,
    }


def _medium_candidate() -> dict[str, object]:
    candidate = _candidate()
    candidate["id"] = "semantic-medium"
    candidate["candidate_severity"] = "medium"
    return candidate


def _review(
    *,
    vulnerable: bool,
    harmful: bool,
    impact: str,
    intent: str,
    confidence: float = 0.95,
) -> dict[str, object]:
    return {
        "is_vulnerability": vulnerable,
        "harmful": harmful,
        "impact": impact,
        "context_role": "instruction" if vulnerable else "example",
        "intent": intent,
        "confidence": confidence,
        "explanation": "context checked",
    }


def test_two_independent_benign_reviews_resolve_without_arbitration(monkeypatch) -> None:
    calls: list[str] = []

    def fake_call(prompt: str) -> dict[str, object]:
        calls.append(prompt)
        return _review(
            vulnerable=False,
            harmful=False,
            impact="none",
            intent="benign",
        )

    monkeypatch.setattr(llm_reviewer, "_call_llm", fake_call)
    result = llm_reviewer.run_llm_review([_candidate()], {}, {})

    assert len(calls) == 2
    assert result["review_rounds"] == 2
    assert result["arbitrated"] == 0
    assert result["decisions"]["semantic-1"]["verdict"] == "likely_benign"


def test_explicit_medium_semantic_candidate_is_reviewed(monkeypatch) -> None:
    calls: list[str] = []

    def fake_call(prompt: str) -> dict[str, object]:
        calls.append(prompt)
        return _review(
            vulnerable=False,
            harmful=False,
            impact="none",
            intent="benign",
        )

    monkeypatch.setattr(llm_reviewer, "_call_llm", fake_call)
    result = llm_reviewer.run_llm_review([_medium_candidate()], {}, {})

    assert len(calls) == 2
    assert result["findings_reviewed"] == 1
    assert result["decisions"]["semantic-medium"]["verdict"] == "likely_benign"


def test_disagreement_uses_third_review_and_majority_verdict(monkeypatch) -> None:
    responses = [
        _review(vulnerable=True, harmful=True, impact="high", intent="malicious"),
        _review(vulnerable=False, harmful=False, impact="none", intent="benign"),
        _review(vulnerable=True, harmful=True, impact="high", intent="malicious"),
    ]
    calls: list[str] = []

    def fake_call(prompt: str) -> dict[str, object]:
        calls.append(prompt)
        return responses[len(calls) - 1]

    monkeypatch.setattr(llm_reviewer, "_call_llm", fake_call)
    result = llm_reviewer.run_llm_review([_candidate()], {}, {})

    assert len(calls) == 3
    assert result["review_rounds"] == 3
    assert result["arbitrated"] == 1
    assert result["decisions"]["semantic-1"]["verdict"] == "confirmed_harmful"
    assert result["labels"]["semantic-1"] == "llm:suspected-malicious"


def test_three_low_confidence_reviews_remain_manual(monkeypatch) -> None:
    monkeypatch.setattr(
        llm_reviewer,
        "_call_llm",
        lambda _prompt: _review(
            vulnerable=True,
            harmful=True,
            impact="high",
            intent="malicious",
            confidence=0.4,
        ),
    )

    result = llm_reviewer.run_llm_review([_candidate()], {}, {})

    assert result["review_rounds"] == 3
    assert result["decisions"]["semantic-1"]["verdict"] == "uncertain"
    assert result["findings_pending"] == 1


def test_internally_inconsistent_reviews_cannot_auto_clear_candidate(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        llm_reviewer,
        "_call_llm",
        lambda _prompt: _review(
            vulnerable=False,
            harmful=True,
            impact="high",
            intent="malicious",
        ),
    )

    result = llm_reviewer.run_llm_review([_candidate()], {}, {})

    assert result["review_rounds"] == 3
    assert result["decisions"]["semantic-1"]["verdict"] == "uncertain"
    assert result["labels"]["semantic-1"] == "llm:uncertain"


def test_real_world_mcp_builder_false_positive_is_removed_after_consensus(
    monkeypatch,
) -> None:
    root = PROJECT_ROOT / "examples" / "real-world" / "skills" / "mcp-builder"
    scanner = RiskScanner(root, source_commit_hash="a" * 40)
    # Keep this regression focused on semantic false positives. Real OSV
    # results are independently covered by supply-chain tests and can change
    # as new advisories are published.
    scanner.osv_client.query = lambda _dependency: SimpleNamespace(
        vulnerability_ids=[],
        error=None,
    )
    report = scanner.scan()
    metadata = extract_single_skill(
        root,
        repo_url="https://github.com/anthropics/skills",
        subdirectory="skills/mcp-builder",
    )
    reconcile_permission_advisories(
        report,
        metadata.get("permission_evidence", []),
    )
    candidates = [
        finding
        for finding in report["findings"]
        if finding.get("requires_llm_validation") is True
    ]
    assert candidates

    contexts = build_finding_contexts(report["findings"], scanner._file_contents)
    assert {
        str(finding["id"]) for finding in candidates
    }.issubset(contexts)

    prompts: list[str] = []

    def fake_call(prompt: str) -> dict[str, object]:
        prompts.append(prompt)
        return _review(
            vulnerable=False,
            harmful=False,
            impact="none",
            intent="benign",
        )

    monkeypatch.setattr(llm_reviewer, "_call_llm", fake_call)
    result = llm_reviewer.run_llm_review(
        report["findings"],
        contexts,
        {"name": "mcp-builder", "type": "skill"},
    )
    trust._apply_llm_decisions(report["findings"], result)
    refresh_report_summaries(report)

    assert len(prompts) == 2
    assert report["summary"]["effective_total"] == 0
    assert all(
        finding.get("requires_manual_review") is False
        for finding in candidates
    )

    acquisition_facts = {
        "source": {
            "type": "github",
            "repository_url": "https://github.com/anthropics/skills",
            "ref_type": "tag",
            "ref": "v1.0.0",
            "commit_hash": "a" * 40,
        },
        "integrity": {
            "sha256": scanner._content_tree_hash,
            "hash_scope": "scanned_source",
            "is_complete": True,
        },
        "verification": {
            "owner": True,
            "signature": False,
            "attestation": False,
            "sbom": False,
        },
    }
    score = trust._load_scorer()(
        package_metadata=metadata,
        scan_report=report,
        review_records={"status": "pending"},
        acquisition_facts=acquisition_facts,
    )

    assert score["risk_summary"]["grade"] not in {"D", "E"}
    assert score["score_breakdown"]["advisory_deduction"] == 6


def test_router_applies_benign_and_harmful_candidate_states() -> None:
    benign = _candidate()
    harmful = {**_candidate(), "id": "semantic-2"}
    result = {
        "labels": {
            "semantic-1": "llm:likely-benign",
            "semantic-2": "llm:suspected-malicious",
        },
        "decisions": {
            "semantic-1": {
                "verdict": "likely_benign",
                "impact": "none",
                "intent": "benign",
                "confidence": 0.96,
                "explanation": "test fixture",
                "rounds": 2,
            },
            "semantic-2": {
                "verdict": "confirmed_harmful",
                "impact": "critical",
                "intent": "malicious",
                "confidence": 0.94,
                "explanation": "test fixture",
                "rounds": 3,
            },
        },
    }

    trust._apply_llm_decisions([benign, harmful], result)

    assert benign["severity"] == "info"
    assert benign["requires_manual_review"] is False
    assert harmful["severity"] == "critical"
    assert harmful["requires_manual_review"] is False


def test_outer_failure_never_restores_candidate_high_severity(monkeypatch) -> None:
    finding = _candidate()

    def raise_offline() -> None:
        raise RuntimeError("offline")

    monkeypatch.setattr(trust, "_load_llm_reviewer", raise_offline)

    result = trust._run_llm_review_with_fallback(
        [finding],
        SimpleNamespace(_file_contents={}, _package_metadata={}),
    )

    assert result["fallback"] == "manual_review_required"
    assert finding["severity"] == "info"
    assert finding["llm_review_state"] == "unavailable"
    assert finding["requires_manual_review"] is True
