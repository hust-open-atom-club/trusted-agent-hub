from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from benchmarks.runner import (
    BenchmarkConfigError,
    _actual_root_issues,
    _benchmark_check_failures,
    _evaluate_case,
    _evaluate_v2_case,
    _OfflineOSVClient,
    _validate_v2_config,
    _with_rates,
    run_benchmark,
)


ROOT = Path(__file__).resolve().parents[3]
V2_CONFIG = ROOT / "benchmarks" / "labels-v2.json"
LEGACY_CONFIG = ROOT / "benchmarks" / "expected-results.json"


def _v2_result(*, enforcement: str, differences: list[dict] | None = None) -> dict:
    return {
        "schema_version": "2.0",
        "cases": [
            {
                "id": "case-one",
                "enforcement": enforcement,
                "differences": differences or [],
            }
        ],
        "coverage": {"incomplete_scan_ratio": 0, "rule_exception_ratio": 0},
        "integrity": {"content_hash_mismatches": 0},
    }


def test_benchmark_check_rejects_regressions_and_incomplete_scans():
    failures = _benchmark_check_failures({
        "overall": {"fp": 1, "fn": 2},
        "coverage": {"incomplete_scan_ratio": 0.5, "rule_exception_ratio": 0.25},
    })

    assert failures == [
        "unexpected rule findings (fp=1)",
        "missing expected rule findings (fn=2)",
        "benchmark contains incomplete scans",
        "benchmark contains rule execution failures",
    ]


def test_benchmark_check_accepts_clean_legacy_result():
    assert _benchmark_check_failures({
        "overall": {"fp": 0, "fn": 0},
        "coverage": {"incomplete_scan_ratio": 0, "rule_exception_ratio": 0},
    }) == []


def test_v2_blocking_mismatch_fails_but_observe_mismatch_does_not():
    difference = [{"field": "raw_rules", "expected": [], "actual": ["SR-005"]}]

    assert _benchmark_check_failures(
        _v2_result(enforcement="blocking", differences=difference)
    ) == ["blocking case case-one differs: raw_rules"]
    assert _benchmark_check_failures(
        _v2_result(enforcement="observe", differences=difference)
    ) == []


def test_v2_incomplete_scans_rule_errors_and_fixture_drift_always_fail():
    result = _v2_result(enforcement="observe")
    result["coverage"] = {
        "incomplete_scan_ratio": 0.25,
        "rule_exception_ratio": 0.1,
    }
    result["integrity"] = {"content_hash_mismatches": 1}

    assert _benchmark_check_failures(result) == [
        "benchmark fixture content hash mismatch",
        "benchmark contains incomplete scans",
        "benchmark contains rule execution failures",
    ]


def test_v2_quality_gates_fail_on_aggregate_metric_regression():
    result = _v2_result(enforcement="blocking")
    result["quality_gates"] = {"minimum_raw_precision": 0.95}
    result["metrics"] = {
        "raw_rules": {"overall": {"precision": 0.9, "recall": 1.0}},
    }

    assert _benchmark_check_failures(result) == [
        "raw rule precision outside quality gate (actual=0.9000, minimum=0.9500)"
    ]


def test_v2_quality_gates_prevent_silently_shrinking_the_corpus():
    result = _v2_result(enforcement="blocking")
    result["quality_gates"] = {"minimum_cases": 2}
    result["corpus"] = {
        "case_count": 1,
        "ground_truth_distribution": {},
    }

    assert _benchmark_check_failures(result) == [
        "case count below quality gate (actual=1, minimum=2)"
    ]


def test_v2_schema_rejects_invalid_case_and_unexplained_observe():
    config = json.loads(V2_CONFIG.read_text(encoding="utf-8"))
    invalid_case = deepcopy(config)
    invalid_case["cases"][0].pop("ground_truth")
    with pytest.raises(BenchmarkConfigError, match="ground_truth"):
        _validate_v2_config(invalid_case, V2_CONFIG)

    unexplained = deepcopy(config)
    observed = unexplained["cases"][0]
    observed["enforcement"] = "observe"
    observed.pop("known_gap", None)
    with pytest.raises(BenchmarkConfigError, match="known_gap"):
        _validate_v2_config(unexplained, V2_CONFIG)


def test_legacy_finding_fallbacks_are_explicit_and_stable():
    roots = _actual_root_issues([
        {
            "id": "random-a",
            "rule_id": "SR-003",
            "severity": "high",
            "location": {"file": "a.py", "line": 1},
            "title": "credential read",
        },
        {
            "id": "random-b",
            "rule_id": "SR-003",
            "severity": "medium",
            "effective_severity": "low",
            "location": {"file": "b.py", "line": 2},
            "title": "credential read",
        },
    ])

    assert [root["id"] for root in roots] == ["legacy-root-001", "legacy-root-002"]
    assert all(root["id_source"] == "finding_id_fallback" for root in roots)
    assert roots[0]["effective_severity"] == "high"
    assert roots[1]["effective_severity"] == "low"
    assert roots[0]["kinds"] == ["legacy_unknown"]
    assert roots[0]["dispositions"] == ["legacy_unknown"]


def test_v2_root_matching_and_metric_calculation():
    case = {
        "id": "download-execute",
        "path": "corpus/malicious-code/download-then-execute",
        "ground_truth": "malicious",
        "content_tree_sha256": "a" * 64,
        "enforcement": "blocking",
        "expected_target": {
            "raw_rules": ["SR-002", "SR-008"],
            "root_issues": [
                {
                    "id": "remote-script",
                    "rule_ids": ["SR-002", "SR-008"],
                    "kind": "vulnerability",
                    "disposition": "confirmed_vulnerability",
                    "effective_severity": "critical",
                }
            ],
            "forbidden_effective_severities": [],
            "capabilities": ["shell"],
            "security_grade": ["D"],
            "manual_review": "not_required",
        },
    }
    report = {
        "findings": [
            {
                "id": "one",
                "root_cause_id": "remote-script",
                "rule_id": "SR-002",
                "detector_ids": ["SR-002", "SR-008"],
                "severity": "critical",
                "kind": "vulnerability",
                "disposition": "confirmed_vulnerability",
                "location": {"file": "install.sh", "line": 1},
            },
        ],
        "structural_analysis": {
            "capability_graph": {"declared": [], "observed": ["shell"]}
        },
        "scan_status": {"state": "complete", "conclusion": "risks_found"},
        "rule_execution": {"total": 21, "failed": 0},
    }

    case_result, evaluation = _evaluate_v2_case(
        case,
        report,
        grade="D",
        manual_review="not_required",
        content_hash="a" * 64,
    )
    assert case_result["differences"] == []
    assert evaluation["root_tp"] == 1
    assert evaluation["root_fp"] == 0
    assert evaluation["root_fn"] == 0

    raw: dict[str, dict[str, int]] = {}
    _evaluate_case({"SR-002", "SR-008"}, {"SR-002", "SR-009"}, raw)
    overall = {
        key: sum(metric[key] for metric in raw.values())
        for key in ("tp", "fp", "fn")
    }
    assert _with_rates(overall) == {
        "tp": 1,
        "fp": 1,
        "fn": 1,
        "precision": 0.5,
        "recall": 0.5,
    }


def test_osv_fixture_never_uses_the_network(monkeypatch):
    def fail_network(*_args, **_kwargs):
        raise AssertionError("benchmark attempted a network request")

    monkeypatch.setattr("urllib.request.urlopen", fail_network)
    client = _OfflineOSVClient(max_queries=10)
    result = client.query(object())

    assert result.vulnerability_ids == []
    assert result.error is None
    assert client.queried == 1
    assert client.failures == 0


def test_v2_corpus_is_complete_checkable_and_deterministic():
    first = run_benchmark(V2_CONFIG)
    second = run_benchmark(V2_CONFIG)

    assert first["corpus"] == {
        "case_count": 25,
        "ground_truth_distribution": {
            "benign": 3,
            "benign_capability": 9,
            "malicious": 9,
            "needs_context": 4,
        },
        "enforcement_distribution": {"blocking": 25, "observe": 0},
    }
    assert first["coverage"]["complete_scan_ratio"] == 1.0
    assert first["coverage"]["rule_exception_ratio"] == 0.0
    assert first["integrity"] == {
        "content_hash_mismatches": 0,
        "offline_osv": True,
        "llm_mode": "not_invoked",
    }
    assert _benchmark_check_failures(first) == []
    assert first["quality_gates"] == {
        "minimum_cases": 25,
        "minimum_benign_cases": 12,
        "minimum_malicious_cases": 9,
        "minimum_raw_precision": 0.95,
        "minimum_raw_recall": 0.95,
        "minimum_root_precision": 0.95,
        "minimum_root_recall": 0.95,
        "maximum_benign_high_critical_false_positive_rate": 0.05,
        "minimum_malicious_high_critical_recall": 0.9,
    }
    assert all(
        case.get("known_gap", {}).get("planned_pr")
        for case in first["cases"]
        if case["enforcement"] == "observe"
    )
    assert sum(first["metrics"]["grade_distribution"].values()) == 25
    assert "severity_confusion_matrix" in first["metrics"]
    assert first["security_fingerprint"] == second["security_fingerprint"]


def test_legacy_config_remains_supported():
    result = run_benchmark(LEGACY_CONFIG)

    assert result["schema_version"] == "1.0"
    assert result["overall"] == {
        "tp": 5,
        "fp": 0,
        "fn": 0,
        "precision": 1.0,
        "recall": 1.0,
    }
    assert _benchmark_check_failures(result) == []
