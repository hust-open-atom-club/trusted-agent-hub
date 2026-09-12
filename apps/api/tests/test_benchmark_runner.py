from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from benchmarks.runner import (
    BenchmarkConfigError,
    _actual_root_issues,
    _benchmark_check_failures,
    _compute_rule_coverage,
    _evaluate_case,
    _evaluate_v2_case,
    _content_tree_hash,
    _OfflineOSVClient,
    _scan_target,
    _tree_fingerprint,
    _validate_v2_config,
    _with_rates,
    run_benchmark,
)
from scanners.risk_scanner.policy import ScanPolicy


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


def test_v2_coverage_gate_rejects_untested_rules_and_variants():
    result = _v2_result(enforcement="blocking")
    result["quality_gates"] = {
        "require_complete_rule_coverage": True,
        "require_independent_variants": True,
    }
    result["coverage"]["rule_coverage"] = {
        "untested_rules": ["SR-001"],
        "incomplete_rules": ["SR-002"],
        "rules": [{"rule_id": "SR-003", "false_positive": 1, "false_negative": 2}],
        "independent_variants": [{"rule_id": "SR-005b", "status": "failed"}],
    }

    assert _benchmark_check_failures(result) == [
        "missing rule coverage rows: SR-001, SR-002, SR-004, SR-005, SR-005b, SR-006, SR-007, SR-008, SR-009, SR-010, SR-011, SR-012, SR-013, SR-014, SR-015, SR-016, SR-017, SR-018, SR-019, SR-020",
        "untested rules: SR-001",
        "incomplete rules: SR-002",
        "rule coverage mismatches: SR-003 (fp=1, fn=2)",
        "independent detector variants failed: SR-005b",
    ]


def test_independent_variant_gate_requires_rule_coverage_report():
    result = _v2_result(enforcement="blocking")
    result["quality_gates"] = {"require_independent_variants": True}

    assert _benchmark_check_failures(result) == [
        "missing rule coverage report",
    ]


def test_independent_variant_gate_requires_coverage_config():
    config = json.loads(V2_CONFIG.read_text(encoding="utf-8"))
    config["quality_gates"]["require_complete_rule_coverage"] = False
    config["quality_gates"]["require_independent_variants"] = True
    config["coverage_config"] = "missing-coverage.json"

    with pytest.raises(BenchmarkConfigError, match="required rule coverage config"):
        _validate_v2_config(config, V2_CONFIG)


def test_rule_coverage_does_not_report_perfect_metrics_without_cases():
    coverage = _compute_rule_coverage({"rules": {}}, {})

    assert coverage is not None
    assert coverage["registry_count"] == 21
    assert coverage["family_count"] == 20
    first_rule = coverage["rules"][0]
    assert first_rule["positive_case_count"] == 0
    assert first_rule["negative_case_count"] == 0
    assert first_rule["precision"] is None
    assert first_rule["recall"] is None
    assert first_rule["coverage_status"] == "untested"


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


def test_v2_fixture_revision_must_contain_the_labeled_corpus():
    config = json.loads(V2_CONFIG.read_text(encoding="utf-8"))
    config["fixture_source_tree_sha256"] = "0" * 64

    with pytest.raises(BenchmarkConfigError, match="fixture source tree hash"):
        _validate_v2_config(config, V2_CONFIG)


def test_v2_legacy_commit_field_remains_a_valid_alias(monkeypatch):
    config = json.loads(V2_CONFIG.read_text(encoding="utf-8"))
    config.pop("fixture_source_tree_sha256")
    config["scanner_source_commit_hash"] = "a" * 40

    verified: list[tuple[str, Path]] = []
    monkeypatch.setattr(
        "benchmarks.runner._verify_fixture_revision",
        lambda reference, benchmark_root: verified.append(
            (reference, benchmark_root)
        ),
    )

    _validate_v2_config(config, V2_CONFIG)

    assert verified == [("a" * 40, V2_CONFIG.parent.resolve())]


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


def test_offline_osv_client_enforces_query_limit():
    client = _OfflineOSVClient(max_queries=1)

    first = client.query(object())
    limited = client.query(object())

    assert first.error is None
    assert limited.error == "query_limit_exceeded"
    assert client.queried == 1
    assert client.limit_reached is True


def test_generated_artifacts_are_excluded_from_benchmark_hashes_but_not_scans(tmp_path):
    clean_root = tmp_path / "clean"
    cache_root = tmp_path / "cache"
    untrusted_root = tmp_path / "untrusted"
    for root in (clean_root, cache_root, untrusted_root):
        root.mkdir(parents=True)
        (root / "module.py").write_text("value = 1\n", encoding="utf-8")
    (cache_root / "__pycache__").mkdir()
    (cache_root / "__pycache__" / "module.cpython-311.pyc").write_bytes(b"compiled")
    (untrusted_root / "__pycache__").mkdir()
    (untrusted_root / "__pycache__" / "module.cpython-311.pyc").write_bytes(b"compiled")
    (untrusted_root / "__pycache__" / "orphan.pyc").write_bytes(b"compiled")
    (untrusted_root / "stray.pyc").write_bytes(b"compiled")

    clean_scanner, _, _, _ = _scan_target(clean_root)
    cache_scanner, cache_report, _, _ = _scan_target(cache_root)
    untrusted_scanner, _, _, _ = _scan_target(untrusted_root)

    assert "__pycache__/module.cpython-311.pyc" in cache_scanner.discovered_files
    assert any(
        finding.get("location", {}).get("file") == "__pycache__/module.cpython-311.pyc"
        for finding in cache_report["findings"]
    )
    assert _content_tree_hash(clean_scanner) == _content_tree_hash(cache_scanner)
    assert _content_tree_hash(clean_scanner) != _content_tree_hash(untrusted_scanner)
    assert _tree_fingerprint([
        ("module.py", b"value = 1\n"),
        ("__pycache__/module.pyc", b"compiled"),
    ]) == _tree_fingerprint([("module.py", b"value = 1\n")])
    assert _tree_fingerprint([
        ("module.py", b"value = 1\n"),
        ("__pycache__/module.pyc", b"compiled"),
        ("__pycache__/orphan.pyc", b"compiled"),
    ]) != _tree_fingerprint([("module.py", b"value = 1\n")])


def test_legacy_and_v2_scan_targets_keep_distinct_parent_license_policies(tmp_path):
    (tmp_path / "SKILL.md").write_text(
        "---\nname: demo\nversion: 1.0.0\ndescription: policy fixture\nauthor: tester\nlicense: MIT\n---\n",
        encoding="utf-8",
    )

    legacy_scanner, _, _, _ = _scan_target(tmp_path)
    v2_scanner, _, _, _ = _scan_target(
        tmp_path,
        "a" * 40,
        policy=ScanPolicy(allow_parent_license_files=False),
    )

    assert legacy_scanner.policy.allow_parent_license_files is True
    assert v2_scanner.policy.allow_parent_license_files is False


def test_v2_corpus_is_complete_checkable_and_deterministic():
    first = run_benchmark(V2_CONFIG)
    second = run_benchmark(V2_CONFIG)

    assert first["corpus"] == {
        "case_count": 59,
        "ground_truth_distribution": {
            "benign": 9,
            "benign_capability": 18,
            "malicious": 19,
            "needs_context": 13,
        },
        "enforcement_distribution": {"blocking": 59, "observe": 0},
    }
    assert first["coverage"]["complete_scan_ratio"] == 1.0
    assert first["coverage"]["rule_exception_ratio"] == 0.0
    assert first["integrity"] == {
        "content_hash_mismatches": 0,
        "fixture_source_tree_sha256": "5825ddb429d469d15747f98994a3662162f2c8f14f2785af8572adf8a5bd70cc",
        "fixture_revision_verified": True,
        "scanner_implementation_sha256": first["integrity"]["scanner_implementation_sha256"],
        "offline_osv": True,
        "llm_mode": "not_invoked",
    }
    assert len(first["integrity"]["scanner_implementation_sha256"]) == 64
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
        "require_complete_rule_coverage": True,
        "require_independent_variants": True,
    }
    assert all(
        case.get("known_gap", {}).get("planned_pr")
        for case in first["cases"]
        if case["enforcement"] == "observe"
    )
    assert sum(first["metrics"]["grade_distribution"].values()) == 59
    assert "severity_confusion_matrix" in first["metrics"]
    rule_coverage = first["coverage"]["rule_coverage"]
    assert rule_coverage["registry_count"] == 21
    assert rule_coverage["family_count"] == 20
    assert rule_coverage["status"] == "complete"
    assert rule_coverage["untested_rules"] == []
    assert rule_coverage["incomplete_rules"] == []
    rows_by_rule = {row["rule_id"]: row for row in rule_coverage["rules"]}
    assert rows_by_rule["SR-001"]["negative_case_count"] == 1
    assert rows_by_rule["SR-004"]["negative_case_count"] == 1
    assert rows_by_rule["SR-005b"]["positive_case_count"] == 1
    assert all(
        set((
            "rule_id",
            "positive_case_count",
            "negative_case_count",
            "context_case_count",
            "true_positive",
            "false_positive",
            "false_negative",
            "coverage_status",
        )) <= row.keys()
        and row["coverage_status"] == "complete"
        for row in rule_coverage["rules"]
    )
    assert rule_coverage["independent_variants"] == [
        {
            "rule_id": "SR-005b",
            "cases": [{"case_id": "sr005b-aliased-exec", "passed": True}],
            "status": "complete",
        }
    ]
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
