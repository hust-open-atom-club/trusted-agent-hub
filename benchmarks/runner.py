"""Run deterministic, labeled scanner benchmarks.

The default v2 corpus evaluates rule hits, root issues, effective severity,
capabilities, manual-review state, and the production trust-score grade.  The
legacy ``expected-results.json`` format remains supported for downstream users.

Usage from the repository root::

    python benchmarks/runner.py --config benchmarks/labels-v2.json
    python benchmarks/runner.py --config benchmarks/labels-v2.json --check
    python benchmarks/runner.py --config benchmarks/expected-results.json
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import sys
import time
import tracemalloc
import types
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanners.risk_scanner.scanner import RiskScanner  # noqa: E402


SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {severity: len(SEVERITIES) - index for index, severity in enumerate(SEVERITIES)}
GROUND_TRUTH_BENIGN = frozenset({"benign", "benign_capability"})


class BenchmarkConfigError(ValueError):
    """Raised when benchmark labels are invalid or unsafe to resolve."""


class _OfflineOSVResult:
    vulnerability_ids: list[str] = []
    error: str | None = None


class _OfflineOSVClient:
    """Deterministic OSV fixture used by every benchmark scan."""

    def __init__(self, *, max_queries: int = 10) -> None:
        self.max_queries = max_queries
        self.queried = 0
        self.failures = 0
        self.limit_reached = False

    def query(self, _dependency: Any) -> _OfflineOSVResult:
        self.queried += 1
        return _OfflineOSVResult()


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1))
    return round(ordered[index], 2)


def _evaluate_case(expected: set[str], actual: set[str], metrics: dict[str, dict[str, int]]) -> None:
    for rule_id in sorted(expected | actual):
        metric = metrics.setdefault(rule_id, {"tp": 0, "fp": 0, "fn": 0})
        if rule_id in expected and rule_id in actual:
            metric["tp"] += 1
        elif rule_id in actual:
            metric["fp"] += 1
        else:
            metric["fn"] += 1


def _with_rates(metric: dict[str, int]) -> dict[str, float | int]:
    tp, fp, fn = metric["tp"], metric["fp"], metric["fn"]
    return {
        **metric,
        "precision": round(tp / (tp + fp), 4) if tp + fp else 1.0,
        "recall": round(tp / (tp + fn), 4) if tp + fn else 1.0,
    }


def _benchmark_check_failures(result: dict[str, Any]) -> list[str]:
    """Return regressions that should make a CI benchmark check fail."""
    failures: list[str] = []
    if result.get("schema_version") == "2.0":
        for case in result.get("cases", []):
            if case.get("enforcement") != "blocking" or not case.get("differences"):
                continue
            fields = sorted({str(item.get("field", "target")) for item in case["differences"]})
            failures.append(
                f"blocking case {case.get('id', '<unknown>')} differs: {', '.join(fields)}"
            )
        integrity = result.get("integrity") or {}
        if int(integrity.get("content_hash_mismatches", 0)):
            failures.append("benchmark fixture content hash mismatch")
    else:
        overall = result.get("overall") or {}
        if int(overall.get("fp", 0)):
            failures.append(f"unexpected rule findings (fp={overall['fp']})")
        if int(overall.get("fn", 0)):
            failures.append(f"missing expected rule findings (fn={overall['fn']})")

    coverage = result.get("coverage") or {}
    if float(coverage.get("incomplete_scan_ratio", 0)):
        failures.append("benchmark contains incomplete scans")
    if float(coverage.get("rule_exception_ratio", 0)):
        failures.append("benchmark contains rule execution failures")
    return failures


def _read_config(config_path: Path) -> dict[str, Any]:
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BenchmarkConfigError(f"cannot read config: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BenchmarkConfigError(
            f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(config, dict):
        raise BenchmarkConfigError("benchmark config root must be an object")
    return config


def _validate_v2_config(config: dict[str, Any], config_path: Path) -> None:
    schema_path = config_path.with_name("schema-v2.json")
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkConfigError(f"cannot load v2 schema: {exc}") from exc
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:  # pragma: no cover - CI and dev dependencies include it
        raise BenchmarkConfigError("jsonschema is required to validate v2 labels") from exc

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(config), key=lambda item: list(item.absolute_path))
    if errors:
        rendered: list[str] = []
        for error in errors[:20]:
            location = ".".join(str(part) for part in error.absolute_path) or "<root>"
            rendered.append(f"{location}: {error.message}")
        if len(errors) > 20:
            rendered.append(f"... and {len(errors) - 20} more error(s)")
        raise BenchmarkConfigError("invalid v2 labels:\n- " + "\n- ".join(rendered))

    ids = [str(case["id"]) for case in config["cases"]]
    duplicates = sorted({case_id for case_id in ids if ids.count(case_id) > 1})
    if duplicates:
        raise BenchmarkConfigError(f"duplicate case id(s): {', '.join(duplicates)}")

    config_root = config_path.parent.resolve()
    for case in config["cases"]:
        target = (config_root / str(case["path"])).resolve()
        try:
            target.relative_to(config_root)
        except ValueError as exc:
            raise BenchmarkConfigError(
                f"case {case['id']} path escapes benchmark directory: {case['path']}"
            ) from exc


def _scan_target(target: Path, source_commit_hash: str = "") -> tuple[Any, dict[str, Any], float, int]:
    scanner = RiskScanner(target, source_commit_hash=source_commit_hash)
    scanner.osv_client = _OfflineOSVClient(max_queries=scanner.policy.max_osv_queries)
    tracemalloc.start()
    started = time.perf_counter()
    try:
        report = scanner.scan()
    finally:
        elapsed_ms = (time.perf_counter() - started) * 1000
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    return scanner, report, elapsed_ms, peak


def _run_v1(config: dict[str, Any], config_path: Path) -> dict[str, Any]:
    """Run the original rule-presence benchmark format unchanged."""
    cases = config.get("cases", [])
    if not isinstance(cases, list):
        raise BenchmarkConfigError("legacy config cases must be an array")
    metrics: dict[str, dict[str, int]] = {}
    durations: list[float] = []
    peak_memory = 0
    incomplete = 0
    rule_failures = 0
    rule_total = 0
    case_results: list[dict[str, Any]] = []

    for case in cases:
        if not isinstance(case, dict) or not all(key in case for key in ("id", "path")):
            raise BenchmarkConfigError("legacy cases require id and path")
        target = (config_path.parent / str(case["path"])).resolve()
        scanner, report, elapsed_ms, peak = _scan_target(target)
        del scanner
        durations.append(elapsed_ms)
        peak_memory = max(peak_memory, peak)

        expected = {str(rule) for rule in case.get("expected_rules", [])}
        actual: set[str] = set()
        for finding in report.get("findings", []):
            detector_ids = finding.get("detector_ids")
            if isinstance(detector_ids, list) and detector_ids:
                actual.update(str(value) for value in detector_ids)
            elif finding.get("rule_id"):
                actual.add(str(finding["rule_id"]))
        _evaluate_case(expected, actual, metrics)
        state = (report.get("scan_status") or {}).get("state", "failed")
        incomplete += state != "complete"
        execution = report.get("rule_execution") or {}
        rule_failures += int(execution.get("failed", 0))
        rule_total += int(execution.get("total", 0))
        case_results.append({
            "id": case["id"],
            "state": state,
            "conclusion": (report.get("scan_status") or {}).get("conclusion"),
            "actual_rules": sorted(actual),
            "duration_ms": round(elapsed_ms, 2),
        })

    total_tp = sum(item["tp"] for item in metrics.values())
    total_fp = sum(item["fp"] for item in metrics.values())
    total_fn = sum(item["fn"] for item in metrics.values())
    return {
        "schema_version": "1.0",
        "cases": case_results,
        "rules": {rule_id: _with_rates(value) for rule_id, value in sorted(metrics.items())},
        "overall": _with_rates({"tp": total_tp, "fp": total_fp, "fn": total_fn}),
        "performance": {
            "average_scan_ms": round(sum(durations) / len(durations), 2) if durations else 0.0,
            "p95_scan_ms": _percentile(durations, 0.95),
            "max_memory_bytes": peak_memory,
        },
        "coverage": {
            "incomplete_scan_ratio": round(incomplete / len(case_results), 4) if case_results else 0.0,
            "rule_exception_ratio": round(rule_failures / rule_total, 4) if rule_total else 0.0,
        },
    }


_SCORER: Callable[..., dict[str, Any]] | None = None


def _load_scorer() -> Callable[..., dict[str, Any]]:
    """Load trust-score under a private package name to avoid API ``src`` clashes."""
    global _SCORER
    if _SCORER is not None:
        return _SCORER

    package_name = "_benchmark_trust_score"
    source_dir = ROOT / "packages" / "trust-score" / "src"
    package = types.ModuleType(package_name)
    package.__path__ = [str(source_dir)]
    package.__package__ = package_name
    sys.modules[package_name] = package
    for name in (
        "model_identity",
        "provenance",
        "intent",
        "community",
        "derived_score",
        "explainer",
        "engine",
    ):
        qualified = f"{package_name}.{name}"
        spec = importlib.util.spec_from_file_location(qualified, source_dir / f"{name}.py")
        if spec is None or spec.loader is None:  # pragma: no cover - repository corruption
            raise RuntimeError(f"cannot load trust-score module {name}")
        module = importlib.util.module_from_spec(spec)
        module.__package__ = package_name
        sys.modules[qualified] = module
        spec.loader.exec_module(module)
    _SCORER = sys.modules[f"{package_name}.engine"].rate
    return _SCORER


def _effective_severity(finding: dict[str, Any]) -> str:
    value = str(finding.get("effective_severity") or finding.get("severity") or "info").lower()
    return value if value in SEVERITY_RANK else "info"


def _stable_finding_key(finding: dict[str, Any]) -> tuple[Any, ...]:
    location = finding.get("location") or {}
    return (
        str(finding.get("rule_id") or ""),
        str(location.get("file") or ""),
        int(location.get("line") or 0),
        str(finding.get("title") or ""),
        _effective_severity(finding),
        str(finding.get("category") or ""),
    )


def _actual_root_issues(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize v2 findings while preserving the required legacy fallbacks."""
    groups: dict[str, dict[str, Any]] = {}
    for finding in sorted(findings, key=_stable_finding_key):
        explicit_root = bool(finding.get("root_cause_id"))
        root_key = str(finding.get("root_cause_id") or finding.get("id") or _stable_finding_key(finding))
        group = groups.setdefault(root_key, {
            "explicit_root": explicit_root,
            "root_cause_id": root_key if explicit_root else "",
            "rule_ids": set(),
            "effective_severities": set(),
            "kinds": set(),
            "dispositions": set(),
            "finding_count": 0,
            "stable_key": _stable_finding_key(finding),
        })
        detector_ids = finding.get("detector_ids")
        if isinstance(detector_ids, list) and detector_ids:
            group["rule_ids"].update(str(value) for value in detector_ids)
        else:
            group["rule_ids"].add(str(finding.get("rule_id") or "legacy_unknown"))
        group["effective_severities"].add(_effective_severity(finding))
        group["kinds"].add(str(finding.get("kind") or "legacy_unknown"))
        group["dispositions"].add(str(finding.get("disposition") or "legacy_unknown"))
        group["finding_count"] += 1

    ordered = sorted(
        groups.values(),
        key=lambda item: (
            0 if item["explicit_root"] else 1,
            item["root_cause_id"] if item["explicit_root"] else item["stable_key"],
        ),
    )
    normalized: list[dict[str, Any]] = []
    legacy_index = 0
    for group in ordered:
        if group["explicit_root"]:
            display_id = group["root_cause_id"]
        else:
            legacy_index += 1
            display_id = f"legacy-root-{legacy_index:03d}"
        severities = sorted(group["effective_severities"], key=lambda value: -SEVERITY_RANK[value])
        normalized.append({
            "id": display_id,
            "id_source": "root_cause_id" if group["explicit_root"] else "finding_id_fallback",
            "rule_ids": sorted(group["rule_ids"]),
            "effective_severity": severities[0] if severities else "info",
            "effective_severities": severities,
            "kinds": sorted(group["kinds"]),
            "dispositions": sorted(group["dispositions"]),
            "finding_count": group["finding_count"],
        })
    return normalized


def _match_root_issues(
    expected: list[dict[str, Any]], actual: list[dict[str, Any]]
) -> tuple[list[tuple[int, int]], list[int], list[int]]:
    """Greedily pair roots by explicit id, then by overlapping raw rules."""
    candidates: list[tuple[int, int, int, int]] = []
    for expected_index, expected_root in enumerate(expected):
        expected_rules = set(map(str, expected_root.get("rule_ids", [])))
        for actual_index, actual_root in enumerate(actual):
            actual_rules = set(map(str, actual_root.get("rule_ids", [])))
            exact_id = int(
                actual_root.get("id_source") == "root_cause_id"
                and str(expected_root.get("id")) == str(actual_root.get("id"))
            )
            overlap = len(expected_rules & actual_rules)
            if exact_id or overlap:
                candidates.append((exact_id, overlap, expected_index, actual_index))

    matched_expected: set[int] = set()
    matched_actual: set[int] = set()
    matches: list[tuple[int, int]] = []
    for _exact, _overlap, expected_index, actual_index in sorted(
        candidates, key=lambda item: (-item[0], -item[1], item[2], item[3])
    ):
        if expected_index in matched_expected or actual_index in matched_actual:
            continue
        matched_expected.add(expected_index)
        matched_actual.add(actual_index)
        matches.append((expected_index, actual_index))
    return (
        sorted(matches),
        [index for index in range(len(expected)) if index not in matched_expected],
        [index for index in range(len(actual)) if index not in matched_actual],
    )


def _capabilities(report: dict[str, Any]) -> list[str]:
    graph = ((report.get("structural_analysis") or {}).get("capability_graph") or {})
    declared = graph.get("declared", []) if isinstance(graph, dict) else []
    observed = graph.get("observed", []) if isinstance(graph, dict) else []
    return sorted({str(value) for value in [*declared, *observed]})


def _content_tree_hash(scanner: Any) -> str:
    """Hash fixture content canonically so Git EOL conversion is irrelevant.

    Production acquisition hashes remain byte-exact.  Benchmark labels,
    however, must describe the same fixture on Windows and Linux checkouts.
    """
    digest = hashlib.sha256()
    for record in sorted(scanner.inventory.files, key=lambda item: item.relative_path):
        path = record.absolute_path
        if path.is_symlink() or not path.is_file():
            continue
        payload = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        digest.update(record.relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(payload)).encode("ascii"))
        digest.update(b"\0")
        digest.update(payload)
        digest.update(b"\0")
    return digest.hexdigest()


def _score_case(
    scanner: Any,
    report: dict[str, Any],
    scoring_context: dict[str, Any],
    source_commit_hash: str,
) -> tuple[str, str]:
    metadata = deepcopy(getattr(scanner, "_package_metadata", None) or {})
    acquisition = deepcopy(scanner.acquisition_facts)
    source = acquisition.setdefault("source", {})
    source.update(deepcopy(scoring_context.get("source", {})))
    source["commit_hash"] = source_commit_hash
    verification = acquisition.setdefault("verification", {})
    verification.update(deepcopy(scoring_context.get("verification", {})))
    acquisition["acquisition_method"] = "benchmark_fixture"
    result = _load_scorer()(
        package_metadata=metadata,
        scan_report=report,
        author_history=deepcopy(scoring_context.get("author_history", {})),
        review_records=deepcopy(scoring_context.get("review_records", {})),
        feedback=deepcopy(scoring_context.get("feedback", {})),
        acquisition_facts=acquisition,
    )
    risk = result.get("risk_summary") or {}
    grade = str(risk.get("grade") or "unknown")
    manual = "required" if risk.get("manual_security_review_required") is True else "not_required"
    return grade, manual


def _difference(field: str, expected: Any, actual: Any) -> dict[str, Any]:
    return {"field": field, "expected": expected, "actual": actual}


def _evaluate_v2_case(
    case: dict[str, Any],
    report: dict[str, Any],
    *,
    grade: str,
    manual_review: str,
    content_hash: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    target = case["expected_target"]
    findings = [item for item in report.get("findings", []) if isinstance(item, dict)]
    actual_rules = sorted({str(item.get("rule_id")) for item in findings if item.get("rule_id")})
    expected_rules = sorted(map(str, target.get("raw_rules", [])))
    actual_roots = _actual_root_issues(findings)
    expected_roots = list(target.get("root_issues", []))
    matches, unmatched_expected, unmatched_actual = _match_root_issues(expected_roots, actual_roots)
    actual_capabilities = _capabilities(report)
    expected_capabilities = sorted(map(str, target.get("capabilities", [])))
    differences: list[dict[str, Any]] = []

    if actual_rules != expected_rules:
        differences.append(_difference("raw_rules", expected_rules, actual_rules))

    root_matches: list[dict[str, Any]] = []
    for expected_index, actual_index in matches:
        expected_root = expected_roots[expected_index]
        actual_root = actual_roots[actual_index]
        root_matches.append({"expected": expected_root["id"], "actual": actual_root["id"]})
        expected_root_rules = sorted(map(str, expected_root.get("rule_ids", [])))
        if expected_root_rules != actual_root["rule_ids"]:
            differences.append(_difference(
                f"root_issues.{expected_root['id']}.rule_ids",
                expected_root_rules,
                actual_root["rule_ids"],
            ))
        if (
            "effective_severity" in expected_root
            and expected_root["effective_severity"] != actual_root["effective_severity"]
        ):
            differences.append(_difference(
                f"root_issues.{expected_root['id']}.effective_severity",
                expected_root["effective_severity"],
                actual_root["effective_severity"],
            ))
        if "kind" in expected_root and [expected_root["kind"]] != actual_root["kinds"]:
            differences.append(_difference(
                f"root_issues.{expected_root['id']}.kind",
                expected_root["kind"],
                actual_root["kinds"],
            ))
        if "disposition" in expected_root and [expected_root["disposition"]] != actual_root["dispositions"]:
            differences.append(_difference(
                f"root_issues.{expected_root['id']}.disposition",
                expected_root["disposition"],
                actual_root["dispositions"],
            ))

    if unmatched_expected:
        differences.append(_difference(
            "root_issues.missing",
            [expected_roots[index]["id"] for index in unmatched_expected],
            [],
        ))
    if unmatched_actual:
        differences.append(_difference(
            "root_issues.unexpected",
            [],
            [actual_roots[index]["id"] for index in unmatched_actual],
        ))

    forbidden = set(map(str, target.get("forbidden_effective_severities", [])))
    forbidden_found = [
        {
            "rule_id": str(item.get("rule_id") or "legacy_unknown"),
            "effective_severity": _effective_severity(item),
            "file": str((item.get("location") or {}).get("file") or ""),
        }
        for item in sorted(findings, key=_stable_finding_key)
        if _effective_severity(item) in forbidden
    ]
    if forbidden_found:
        differences.append(_difference(
            "forbidden_effective_severities",
            sorted(forbidden),
            forbidden_found,
        ))

    if expected_capabilities != actual_capabilities:
        differences.append(_difference("capabilities", expected_capabilities, actual_capabilities))
    allowed_grades = list(map(str, target.get("security_grade", [])))
    if grade not in allowed_grades:
        differences.append(_difference("security_grade", allowed_grades, grade))
    expected_manual = str(target.get("manual_review", "either"))
    if expected_manual != "either" and manual_review != expected_manual:
        differences.append(_difference("manual_review", expected_manual, manual_review))
    if content_hash != case["content_tree_sha256"]:
        differences.append(_difference("content_tree_sha256", case["content_tree_sha256"], content_hash))

    state = str((report.get("scan_status") or {}).get("state", "failed"))
    if state != "complete":
        differences.append(_difference("scan_state", "complete", state))
    execution = report.get("rule_execution") or {}
    if int(execution.get("failed", 0)):
        differences.append(_difference("rule_execution.failed", 0, int(execution["failed"])))

    case_result: dict[str, Any] = {
        "id": case["id"],
        "path": case["path"],
        "ground_truth": case["ground_truth"],
        "enforcement": case["enforcement"],
        "scan_state": state,
        "conclusion": (report.get("scan_status") or {}).get("conclusion"),
        "actual": {
            "raw_rules": actual_rules,
            "root_issues": actual_roots,
            "effective_severities": sorted(
                {_effective_severity(item) for item in findings},
                key=lambda value: -SEVERITY_RANK[value],
            ),
            "capabilities": actual_capabilities,
            "security_grade": grade,
            "manual_review": manual_review,
            "content_tree_sha256": content_hash,
        },
        "target": target,
        "root_matches": root_matches,
        "status": "match" if not differences else "difference",
        "differences": differences,
    }
    if case["enforcement"] == "observe":
        case_result["known_gap"] = case["known_gap"]

    evaluation = {
        "expected_rules": set(expected_rules),
        "actual_rules": set(actual_rules),
        "root_tp": len(matches),
        "root_fp": len(unmatched_actual),
        "root_fn": len(unmatched_expected),
        "root_matches": [(expected_roots[e], actual_roots[a]) for e, a in matches],
        "unmatched_expected_roots": [expected_roots[index] for index in unmatched_expected],
        "unmatched_actual_roots": [actual_roots[index] for index in unmatched_actual],
        "has_high_critical": any(_effective_severity(item) in {"high", "critical"} for item in findings),
        "grade": grade,
        "content_hash_mismatch": content_hash != case["content_tree_sha256"],
        "rule_failed": int(execution.get("failed", 0)),
        "rule_total": int(execution.get("total", 0)),
        "incomplete": state != "complete",
    }
    return case_result, evaluation


def _empty_confusion_matrix() -> dict[str, dict[str, int]]:
    labels = (*SEVERITIES, "none")
    return {expected: {actual: 0 for actual in labels} for expected in labels}


def _security_fingerprint(result: dict[str, Any]) -> str:
    stable = deepcopy(result)
    stable.pop("performance", None)
    stable.pop("security_fingerprint", None)
    payload = json.dumps(stable, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _run_v2(config: dict[str, Any], config_path: Path) -> dict[str, Any]:
    _validate_v2_config(config, config_path)
    source_commit_hash = str(config["scanner_source_commit_hash"])
    scoring_context = config["scoring_context"]
    raw_metrics: dict[str, dict[str, int]] = {}
    root_counts = {"tp": 0, "fp": 0, "fn": 0}
    confusion = _empty_confusion_matrix()
    grade_distribution = {grade: 0 for grade in ("A", "B", "C", "D", "E", "unknown")}
    benign_total = 0
    benign_high_critical = 0
    malicious_total = 0
    malicious_high_critical = 0
    incomplete = 0
    rule_failures = 0
    rule_total = 0
    content_hash_mismatches = 0
    durations: list[float] = []
    case_durations: dict[str, float] = {}
    peak_memory = 0
    case_results: list[dict[str, Any]] = []

    for case in config["cases"]:
        target = (config_path.parent / str(case["path"])).resolve()
        scanner, report, elapsed_ms, peak = _scan_target(target, source_commit_hash)
        grade, manual_review = _score_case(
            scanner, report, scoring_context, source_commit_hash
        )
        content_hash = _content_tree_hash(scanner)
        case_result, evaluation = _evaluate_v2_case(
            case,
            report,
            grade=grade,
            manual_review=manual_review,
            content_hash=content_hash,
        )
        case_results.append(case_result)
        durations.append(elapsed_ms)
        case_durations[str(case["id"])] = round(elapsed_ms, 2)
        peak_memory = max(peak_memory, peak)

        _evaluate_case(evaluation["expected_rules"], evaluation["actual_rules"], raw_metrics)
        for name in root_counts:
            root_counts[name] += int(evaluation[f"root_{name}"])
        for expected_root, actual_root in evaluation["root_matches"]:
            expected_severity = str(expected_root.get("effective_severity", "info"))
            confusion[expected_severity][actual_root["effective_severity"]] += 1
        for expected_root in evaluation["unmatched_expected_roots"]:
            expected_severity = str(expected_root.get("effective_severity", "info"))
            confusion[expected_severity]["none"] += 1
        for actual_root in evaluation["unmatched_actual_roots"]:
            confusion["none"][actual_root["effective_severity"]] += 1

        ground_truth = str(case["ground_truth"])
        if ground_truth in GROUND_TRUTH_BENIGN:
            benign_total += 1
            benign_high_critical += int(evaluation["has_high_critical"])
        elif ground_truth == "malicious":
            malicious_total += 1
            malicious_high_critical += int(evaluation["has_high_critical"])
        grade_key = evaluation["grade"] if evaluation["grade"] in grade_distribution else "unknown"
        grade_distribution[grade_key] += 1
        incomplete += int(evaluation["incomplete"])
        rule_failures += int(evaluation["rule_failed"])
        rule_total += int(evaluation["rule_total"])
        content_hash_mismatches += int(evaluation["content_hash_mismatch"])

    total_tp = sum(item["tp"] for item in raw_metrics.values())
    total_fp = sum(item["fp"] for item in raw_metrics.values())
    total_fn = sum(item["fn"] for item in raw_metrics.values())
    result: dict[str, Any] = {
        "schema_version": "2.0",
        "corpus": {
            "case_count": len(case_results),
            "ground_truth_distribution": {
                truth: sum(1 for case in config["cases"] if case["ground_truth"] == truth)
                for truth in ("benign", "benign_capability", "malicious", "needs_context")
            },
            "enforcement_distribution": {
                mode: sum(1 for case in config["cases"] if case["enforcement"] == mode)
                for mode in ("blocking", "observe")
            },
        },
        "cases": case_results,
        "metrics": {
            "raw_rules": {
                "overall": _with_rates({"tp": total_tp, "fp": total_fp, "fn": total_fn}),
                "by_rule": {
                    rule_id: _with_rates(value) for rule_id, value in sorted(raw_metrics.items())
                },
            },
            "root_issues": {"overall": _with_rates(root_counts)},
            "benign_high_critical_false_positive_rate": round(
                benign_high_critical / benign_total, 4
            ) if benign_total else 0.0,
            "malicious_high_critical_recall": round(
                malicious_high_critical / malicious_total, 4
            ) if malicious_total else 0.0,
            "severity_confusion_matrix": confusion,
            "grade_distribution": grade_distribution,
        },
        "coverage": {
            "complete_scan_ratio": round((len(case_results) - incomplete) / len(case_results), 4)
            if case_results else 1.0,
            "incomplete_scan_ratio": round(incomplete / len(case_results), 4)
            if case_results else 0.0,
            "rule_exception_ratio": round(rule_failures / rule_total, 4) if rule_total else 0.0,
            "failed_rule_executions": rule_failures,
            "total_rule_executions": rule_total,
        },
        "integrity": {
            "content_hash_mismatches": content_hash_mismatches,
            "offline_osv": True,
            "llm_mode": "not_invoked",
        },
        "performance": {
            "case_duration_ms": case_durations,
            "average_scan_ms": round(sum(durations) / len(durations), 2) if durations else 0.0,
            "p95_scan_ms": _percentile(durations, 0.95),
            "max_memory_bytes": peak_memory,
        },
    }
    result["security_fingerprint"] = _security_fingerprint(result)
    return result


def run_benchmark(config_path: Path) -> dict[str, Any]:
    config_path = config_path.resolve()
    config = _read_config(config_path)
    if config.get("schema_version") == "2.0":
        return _run_v2(config, config_path)
    return _run_v1(config, config_path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).with_name("labels-v2.json"),
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail on blocking mismatches, fixture drift, incomplete scans, or rule errors",
    )
    args = parser.parse_args()
    try:
        result = run_benchmark(args.config.resolve())
    except BenchmarkConfigError as exc:
        print(f"Benchmark configuration error: {exc}", file=sys.stderr)
        return 2
    encoded = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    if args.check:
        failures = _benchmark_check_failures(result)
        if failures:
            print("Benchmark check failed:", file=sys.stderr)
            for failure in failures:
                print(f"- {failure}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
