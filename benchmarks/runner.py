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
import io
import importlib.util
import json
import math
import subprocess
import sys
import tarfile
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
from scanners.risk_scanner.rule_runner import RULE_SPECS  # noqa: E402
from scanners.risk_scanner.policy import ScanPolicy  # noqa: E402
from benchmarks.fixture_paths import (  # noqa: E402
    generated_artifact_source_path,
    is_generated_artifact_path,
)


SEVERITIES = ("critical", "high", "medium", "low", "info")
LEGACY_RULE_ALIASES = {"SR-005b": "SR-005"}
SEVERITY_RANK = {severity: len(SEVERITIES) - index for index, severity in enumerate(SEVERITIES)}
GROUND_TRUTH_BENIGN = frozenset({"benign", "benign_capability"})


class BenchmarkConfigError(ValueError):
    """Raised when benchmark labels are invalid or unsafe to resolve."""


class _OfflineOSVResult:
    def __init__(
        self,
        vulnerability_ids: list[str] | None = None,
        error: str | None = None,
    ) -> None:
        self.vulnerability_ids = vulnerability_ids or []
        self.error = error


class _OfflineOSVClient:
    """Deterministic OSV fixture used by every benchmark scan."""

    def __init__(self, *, max_queries: int = 10) -> None:
        self.max_queries = max_queries
        self.queried = 0
        self.failures = 0
        self.limit_reached = False

    def query(self, _dependency: Any) -> _OfflineOSVResult:
        if self.queried >= self.max_queries:
            self.limit_reached = True
            return _OfflineOSVResult([], "query_limit_exceeded")
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


def _rule_family_id(rule_id: str) -> str:
    """Return the numeric SR family for a registered detector variant."""
    return rule_id[:-1] if rule_id.endswith("b") else rule_id


def _case_source_commit_hash(case: dict[str, Any], default: str) -> str:
    """Allow a labeled case to model missing acquisition provenance."""
    context = case.get("scan_context") or {}
    if isinstance(context, dict) and "source_commit_hash" in context:
        return str(context["source_commit_hash"])
    return default


def _fixture_source_reference(config: dict[str, Any]) -> tuple[str, str]:
    """Return the stable fixture identity, preferring content over Git history."""
    tree_hash = config.get("fixture_source_tree_sha256")
    if tree_hash:
        return "tree", str(tree_hash)
    commit_hash = config.get("fixture_source_commit_hash")
    if commit_hash is None:
        commit_hash = config["scanner_source_commit_hash"]
    return "commit", str(commit_hash)


def _default_benchmark_source_commit_hash(
    reference_kind: str,
    reference: str,
) -> str:
    """Provide deterministic acquisition context for fixture-only scans.

    The scanner's source-integrity rule models an acquired commit, while the
    benchmark corpus is intentionally identified by a content hash.  A
    content-derived, commit-shaped value keeps ordinary fixtures in the
    complete-source context without pretending that a branch-local commit is
    the corpus identity.  Cases that model missing provenance override this
    value through ``scan_context.source_commit_hash``.
    """
    if reference_kind == "commit":
        return reference
    return reference[:40]


def _coverage_config_path(config: dict[str, Any], config_path: Path) -> Path:
    reference = str(config.get("coverage_config") or "coverage-v2.json")
    config_root = config_path.parent.resolve()
    target = (config_root / reference).resolve()
    try:
        target.relative_to(config_root)
    except ValueError as exc:
        raise BenchmarkConfigError(
            f"coverage config path escapes benchmark directory: {reference}"
        ) from exc
    return target


def _load_coverage_config(
    config: dict[str, Any],
    config_path: Path,
    *,
    required: bool,
) -> dict[str, Any] | None:
    """Load and schema-validate the optional detector coverage map."""
    coverage_path = _coverage_config_path(config, config_path)
    if not coverage_path.is_file():
        if required:
            raise BenchmarkConfigError(
                f"required rule coverage config is missing: {coverage_path.name}"
            )
        return None

    coverage = _read_config(coverage_path)
    schema_path = coverage_path.with_name("coverage-schema-v2.json")
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BenchmarkConfigError(f"cannot load coverage schema: {exc}") from exc
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:  # pragma: no cover - CI and dev dependencies include it
        raise BenchmarkConfigError("jsonschema is required to validate rule coverage") from exc

    errors = sorted(
        Draft202012Validator(schema).iter_errors(coverage),
        key=lambda item: list(item.absolute_path),
    )
    if errors:
        rendered: list[str] = []
        for error in errors[:20]:
            location = ".".join(str(part) for part in error.absolute_path) or "<root>"
            rendered.append(f"{location}: {error.message}")
        if len(errors) > 20:
            rendered.append(f"... and {len(errors) - 20} more error(s)")
        raise BenchmarkConfigError(
            "invalid rule coverage:\n- " + "\n- ".join(rendered)
        )
    return coverage


def _validate_coverage_config(
    coverage: dict[str, Any],
    labels: dict[str, Any],
) -> None:
    """Validate coverage references against labels and the live rule registry."""
    registered = {spec.rule_id for spec in RULE_SPECS}
    configured_rules = coverage.get("rules") or {}
    unknown_rules = sorted(set(configured_rules) - registered)
    if unknown_rules:
        raise BenchmarkConfigError(
            "coverage contains unregistered rule(s): " + ", ".join(unknown_rules)
        )

    cases = {
        str(case["id"]): case
        for case in labels.get("cases", [])
        if isinstance(case, dict) and "id" in case
    }
    if len(cases) != len(labels.get("cases", [])):
        raise BenchmarkConfigError("coverage validation requires unique labeled case ids")

    def case_ids(rule_id: str, entry: dict[str, Any], field: str) -> list[str]:
        values = entry.get(field, [])
        if not isinstance(values, list):
            raise BenchmarkConfigError(f"coverage {rule_id}.{field} must be an array")
        if len(values) != len(set(map(str, values))):
            raise BenchmarkConfigError(f"coverage {rule_id}.{field} contains duplicate cases")
        missing = sorted(set(map(str, values)) - set(cases))
        if missing:
            raise BenchmarkConfigError(
                f"coverage {rule_id}.{field} references unknown case(s): {', '.join(missing)}"
            )
        return [str(value) for value in values]

    for rule_id, entry in configured_rules.items():
        positive = case_ids(rule_id, entry, "positive_cases")
        negative = case_ids(rule_id, entry, "negative_cases")
        context = case_ids(rule_id, entry, "context_cases")
        if set(positive) & set(negative):
            raise BenchmarkConfigError(
                f"coverage {rule_id} uses the same case as positive and negative"
            )
        if not set(context) <= set(positive):
            raise BenchmarkConfigError(
                f"coverage {rule_id}.context_cases must be a subset of positive_cases"
            )

        for case_id in positive:
            target = cases[case_id]["expected_target"]
            expected = set(map(str, target.get("raw_rules", [])))
            if rule_id not in expected:
                raise BenchmarkConfigError(
                    f"coverage {rule_id} positive case {case_id} does not expect the rule"
                )
        for case_id in negative:
            case = cases[case_id]
            if case["ground_truth"] not in GROUND_TRUTH_BENIGN:
                raise BenchmarkConfigError(
                    f"coverage {rule_id} negative case {case_id} must be benign"
                )
            expected = set(map(str, case["expected_target"].get("raw_rules", [])))
            if rule_id in expected:
                raise BenchmarkConfigError(
                    f"coverage {rule_id} negative case {case_id} expects the rule"
                )

        for case_id in context:
            case = cases[case_id]
            roots = case["expected_target"].get("root_issues", [])
            is_context = case["ground_truth"] == "needs_context" or any(
                root.get("kind") == "context_dependent"
                or root.get("disposition") == "needs_context"
                for root in roots
                if isinstance(root, dict)
            )
            if not is_context:
                raise BenchmarkConfigError(
                    f"coverage {rule_id} context case {case_id} is not context-dependent"
                )

    for variant in coverage.get("independent_variants", []):
        rule_id = str(variant["rule_id"])
        if rule_id not in registered:
            raise BenchmarkConfigError(
                f"independent variant uses unregistered rule: {rule_id}"
            )
        entry = configured_rules.get(rule_id) or {}
        positive = set(map(str, entry.get("positive_cases", [])))
        variant_cases = set(map(str, variant.get("positive_cases", [])))
        if not variant_cases <= positive:
            raise BenchmarkConfigError(
                f"independent variant cases for {rule_id} must be positive cases"
            )
        forbidden = set(map(str, variant.get("forbidden_rules", [])))
        if rule_id in forbidden:
            raise BenchmarkConfigError(
                f"independent variant for {rule_id} cannot forbid itself"
            )
        for case_id in variant_cases:
            expected = set(map(str, cases[case_id]["expected_target"].get("raw_rules", [])))
            if rule_id not in expected or expected & forbidden:
                raise BenchmarkConfigError(
                    f"independent variant case {case_id} is not exclusive for {rule_id}"
                )

    if (labels.get("quality_gates") or {}).get("require_independent_variants"):
        configured_variants = {
            str(variant["rule_id"])
            for variant in coverage.get("independent_variants", [])
        }
        required_variants = {
            spec.rule_id for spec in RULE_SPECS if spec.rule_id.endswith("b")
        }
        missing_variants = sorted(required_variants - configured_variants)
        if missing_variants:
            raise BenchmarkConfigError(
                "missing independent detector variant(s): "
                + ", ".join(missing_variants)
            )


def _compute_rule_coverage(
    coverage: dict[str, Any] | None,
    evaluations: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """Calculate per-detector coverage using only explicitly scoped cases."""
    if coverage is None:
        return None

    configured_rules = coverage.get("rules") or {}
    rows: list[dict[str, Any]] = []
    for spec in RULE_SPECS:
        rule_id = spec.rule_id
        entry = configured_rules.get(rule_id) or {}
        positive = [str(value) for value in entry.get("positive_cases", [])]
        negative = [str(value) for value in entry.get("negative_cases", [])]
        context = [str(value) for value in entry.get("context_cases", [])]
        true_positive = sum(
            rule_id in evaluations[case_id]["actual_rules"] for case_id in positive
        )
        false_negative = len(positive) - true_positive
        false_positive = sum(
            rule_id in evaluations[case_id]["actual_rules"] for case_id in negative
        )
        status = (
            "untested" if not positive
            else "incomplete" if not negative
            else "complete"
        )
        rows.append({
            "rule_id": rule_id,
            "family_id": _rule_family_id(rule_id),
            "positive_case_count": len(positive),
            "negative_case_count": len(negative),
            "context_case_count": len(context),
            "true_positive": true_positive,
            "false_positive": false_positive,
            "false_negative": false_negative,
            "precision": (
                round(true_positive / (true_positive + false_positive), 4)
                if true_positive + false_positive else None
            ),
            "recall": (
                round(true_positive / (true_positive + false_negative), 4)
                if true_positive + false_negative else None
            ),
            "coverage_status": status,
        })

    independent_results: list[dict[str, Any]] = []
    for variant in coverage.get("independent_variants", []):
        rule_id = str(variant["rule_id"])
        forbidden = set(map(str, variant.get("forbidden_rules", [])))
        case_results = []
        for case_id in map(str, variant.get("positive_cases", [])):
            actual = evaluations[case_id]["actual_rules"]
            passed = rule_id in actual and not (actual & forbidden)
            case_results.append({"case_id": case_id, "passed": passed})
        independent_results.append({
            "rule_id": rule_id,
            "cases": case_results,
            "status": "complete" if case_results and all(
                item["passed"] for item in case_results
            ) else "failed",
        })

    untested = [row["rule_id"] for row in rows if row["coverage_status"] == "untested"]
    incomplete = [row["rule_id"] for row in rows if row["coverage_status"] == "incomplete"]
    independent_failed = [
        item["rule_id"] for item in independent_results if item["status"] != "complete"
    ]
    return {
        "registry_count": len(RULE_SPECS),
        "family_count": len({_rule_family_id(spec.rule_id) for spec in RULE_SPECS}),
        "rules": rows,
        "untested_rules": untested,
        "incomplete_rules": incomplete,
        "independent_variants": independent_results,
        "status": "complete" if not untested and not incomplete and not independent_failed else "incomplete",
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

        gates = result.get("quality_gates") or {}
        metrics = result.get("metrics") or {}
        corpus = result.get("corpus") or {}
        distribution = corpus.get("ground_truth_distribution") or {}
        benign_cases = int(distribution.get("benign", 0)) + int(
            distribution.get("benign_capability", 0)
        )
        minimum_checks = (
            ("case count", int(corpus.get("case_count", 0)), "minimum_cases"),
            ("benign case count", benign_cases, "minimum_benign_cases"),
            (
                "malicious case count",
                int(distribution.get("malicious", 0)),
                "minimum_malicious_cases",
            ),
        )
        for label, actual, gate_name in minimum_checks:
            minimum = int(gates.get(gate_name, 0))
            if actual < minimum:
                failures.append(
                    f"{label} below quality gate (actual={actual}, minimum={minimum})"
                )

        rate_checks = (
            (
                "raw rule precision",
                float(((metrics.get("raw_rules") or {}).get("overall") or {}).get("precision", 0)),
                "minimum_raw_precision",
                "minimum",
            ),
            (
                "raw rule recall",
                float(((metrics.get("raw_rules") or {}).get("overall") or {}).get("recall", 0)),
                "minimum_raw_recall",
                "minimum",
            ),
            (
                "root issue precision",
                float(((metrics.get("root_issues") or {}).get("overall") or {}).get("precision", 0)),
                "minimum_root_precision",
                "minimum",
            ),
            (
                "root issue recall",
                float(((metrics.get("root_issues") or {}).get("overall") or {}).get("recall", 0)),
                "minimum_root_recall",
                "minimum",
            ),
            (
                "benign high/critical false-positive rate",
                float(metrics.get("benign_high_critical_false_positive_rate", 0)),
                "maximum_benign_high_critical_false_positive_rate",
                "maximum",
            ),
            (
                "malicious high/critical recall",
                float(metrics.get("malicious_high_critical_recall", 0)),
                "minimum_malicious_high_critical_recall",
                "minimum",
            ),
        )
        for label, actual, gate_name, direction in rate_checks:
            threshold = float(gates.get(gate_name, 0 if direction == "minimum" else 1))
            failed = actual < threshold if direction == "minimum" else actual > threshold
            if failed:
                failures.append(
                    f"{label} outside quality gate "
                    f"(actual={actual:.4f}, {direction}={threshold:.4f})"
                )

        rule_coverage = (result.get("coverage") or {}).get("rule_coverage")
        coverage_gate_enabled = bool(
            gates.get("require_complete_rule_coverage")
            or gates.get("require_independent_variants")
        )
        if coverage_gate_enabled:
            if not isinstance(rule_coverage, dict):
                failures.append("missing rule coverage report")
            elif gates.get("require_complete_rule_coverage"):
                untested = list(rule_coverage.get("untested_rules") or [])
                incomplete = list(rule_coverage.get("incomplete_rules") or [])
                rows = [
                    row for row in rule_coverage.get("rules", [])
                    if isinstance(row, dict)
                ]
                covered_rule_ids = {
                    str(row.get("rule_id")) for row in rows if row.get("rule_id")
                }
                missing_rows = sorted(
                    {spec.rule_id for spec in RULE_SPECS} - covered_rule_ids
                )
                if missing_rows:
                    failures.append(
                        "missing rule coverage rows: " + ", ".join(missing_rows)
                    )
                row_untested = {
                    str(row["rule_id"])
                    for row in rows
                    if row.get("coverage_status") == "untested" and row.get("rule_id")
                }
                row_incomplete = {
                    str(row["rule_id"])
                    for row in rows
                    if row.get("coverage_status") == "incomplete" and row.get("rule_id")
                }
                untested = sorted(set(map(str, untested)) | row_untested)
                incomplete = sorted(set(map(str, incomplete)) | row_incomplete)
                if untested:
                    failures.append("untested rules: " + ", ".join(map(str, untested)))
                if incomplete:
                    failures.append("incomplete rules: " + ", ".join(map(str, incomplete)))
                coverage_status = str(rule_coverage.get("status") or "")
                if coverage_status and coverage_status != "complete":
                    failures.append(f"rule coverage status is {coverage_status}")
                mismatches = [
                    f"{row.get('rule_id')} (fp={int(row.get('false_positive', 0))}, "
                    f"fn={int(row.get('false_negative', 0))})"
                    for row in rows
                    if int(row.get("false_positive", 0))
                    or int(row.get("false_negative", 0))
                ]
                if mismatches:
                    failures.append(
                        "rule coverage mismatches: " + ", ".join(mismatches)
                    )

        if (
            coverage_gate_enabled
            and isinstance(rule_coverage, dict)
            and gates.get("require_independent_variants")
        ):
            variants = rule_coverage.get("independent_variants") or []
            configured_variants = {
                str(item.get("rule_id"))
                for item in variants
                if isinstance(item, dict) and item.get("rule_id")
            }
            required_variants = {
                spec.rule_id for spec in RULE_SPECS if spec.rule_id.endswith("b")
            }
            missing_variants = sorted(required_variants - configured_variants)
            if missing_variants:
                failures.append(
                    "missing independent detector variants: "
                    + ", ".join(missing_variants)
                )
            failed_variants = [
                str(item.get("rule_id"))
                for item in variants
                if isinstance(item, dict)
                if item.get("status") != "complete"
            ]
            if failed_variants:
                failures.append(
                    "independent detector variants failed: "
                    + ", ".join(failed_variants)
                )
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
        case_context = case.get("scan_context") or {}
        if isinstance(case_context, dict) and "source_commit_hash" in case_context:
            case_commit = str(case_context["source_commit_hash"])
            if case_commit and not len(case_commit) == 40:
                raise BenchmarkConfigError(
                    f"case {case['id']} scan_context.source_commit_hash must be empty or a 40-character hash"
                )

    _fixture_reference_kind, fixture_reference = _fixture_source_reference(config)
    _verify_fixture_revision(fixture_reference, config_root)

    gates = config.get("quality_gates") or {}
    require_coverage = bool(
        gates.get("require_complete_rule_coverage")
        or gates.get("require_independent_variants")
    )
    coverage = _load_coverage_config(config, config_path, required=require_coverage)
    if coverage is not None:
        _validate_coverage_config(coverage, config)


def _tree_fingerprint(entries: list[tuple[str, bytes]]) -> str:
    digest = hashlib.sha256()
    entry_names = {name for name, _ in entries}
    for name, content in sorted(entries):
        source_name = generated_artifact_source_path(name)
        if is_generated_artifact_path(
            name,
            source_exists=source_name in entry_names if source_name else False,
        ):
            continue
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(content)).encode("ascii"))
        digest.update(b"\0")
        digest.update(content)
    return digest.hexdigest()


def _fixture_tree_entries(root: Path) -> list[tuple[str, bytes]]:
    """Represent regular files and symlinks without following links."""
    root = root.resolve()

    def normalize_bytes(payload: bytes) -> bytes:
        # Git checkouts may materialize committed text as CRLF on Windows.
        # Provenance identifies fixture content, not the checkout EOL policy.
        return payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n")

    entries: list[tuple[str, bytes]] = []
    for path in root.rglob("*"):
        relative_to_root = path.relative_to(root).as_posix()
        source_relative = generated_artifact_source_path(relative_to_root)
        source_exists = False
        if source_relative:
            source_path = root / source_relative
            try:
                source_exists = source_path.is_file() and not source_path.is_symlink()
            except OSError:
                source_exists = False
        if is_generated_artifact_path(
            relative_to_root,
            source_exists=source_exists,
        ):
            continue
        name = path.relative_to(ROOT).as_posix()
        if path.is_symlink():
            try:
                target = str(path.readlink()).replace("\\", "/")
            except OSError:
                target = "<unreadable>"
            entries.append((name, b"symlink\0" + target.encode("utf-8")))
        elif path.is_file():
            entries.append((name, b"file\0" + normalize_bytes(path.read_bytes())))
    return entries


def _verify_fixture_tree_hash(tree_hash: str, benchmark_root: Path) -> None:
    corpus_root = benchmark_root / "corpus"
    if not corpus_root.is_dir():
        raise BenchmarkConfigError(
            "fixture source tree hash cannot be verified: benchmarks/corpus is missing"
        )
    actual = _tree_fingerprint(_fixture_tree_entries(corpus_root))
    if actual != tree_hash:
        raise BenchmarkConfigError(
            "fixture source tree hash does not match benchmarks/corpus "
            f"(expected={tree_hash}, actual={actual})"
        )


def _verify_fixture_commit(commit_hash: str, benchmark_root: Path) -> None:
    corpus_root = benchmark_root / "corpus"
    current_entries = _fixture_tree_entries(corpus_root)
    try:
        archive = subprocess.run(
            ["git", "archive", "--format=tar", commit_hash, "benchmarks/corpus"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise BenchmarkConfigError(
            f"cannot verify fixture source commit {commit_hash}: {exc}"
        ) from exc
    if archive.returncode != 0:
        detail = archive.stderr.decode("utf-8", errors="replace").strip()
        raise BenchmarkConfigError(
            f"fixture source commit {commit_hash} cannot be read: {detail}"
        )

    committed_entries: list[tuple[str, bytes]] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(archive.stdout), mode="r:") as bundle:
            members = bundle.getmembers()
            archive_file_names = {
                member.name
                for member in members
                if member.isfile()
            }
            for member in members:
                source_name = generated_artifact_source_path(member.name)
                if is_generated_artifact_path(
                    member.name,
                    source_exists=source_name in archive_file_names if source_name else False,
                ):
                    continue
                if member.issym() or member.islnk():
                    committed_entries.append(
                        (
                            member.name,
                            b"symlink\0" + member.linkname.replace("\\", "/").encode("utf-8"),
                        )
                    )
                    continue
                if not member.isfile():
                    continue
                source = bundle.extractfile(member)
                if source is not None:
                    payload = source.read().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
                    committed_entries.append((member.name, b"file\0" + payload))
    except tarfile.TarError as exc:
        raise BenchmarkConfigError(
            f"fixture source commit {commit_hash} produced an invalid archive"
        ) from exc

    if _tree_fingerprint(current_entries) != _tree_fingerprint(committed_entries):
        raise BenchmarkConfigError(
            f"fixture source commit {commit_hash} does not match benchmarks/corpus"
        )


def _verify_fixture_revision(reference: str, benchmark_root: Path) -> None:
    """Verify a content-tree identity or a legacy Git commit reference."""
    if len(reference) == 64 and all(char in "0123456789abcdef" for char in reference):
        _verify_fixture_tree_hash(reference, benchmark_root)
        return
    _verify_fixture_commit(reference, benchmark_root)


def _scanner_implementation_fingerprint() -> str:
    source_files = list((ROOT / "scanners" / "risk_scanner").rglob("*.py"))
    source_files.extend((ROOT / "packages" / "trust-score" / "src").rglob("*.py"))
    return _tree_fingerprint([
        (path.relative_to(ROOT).as_posix(), path.read_bytes())
        for path in source_files
        if path.is_file()
    ])


def _scan_target(
    target: Path,
    source_commit_hash: str = "",
    *,
    policy: ScanPolicy | None = None,
) -> tuple[Any, dict[str, Any], float, int]:
    scanner = RiskScanner(
        target,
        source_commit_hash=source_commit_hash,
        policy=policy,
    )
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
                actual.update(
                    LEGACY_RULE_ALIASES.get(str(value), str(value))
                    for value in detector_ids
                )
            elif finding.get("rule_id"):
                rule_id = str(finding["rule_id"])
                actual.add(LEGACY_RULE_ALIASES.get(rule_id, rule_id))
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
    inventory_paths = {record.relative_path for record in scanner.inventory.files}
    for record in sorted(scanner.inventory.files, key=lambda item: item.relative_path):
        path = record.absolute_path
        source_path = generated_artifact_source_path(record.relative_path)
        if is_generated_artifact_path(
            record.relative_path,
            source_exists=source_path in inventory_paths if source_path else False,
        ):
            continue
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
    configured_verification = deepcopy(scoring_context.get("verification", {}))
    verification.update(configured_verification)
    capabilities = acquisition.setdefault("verification_capabilities", {})
    capabilities.update({key: True for key in configured_verification})
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
    actual_rule_set: set[str] = set()
    for item in findings:
        detector_ids = item.get("detector_ids")
        if isinstance(detector_ids, list) and detector_ids:
            actual_rule_set.update(str(value) for value in detector_ids if value)
        elif item.get("rule_id"):
            actual_rule_set.add(str(item["rule_id"]))
    actual_rules = sorted(actual_rule_set)
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
    fixture_reference_kind, fixture_reference = _fixture_source_reference(config)
    source_commit_hash = _default_benchmark_source_commit_hash(
        fixture_reference_kind,
        fixture_reference,
    )
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
    evaluations_by_case: dict[str, dict[str, Any]] = {}
    coverage_config = _load_coverage_config(
        config,
        config_path,
        required=bool(
            (config.get("quality_gates") or {}).get(
                "require_complete_rule_coverage", False
            )
            or (config.get("quality_gates") or {}).get(
                "require_independent_variants", False
            )
        ),
    )

    for case in config["cases"]:
        target = (config_path.parent / str(case["path"])).resolve()
        case_source_commit_hash = _case_source_commit_hash(case, source_commit_hash)
        scanner, report, elapsed_ms, peak = _scan_target(
            target,
            case_source_commit_hash,
            policy=ScanPolicy(allow_parent_license_files=False),
        )
        grade, manual_review = _score_case(
            scanner, report, scoring_context, case_source_commit_hash
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
        evaluations_by_case[str(case["id"])] = evaluation
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
        "quality_gates": deepcopy(config["quality_gates"]),
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
            "rule_coverage": _compute_rule_coverage(
                coverage_config,
                evaluations_by_case,
            ),
        },
        "integrity": {
            "content_hash_mismatches": content_hash_mismatches,
            "fixture_revision_verified": True,
            "scanner_implementation_sha256": _scanner_implementation_fingerprint(),
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
    if fixture_reference_kind == "tree":
        result["integrity"]["fixture_source_tree_sha256"] = fixture_reference
    else:
        result["integrity"]["fixture_source_commit_hash"] = fixture_reference
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
