"""Run scanner benchmarks and emit quality/performance metrics.

Usage from the repository root::

    python benchmarks/runner.py
    python benchmarks/runner.py --output benchmark-results.json

Expected labels are rule-level labels. A case containing a rule finding counts
as a positive for that rule; finding locations remain available in the scan
report but are intentionally not copied into benchmark output.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scanners.risk_scanner.scanner import RiskScanner  # noqa: E402


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


def run_benchmark(config_path: Path) -> dict[str, Any]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    metrics: dict[str, dict[str, int]] = {}
    durations: list[float] = []
    peak_memory = 0
    incomplete = 0
    rule_failures = 0
    rule_total = 0
    case_results: list[dict[str, Any]] = []

    for case in config.get("cases", []):
        target = (config_path.parent / str(case["path"])).resolve()
        tracemalloc.start()
        started = time.perf_counter()
        report = RiskScanner(target).scan()
        elapsed_ms = (time.perf_counter() - started) * 1000
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        durations.append(elapsed_ms)
        peak_memory = max(peak_memory, peak)

        expected = {str(rule) for rule in case.get("expected_rules", [])}
        actual = {str(finding.get("rule_id")) for finding in report.get("findings", [])}
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("expected-results.json"))
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--check",
        action="store_true",
        help="return non-zero when expected labels, scan completeness, or rule execution regresses",
    )
    args = parser.parse_args()
    result = run_benchmark(args.config.resolve())
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
