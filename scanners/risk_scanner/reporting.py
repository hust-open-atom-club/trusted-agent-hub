"""Pure helpers for scan completeness and security conclusion reporting."""

from __future__ import annotations

from typing import Any


def _matched_text(finding: dict[str, Any]) -> str:
    evidence = str(finding.get("evidence", ""))
    for prefix in ("匹配模式:", "匹配:"):
        if evidence.startswith(prefix):
            return evidence[len(prefix):].strip()[:120]
    return evidence.strip()[:120]


def aggregate_findings(
    findings: list[dict[str, Any]], *, max_occurrence_items: int = 100
) -> list[dict[str, Any]]:
    """Aggregate only the report view; never mutate or delete raw findings."""
    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []
    for finding in findings:
        key = (str(finding.get("rule_id", "")), _matched_text(finding))
        # Findings without a stable match are intentionally not grouped.
        if not key[1]:
            key = (key[0], f"__finding__{finding.get('id', len(order))}")
        occurrence = _occurrence(finding)
        if key not in groups:
            groups[key] = dict(finding)
            groups[key]["occurrences"] = {
                "count": 1,
                "items": [occurrence],
                "truncated": False,
            }
            order.append(key)
            continue
        group = groups[key]
        occurrences = group["occurrences"]
        occurrences["count"] += 1
        if len(occurrences["items"]) < max_occurrence_items:
            occurrences["items"].append(occurrence)
        else:
            occurrences["truncated"] = True
        if severity_rank.get(str(finding.get("severity", "info")), 0) > severity_rank.get(str(group.get("severity", "info")), 0):
            preserved = group["occurrences"]
            groups[key] = dict(finding)
            groups[key]["occurrences"] = preserved
    return [groups[key] for key in order]


def _occurrence(finding: dict[str, Any]) -> dict[str, Any]:
    location = finding.get("location", {}) or {}
    item: dict[str, Any] = {"file": str(location.get("file", "(unknown)"))}
    if location.get("line"):
        item["line"] = int(location["line"])
    return item


def determine_scan_status(
    *,
    target_valid: bool,
    limit_violations: list[str],
    scanner_errors: list[dict[str, Any]],
    effective_total: int,
) -> dict[str, Any]:
    if not target_valid:
        state = "failed"
    elif limit_violations or scanner_errors:
        state = "partial"
    else:
        state = "complete"
    conclusion = "inconclusive" if state != "complete" else (
        "risks_found" if effective_total > 0 else "no_risks_found"
    )
    reasons = list(limit_violations)
    if any(error.get("phase") == "rule_execution" for error in scanner_errors):
        reasons.append("rule_execution_errors")
    if any(error.get("phase") == "structured_analysis" for error in scanner_errors):
        reasons.append("structured_analysis_errors")
    if scanner_errors and not any(error.get("phase") in {"rule_execution", "structured_analysis"} for error in scanner_errors):
        reasons.append("scanner_errors")
    return {
        "state": state,
        "conclusion": conclusion,
        "complete": state == "complete",
        "reasons": reasons,
    }
