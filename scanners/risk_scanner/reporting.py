"""Pure helpers for scan completeness and security conclusion reporting."""

from __future__ import annotations

from typing import Any

from scanners.risk_scanner.weights import SEVERITY_POINTS


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


def build_findings_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the score-facing summary from the current effective severities.

    Semantic findings awaiting LLM validation use ``severity=info``.  Calling
    this helper after the review therefore keeps the report summary aligned
    with the reviewed finding state instead of retaining the static
    candidate's original high/critical severity.
    """
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()
        if severity in severity_counts:
            severity_counts[severity] += 1

    occurrences_total = sum(
        int((finding.get("occurrences") or {}).get("count", 1))
        for finding in findings
    )
    effective_total = sum(
        severity_counts[severity]
        for severity in ("critical", "high", "medium", "low")
    )
    penalty = sum(
        SEVERITY_POINTS.get(severity, 0) * severity_counts[severity]
        for severity in ("critical", "high", "medium", "low")
    )
    return {
        "total": len(findings),
        "occurrences_total": occurrences_total,
        "effective_total": effective_total,
        **severity_counts,
        "pass_rate": (
            100.0
            if effective_total == 0
            else max(0.0, round(100.0 - penalty, 1))
        ),
    }


def build_advisory_summary(advisories: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize non-security review advisories without turning them into findings."""
    levels = {"high": 0, "warning": 0, "info": 0}
    deduction_total = 0
    grade_downgrade_steps = 0
    manual_review_required = False
    for advisory in advisories:
        level = str(advisory.get("level", "warning")).lower()
        if level in levels:
            levels[level] += 1
        try:
            deduction_total += max(0, int(advisory.get("deduction", 0)))
        except (TypeError, ValueError):
            pass
        try:
            grade_downgrade_steps = max(
                grade_downgrade_steps,
                max(0, int(advisory.get("grade_downgrade_steps", 0))),
            )
        except (TypeError, ValueError):
            pass
        manual_review_required = (
            manual_review_required
            or advisory.get("requires_manual_review") is True
        )

    return {
        "total": len(advisories),
        **levels,
        "deduction_total": min(100, deduction_total),
        # A capability mismatch is a package-level condition.  Repeated
        # capabilities must not cascade a package from B directly to D/E.
        "grade_downgrade_steps": min(1, grade_downgrade_steps),
        "manual_review_required": manual_review_required,
    }


def refresh_report_summaries(report: dict[str, Any]) -> None:
    """Refresh mutable report summaries after permission or LLM reconciliation."""
    findings = report.get("findings", [])
    advisories = report.get("review_advisories", [])
    report["summary"] = build_findings_summary(
        findings if isinstance(findings, list) else []
    )
    report["advisory_summary"] = build_advisory_summary(
        advisories if isinstance(advisories, list) else []
    )


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
