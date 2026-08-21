"""Pure helpers for scan completeness and security conclusion reporting."""

from __future__ import annotations

from typing import Any


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
    if scanner_errors:
        reasons.append("rule_execution_errors")
    return {
        "state": state,
        "conclusion": conclusion,
        "complete": state == "complete",
        "reasons": reasons,
    }
