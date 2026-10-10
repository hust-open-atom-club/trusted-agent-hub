"""Shared admission policy for semantic LLM review candidates.

LLM review is an explicit semantic-analysis stage, not a severity fallback.
Only scanner findings that opt in to semantic adjudication and point at source
that was actually scanned may consume the review budget.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from scanners.risk_scanner.evidence import delivered_source_lines, finding_location, normalize_file_path


def is_semantic_candidate(finding: Mapping[str, Any]) -> bool:
    """Intent is independent of source availability, so missing evidence counts."""
    return (
        finding.get("rule_id") != "SR-004"
        and finding.get("llm_review_exempt") is not True
        and bool(finding.get("id"))
        and (finding.get("requires_llm_validation") is True or finding.get("llm_adjudication_eligible") is True)
    )


@dataclass(frozen=True)
class LLMCandidateDecision:
    """Result of applying the shared LLM candidate admission policy."""

    eligible: bool
    reason: str | None = None


_CONTEXT_SKIP_REASONS = frozenset({
    "missing_source_location",
    "missing_source_file",
    "invalid_source_line",
    "source_file_not_scanned",
    "source_file_not_text",
    "source_context_empty",
    "source_line_out_of_range",
    "source_context_not_built",
    "source_location_not_in_context",
    "invalid_source_path",
    "evidence_limit",
    "evidence_redacted",
})


def _location_line(location: Mapping[str, Any]) -> int | None:
    line = location.get("line")
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        return None
    return line


def _context_contains_location(
    context: str,
    context_audit: Mapping[str, Any] | None,
    *,
    file_path: str,
    line: int,
) -> bool:
    if context_audit is not None:
        return (file_path, line) in delivered_source_lines(context, context_audit)

    return re.search(rf"(?m)^{line}:\s", context) is not None


def evaluate_llm_candidate(
    finding: Mapping[str, Any],
    *,
    file_contents: Mapping[str, str] | None = None,
    finding_context: str | None = None,
    context_audit: Mapping[str, Any] | None = None,
    require_built_context: bool = False,
) -> LLMCandidateDecision:
    """Return whether ``finding`` may be sent to semantic LLM review.

    ``file_contents`` is the scanner-owned text snapshot. Supplying it proves
    that the finding refers to a real scanned file and that its line can be
    excerpted. At the reviewer boundary, ``finding_context`` plus its audit
    proves that the admitted location survived context construction.
    """

    if finding.get("rule_id") == "SR-004" or finding.get("llm_review_exempt") is True:
        return LLMCandidateDecision(False, "explicitly_exempt")
    if not (
        finding.get("requires_llm_validation") is True
        or finding.get("llm_adjudication_eligible") is True
    ):
        return LLMCandidateDecision(False, "not_semantic_candidate")
    if not str(finding.get("id") or "").strip():
        return LLMCandidateDecision(False, "missing_finding_id")

    location = finding.get("location")
    if finding.get("evidence_missing_reason") == "sensitive_identifier" or (
        isinstance(location, Mapping) and location.get("missing_reason") == "sensitive_identifier"
    ):
        return LLMCandidateDecision(False, "evidence_redacted")
    if not isinstance(location, Mapping):
        return LLMCandidateDecision(False, "missing_source_location")
    file_path = location.get("file")
    if not file_path:
        return LLMCandidateDecision(False, "missing_source_file")
    file_path = normalize_file_path(file_path)
    if file_path is None:
        return LLMCandidateDecision(False, "invalid_source_path")
    location = finding_location(finding)
    if file_contents is not None:
        if file_path not in file_contents:
            return LLMCandidateDecision(False, "source_file_not_scanned")
        content = file_contents[file_path]
        if not isinstance(content, str):
            return LLMCandidateDecision(False, "source_file_not_text")
    if finding.get("evidence_missing_reason") == "source_ref_too_long":
        return LLMCandidateDecision(False, "evidence_limit")
    line = _location_line(location)
    if line is None:
        return LLMCandidateDecision(False, "invalid_source_line")

    if file_contents is not None:
        lines = content.splitlines()
        if not lines:
            return LLMCandidateDecision(False, "source_context_empty")
        if line > len(lines):
            return LLMCandidateDecision(False, "source_line_out_of_range")

    if require_built_context:
        context = finding_context or ""
        if not context.strip():
            return LLMCandidateDecision(False, "source_context_not_built")
        if not _context_contains_location(
            context,
            context_audit,
            file_path=file_path,
            line=line,
        ):
            return LLMCandidateDecision(
                False,
                "source_location_not_in_context",
            )
        end_line = location.get("end_line", line)
        if isinstance(end_line, bool) or not isinstance(end_line, int) or end_line < line:
            return LLMCandidateDecision(False, "invalid_source_line")
        if context_audit is not None:
            delivered = delivered_source_lines(context, context_audit)
            if any((file_path, number) not in delivered for number in range(line, end_line + 1)):
                return LLMCandidateDecision(False, "source_location_not_in_context")

    return LLMCandidateDecision(True)


def candidate_context_reason(reason: str | None) -> str | None:
    if reason not in _CONTEXT_SKIP_REASONS:
        return None
    if reason in {"source_context_not_built", "source_location_not_in_context"}:
        return "delivery_missing"
    if reason in {"invalid_source_line", "source_line_out_of_range", "source_context_empty"}:
        return "location_unresolved"
    if reason in {"evidence_limit", "evidence_redacted"}:
        return reason
    return "source_missing"


def record_llm_candidate_skip(
    finding: dict[str, Any],
    decision: LLMCandidateDecision,
) -> None:
    """Persist source-context admission failures using existing report fields."""

    reason = decision.reason
    if decision.eligible or reason not in _CONTEXT_SKIP_REASONS:
        return
    marker = f"llm_candidate_skipped:{reason}"
    raw_missing = finding.get("llm_missing_context")
    missing = (
        [str(item) for item in raw_missing]
        if isinstance(raw_missing, list)
        else []
    )
    if marker not in missing:
        missing.append(marker)
    finding["llm_missing_context"] = missing
    finding["llm_context_status"] = "missing"
    finding["llm_context_reasons"] = [candidate_context_reason(reason)]
    finding["llm_adjudication_action"] = "manual_review"
    finding["requires_manual_review"] = True


def is_llm_candidate(
    finding: dict[str, Any],
    *,
    file_contents: Mapping[str, str] | None = None,
    finding_context: str | None = None,
    context_audit: Mapping[str, Any] | None = None,
    require_built_context: bool = False,
    record_skip: bool = False,
) -> bool:
    """Boolean convenience wrapper around :func:`evaluate_llm_candidate`."""

    decision = evaluate_llm_candidate(
        finding,
        file_contents=file_contents,
        finding_context=finding_context,
        context_audit=context_audit,
        require_built_context=require_built_context,
    )
    if record_skip:
        record_llm_candidate_skip(finding, decision)
    return decision.eligible
