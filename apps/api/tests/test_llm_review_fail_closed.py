"""Regression tests for fail-closed LLM-review orchestration failures."""

from types import SimpleNamespace

from src.models.packages import LLMReview
from src.routers import trust


def _findings() -> list[dict[str, object]]:
    return [
        {
            "id": "critical-dangerous",
            "severity": "critical",
            "category": "prompt_injection",
        },
        {
            "id": "high-non-dangerous",
            "severity": "high",
            "category": "metadata_quality",
        },
        {
            "id": "medium",
            "severity": "medium",
            "category": "metadata_quality",
        },
    ]


def test_llm_reviewer_load_failure_marks_reviewable_findings_unavailable(
    monkeypatch,
) -> None:
    """A failed dynamic import must preserve the scorer's fail-closed signal."""
    findings = _findings()
    monkeypatch.setattr(
        trust.importlib.util,
        "spec_from_file_location",
        lambda *_args, **_kwargs: None,
    )

    result = trust._run_llm_review_with_fallback(findings, SimpleNamespace())

    assert result["status"] == "call_failed"
    assert result["fallback"] == "fail_closed_after_outer_exception"
    assert result["labels"] == {
        "critical-dangerous": "llm:unavailable",
        "high-non-dangerous": "llm:unavailable",
    }
    assert result["labels_summary"]["unavailable"] == 2
    assert findings[0]["llm_label"] == "llm:unavailable"
    assert findings[1]["llm_label"] == "llm:unavailable"
    assert "llm_label" not in findings[2]
    assert LLMReview.model_validate(result).status == "call_failed"


def test_unexpected_reviewer_exception_marks_reviewable_findings_unavailable(
    monkeypatch,
) -> None:
    """Unexpected reviewer exceptions must not bypass the outer fallback."""
    findings = _findings()

    def raise_from_reviewer(**_kwargs: object) -> dict[str, object]:
        raise ValueError("invalid reviewer response")

    monkeypatch.setattr(
        trust,
        "_load_llm_reviewer",
        lambda: SimpleNamespace(run_llm_review=raise_from_reviewer),
    )
    monkeypatch.setattr(trust, "build_finding_contexts", lambda *_args: {})

    result = trust._run_llm_review_with_fallback(
        findings,
        SimpleNamespace(_file_contents={}, _package_metadata={}),
    )

    assert result["status"] == "call_failed"
    assert result["error"] == "ValueError: invalid reviewer response"
    assert all(
        finding.get("llm_label") == "llm:unavailable"
        for finding in findings[:2]
    )


def test_not_configured_result_preserves_manual_review_semantics(monkeypatch) -> None:
    """A normal not-configured result must not be converted to call_failed."""
    findings = _findings()
    expected = {
        "triggered": True,
        "findings_reviewed": 0,
        "findings_skipped": 1,
        "findings_pending": 2,
        "status": "not_configured",
        "attempts": 0,
        "labels": {},
        "labels_summary": {
            "suspected_malicious": 0,
            "suspected_negligent": 0,
            "likely_benign": 0,
            "uncertain": 0,
            "unavailable": 0,
        },
        "error": "LLM provider is not configured",
        "fallback": "manual_review_required",
    }
    monkeypatch.setattr(
        trust,
        "_load_llm_reviewer",
        lambda: SimpleNamespace(run_llm_review=lambda **_kwargs: expected),
    )
    monkeypatch.setattr(trust, "build_finding_contexts", lambda *_args: {})

    result = trust._run_llm_review_with_fallback(
        findings,
        SimpleNamespace(_file_contents={}, _package_metadata={}),
    )

    assert result is expected
    assert result["status"] == "not_configured"
    assert all("llm_label" not in finding for finding in findings)
