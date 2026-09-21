"""Shared helpers for durable, user-facing LLM review progress."""

from __future__ import annotations

from typing import Any, Literal


def nonnegative_int(value: object, default: int = 0) -> int:
    """Coerce an integer-like value, clamping valid values at zero."""
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def finalize_running_llm_progress(
    progress: object,
    *,
    terminal_status: Literal["degraded", "timeout"],
    last_update_at: str,
    reason_code: str | None = None,
) -> dict[str, Any] | None:
    """Return a terminal copy of a running LLM progress snapshot."""
    if not isinstance(progress, dict):
        return None

    finalized = dict(progress)
    if finalized.get("status") != "running":
        return finalized

    findings_total = nonnegative_int(finalized.get("findings_total"))
    findings_reviewed = nonnegative_int(finalized.get("findings_reviewed"))
    finalized.update(
        {
            "status": terminal_status,
            "fallback": "manual_review_for_unresolved",
            "findings_pending": max(
                nonnegative_int(finalized.get("findings_pending")),
                findings_total - findings_reviewed,
            ),
            "last_update_at": last_update_at,
        }
    )
    if reason_code:
        finalized["reason_code"] = reason_code
    return finalized
