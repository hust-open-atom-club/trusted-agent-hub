"""Conservative redaction for data that may cross a trust boundary."""

from __future__ import annotations

import re
from typing import Any

_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_CONNECTION = re.compile(r"(?i)([a-z][a-z0-9+.-]*://[^\s/@:]+:)[^\s/@]+(@)")
_API_KEY = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9_]{20,})\b")
_SECRET_FIELD = re.compile(r"(?i)(\b(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*)([^,\s;}]+)")


def redact_text(value: str) -> str:
    value = _PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", value)
    value = _BEARER.sub("Bearer [REDACTED]", value)
    value = _CONNECTION.sub(r"\1[REDACTED]\2", value)
    value = _API_KEY.sub("[REDACTED_SECRET]", value)
    return _SECRET_FIELD.sub(r"\1[REDACTED]", value)


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, dict):
        result: dict[Any, Any] = {}
        for key, item in value.items():
            if re.search(r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key)", str(key)):
                result[key] = "[REDACTED]"
            else:
                result[key] = redact_value(item)
        return result
    return value


def redact_report(report: dict[str, Any]) -> dict[str, Any]:
    """Return a recursively redacted report copy."""
    return redact_value(report)


def build_finding_contexts(
    findings: list[dict[str, Any]],
    file_cache: dict[str, str],
    *,
    max_lines: int = 20,
    max_bytes_per_finding: int = 4096,
    max_total_bytes: int = 32 * 1024,
) -> dict[str, str]:
    contexts: dict[str, str] = {}
    total = 0
    for finding in findings:
        review_severity = str(
            finding.get("candidate_severity") or finding.get("severity", "")
        ).lower()
        is_semantic_candidate = finding.get("requires_llm_validation") is True
        if review_severity not in {"critical", "high"} and not (
            is_semantic_candidate and review_severity == "medium"
        ):
            continue
        fid = str(finding.get("id", ""))
        location = finding.get("location", {}) or {}
        content = file_cache.get(str(location.get("file", "")), "")
        if not fid or not content:
            continue
        line = max(1, int(location.get("line", 1) or 1))
        lines = content.splitlines()
        half = max_lines // 2
        start = max(0, line - 1 - half)
        end = min(len(lines), start + max_lines)
        context = "\n".join(f"{idx + 1}: {lines[idx]}" for idx in range(start, end))
        context = redact_text(context)[:max_bytes_per_finding]
        encoded_size = len(context.encode("utf-8"))
        if total + encoded_size > max_total_bytes:
            break
        contexts[fid] = context
        total += encoded_size
    return contexts
