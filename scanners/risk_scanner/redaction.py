"""Conservative redaction for data that may cross a trust boundary."""

from __future__ import annotations

import hashlib
import re
from typing import Any


_PRIVATE_KEY_BOUNDARY = re.compile(r"-----(BEGIN|END) [A-Z ]*PRIVATE KEY-----")
_BEARER = re.compile(r"(?i)\bBearer(\s+)[A-Za-z0-9._~+/=-]+")
_CONNECTION = re.compile(r"(://[^\s/@:]+:)[^\s/@]+(@)")
_API_KEY = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|AKIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9_]{20,})\b")
_SECRET_FIELD = re.compile(r"(?i)(\b(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*)([^,\s;}]+)")


def _redact_private_keys(value: str) -> str:
    # Visit each delimiter once. Repeated BEGIN markers without END must not
    # restart a full-tail regex search; an unfinished block is secret too.
    pieces: list[str] = []
    cursor = 0
    start: int | None = None

    def mask(first: int, last: int) -> str:
        newlines = value.count("\n", first, last)
        result = "[REDACTED_PRIVATE_KEY]" + "\n" * newlines
        # Keep the final source line when a block ends at EOF without a newline.
        # Otherwise splitlines() would silently discard that now-empty line.
        if newlines and value[last - 1] != "\n":
            result += "[REDACTED_PRIVATE_KEY]"
        return result

    for boundary in _PRIVATE_KEY_BOUNDARY.finditer(value):
        if boundary[1] == "BEGIN" and start is None:
            start = boundary.start()
        elif boundary[1] == "END" and start is not None:
            pieces.extend((
                value[cursor:start],
                mask(start, boundary.end()),
            ))
            cursor, start = boundary.end(), None
    if start is not None:
        pieces.extend((
            value[cursor:start],
            mask(start, len(value)),
        ))
        cursor = len(value)
    pieces.append(value[cursor:])
    return "".join(pieces)


def redact_text(value: str) -> str:
    value = _redact_private_keys(value)
    value = _BEARER.sub(lambda match: "Bearer" + match[1] + "[REDACTED]", value)
    value = _CONNECTION.sub(r"\1[REDACTED]\2", value)
    value = _API_KEY.sub("[REDACTED_SECRET]", value)
    return _SECRET_FIELD.sub(r"\1[REDACTED]", value)


def contains_sensitive_identifier(value: object) -> bool:
    return isinstance(value, str) and _API_KEY.search(value) is not None


def redact_identifier(value: str) -> str:
    """Preserve ordinary identifiers; replace credential tokens with stable digests."""
    return _API_KEY.sub(
        lambda match: "[REDACTED_" + hashlib.sha256(match[0].encode()).hexdigest() + "]",
        value,
    )


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, dict):
        result: dict[Any, Any] = {}
        for key, item in value.items():
            output_key = redact_identifier(key) if isinstance(key, str) else key
            if key in {"file", "source_file", "source_ref"} and isinstance(item, str):
                result[output_key] = redact_identifier(item)
            elif key == "top_finding_files" and isinstance(item, dict):
                result[output_key] = {
                    redact_identifier(path): redact_value(count)
                    for path, count in item.items()
                }
            elif key == "code_context" and isinstance(item, str):
                result[output_key] = redact_source_context(item)
            elif re.search(r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key)", str(key)):
                result[output_key] = "[REDACTED]"
            else:
                result[output_key] = redact_value(item)
        return result
    return value


def redact_source_context(context: str) -> str:
    """Redact payloads while preserving source headers and numbered lines."""
    output: list[str] = []
    pending: list[tuple[str, str]] = []

    def flush() -> None:
        if pending:
            redacted = redact_text("\n".join(text for _, text in pending)).split("\n")
            output.extend(f"{number}: {text}" for (number, _), text in zip(pending, redacted))
            pending.clear()

    for raw in context.split("\n"):
        source = re.fullmatch(r"(\d+):(?: (.*))?", raw)
        if source:
            pending.append((source[1], source[2] or ""))
        else:
            flush()
            output.append(
                redact_identifier(raw) if raw.startswith("[SOURCE file=") else redact_text(raw)
            )
    flush()
    return "\n".join(output)


def redact_report(report: dict[str, Any]) -> dict[str, Any]:
    """Return a recursively redacted report copy."""
    return redact_value(report)
