"""Conservative redaction for data that may cross a trust boundary."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Iterator
from datetime import datetime
from functools import cache
from pathlib import Path
from typing import Any

from scanners.risk_scanner.credentials import LiteralRedactions, find_credentials, literal_pattern, mask_literals

_PRIVATE_KEY_BOUNDARY = re.compile(r"-----(BEGIN|END) [A-Z ]*PRIVATE KEY-----")
_BEARER = re.compile(r"(?i)\bBearer(\s+)[A-Za-z0-9._~+/=-]+")
_CONNECTION = re.compile(r"(://[^\s/@:]+:)[^\s/@]+(@)")
_API_KEY = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{22,}|AIza[A-Za-z0-9_-]{35}|do[por]_v1_[a-f0-9]{64}|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{8,})\b")
_SECRET_FIELD = re.compile(r"(?i)(\b(?:password|passwd|secret|token|api[_-]?key|private[_-]?key)\s*[:=]\s*)([^,\s;}]+)")


def credential_redactions(contents: Iterable[str]) -> LiteralRedactions:
    """Recognize once across the full snapshot, including cross-file reuse."""
    return literal_pattern(match.value for content in contents for match in find_credentials(content))


@cache
def _report_schema() -> dict[str, Any]:
    # Read the shipped contract, never a schema from the scanned package.
    path = Path(__file__).resolve().parents[2] / "packages/schema/scan-report.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _schema_options(schema: dict[str, Any]) -> Iterator[dict[str, Any]]:
    if "$ref" in schema:
        target = _report_schema()
        for part in schema["$ref"].removeprefix("#/").split("/"):
            target = target[part.replace("~1", "/").replace("~0", "~")]
        yield from _schema_options(target)
    yield schema
    for keyword in ("allOf", "anyOf", "oneOf"):
        for option in schema.get(keyword, []):
            if isinstance(option, dict):
                yield from _schema_options(option)


def _child_schema(schema: dict[str, Any], key: str | None = None) -> dict[str, Any]:
    children = []
    for option in _schema_options(schema):
        child = (
            option.get("items", {}) if key is None else
            option.get("properties", {}).get(key, option.get("additionalProperties", {}))
        )
        if isinstance(child, dict) and child:
            children.append(child)
    return {"anyOf": children} if len(children) > 1 else children[0] if children else {}


def _protocol_string(value: str, schema: dict[str, Any]) -> bool:
    """Only protect vocabulary at its contract path, not arbitrary metadata."""
    for option in _schema_options(schema):
        if (
            value in option.get("enum", ()) or value == option.get("const")
            or value in option.get("x-redaction-public-values", ())
        ):
            return True
        # Scanner-produced timestamps and digests also have a fixed wire format.
        # File/path patterns intentionally do not qualify for this exemption.
        pattern = option.get("pattern", "")
        if pattern and ("[a-f0-9]" in pattern or "[0-9a-f]" in pattern) and re.fullmatch(pattern, value):
            return True
        if option.get("format") == "date-time":
            try:
                datetime.fromisoformat(value)
                return True
            except ValueError:
                pass
    return False


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
    value = mask_literals(value, literal_pattern(match.value for match in find_credentials(value)))
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


def redact_value(
    value: Any, *, literal_redactions: LiteralRedactions | None = None,
    _schema: dict[str, Any] | None = None,
) -> Any:
    schema = _schema or {}
    if isinstance(value, str):
        if _protocol_string(value, schema):
            return value
        return redact_text(mask_literals(value, literal_redactions))
    if isinstance(value, list):
        item_schema = _child_schema(schema)
        return [redact_value(item, literal_redactions=literal_redactions, _schema=item_schema) for item in value]
    if isinstance(value, dict):
        result: dict[Any, Any] = {}
        for key, item in value.items():
            output_key = redact_identifier(key) if isinstance(key, str) else key
            item_schema = _child_schema(schema, key)
            if isinstance(item, str) and _protocol_string(item, item_schema):
                result[output_key] = item
            elif key in {"id", "scan_id", "rule_id", "root_cause_id", "fingerprint"} and isinstance(item, str) and re.fullmatch(
                r"(?:finding-[0-9a-f]{8,12}|scan-[0-9a-f]{12}|SR-\d{3}[a-z]?|root-[0-9a-f]{20}|hmac-sha256:[0-9a-f]{32})", item,
            ):
                result[output_key] = item
            elif key in {"file", "source_file", "source_ref"} and isinstance(item, str):
                result[output_key] = redact_identifier(mask_literals(item, literal_redactions))
            elif key == "top_finding_files" and isinstance(item, dict):
                result[output_key] = {
                    redact_identifier(mask_literals(path, literal_redactions)): redact_value(count, literal_redactions=literal_redactions)
                    for path, count in item.items()
                }
            elif key == "code_context" and isinstance(item, str):
                result[output_key] = redact_source_context(mask_literals(item, literal_redactions))
            elif re.search(r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key)", str(key)):
                result[output_key] = "[REDACTED]"
            else:
                result[output_key] = redact_value(item, literal_redactions=literal_redactions, _schema=item_schema)
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


def redact_report(report: dict[str, Any], *, literal_redactions: LiteralRedactions | None = None) -> dict[str, Any]:
    """Return a recursively redacted report copy."""
    return redact_value(report, literal_redactions=literal_redactions, _schema=_report_schema())


def redact_finding(finding: dict[str, Any], *, literal_redactions: LiteralRedactions | None = None) -> dict[str, Any]:
    """Use the same contract before LLM review as at the report boundary."""
    return redact_value(
        finding, literal_redactions=literal_redactions,
        _schema=_report_schema()["properties"]["findings"]["items"],
    )
