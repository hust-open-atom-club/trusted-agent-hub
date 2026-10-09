"""Canonical, repository-relative evidence identities shared by all consumers.

Lines and columns are one-based and inclusive. ``source_ref`` is a JSON
Pointer fragment (``#/...``) for structured evidence, never a guessed file.
"""

from __future__ import annotations

import hashlib
import json
import re
from bisect import bisect_right
from collections import Counter
from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from packages.schema.constants import MAX_EVIDENCE_SOURCE_REF_LENGTH
from scanners.risk_scanner.redaction import contains_sensitive_identifier


def source_reference(value: str) -> dict[str, Any]:
    """Keep an exact identifier, or an explicit omission with a stable digest."""
    if contains_sensitive_identifier(value):
        return {
            "source_ref_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
            "missing_reason": "sensitive_identifier",
        }
    if len(value) <= MAX_EVIDENCE_SOURCE_REF_LENGTH:
        return {"source_ref": value}
    return {
        "source_ref_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "source_ref_length": len(value),
        "missing_reason": "source_ref_too_long",
    }


def source_reference_label(value: str) -> str:
    reference = source_reference(value)
    if reference.get("source_ref"):
        return reference["source_ref"]
    length = (
        f"; length={reference['source_ref_length']}"
        if "source_ref_length" in reference else ""
    )
    return f"[{reference['missing_reason']}; sha256={reference['source_ref_sha256']}{length}]"


def evidence_reason_code(reason: str) -> str:
    if reason == "sensitive_identifier":
        return "evidence_redacted"
    if reason == "source_ref_too_long":
        return "evidence_limit"
    if reason in {"missing_line", "invalid_span", "line_out_of_range"}:
        return "location_unresolved"
    return "source_missing"


def normalize_file_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or value in {"unknown", "(unknown)"}:
        return None
    path = value.replace("\\", "/")
    if path.startswith("/") or ":" in path or re.search(r"[\x00-\x1f\x7f]", path):
        return None
    parts = path.split("/")
    if ".." in parts:
        return None
    normalized = "/".join(part for part in parts if part not in {"", "."})
    return normalized if normalized and normalized not in {"unknown", "(unknown)"} else None


def positive_integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def metadata_location(
    scanner: Any, field: str | tuple[str | int, ...] | None = None,
) -> dict[str, Any]:
    """Use loader provenance. A string is one key; tuples are nested paths."""
    tokens = (field,) if isinstance(field, str) else field or ()
    if hasattr(scanner, "_metadata_source_file"):
        path = scanner._metadata_source_file
    else:
        # Compatibility for rule integrations that expose only the snapshot.
        files = getattr(scanner, "_file_contents", getattr(scanner, "files", {}))
        path = next((name for name in ("manifest.json", "plugin.json", "SKILL.md", "package.json") if name in files), None)
    if tokens:
        path = getattr(scanner, "_metadata_field_sources", {}).get(tokens[0], path)
    path = normalize_file_path(path)
    if not path:
        return {}
    location = {"file": path}
    if tokens and path.endswith(".json"):
        pointer = "#/" + "/".join(
            str(token).replace("~", "~0").replace("/", "~1") for token in tokens
        )
        location.update(source_reference(pointer))
    return location


def normalize_location(value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    raw_path = value.get("file") or value.get("source_file")
    if contains_sensitive_identifier(raw_path):
        return {}
    path = normalize_file_path(raw_path)
    if path is None:
        return {}
    location = deepcopy(dict(value))
    location.pop("source_file", None)
    location["file"] = path
    reference = location.get("source_ref")
    if isinstance(reference, str):
        location.pop("source_ref")
        location.update(source_reference(reference))
    for field in (location.get("field_locations") or {}).values():
        reference = field.get("source_ref")
        if isinstance(reference, str):
            field.pop("source_ref")
            field.update(source_reference(reference))
        if field.get("missing_reason") in {"source_ref_too_long", "sensitive_identifier"}:
            location.setdefault("missing_reason", field["missing_reason"])
    for field in ("line", "end_line", "column", "end_column"):
        number = positive_integer(location.get(field))
        if number is None:
            location.pop(field, None)
        else:
            location[field] = number
    return location


def _missing_location_reason(value: object) -> str:
    path = (value.get("file") or value.get("source_file")) if isinstance(value, Mapping) else None
    if contains_sensitive_identifier(path):
        return "sensitive_identifier"
    return "invalid_path" if path else "missing_location"


def finding_location(finding: Mapping[str, Any]) -> dict[str, Any]:
    """Read the canonical field; accept the historical flat projection once."""
    if isinstance(finding.get("location"), Mapping):
        return normalize_location(finding["location"])
    return normalize_location({"file": finding.get("file"), "line": finding.get("line")})


def location_key(location: Mapping[str, Any]) -> tuple[object, ...]:
    return (
        location.get("file"), location.get("line"),
        location.get("end_line") or location.get("line"),
        location.get("column"), location.get("end_column"), location.get("source_ref"),
        location.get("source_ref_sha256"),
    )


def finding_locations(finding: Mapping[str, Any]) -> list[dict[str, Any]]:
    candidates = [finding_location(finding)]
    candidates.extend(finding_location(hit) for hit in finding.get("detector_hits") or [] if isinstance(hit, Mapping))
    occurrences = finding.get("occurrences") or {}
    if isinstance(occurrences, Mapping):
        candidates.extend(normalize_location(item) for item in occurrences.get("items") or [])
    unique = {location_key(item): item for item in candidates if item}
    return list(unique.values())


def delivered_source_lines(context: str, audit: Mapping[str, Any] | None) -> dict[tuple[str, int], str]:
    ranges = (audit or {}).get("line_ranges") or []
    files = {item.get("file") for item in ranges if isinstance(item, Mapping) and item.get("file")}
    current = next(iter(files)) if len(files) == 1 else None
    result: dict[tuple[str, int], str] = {}
    conflicts: set[tuple[str, int]] = set()
    for raw in context.splitlines():
        header = re.fullmatch(r"\[SOURCE file=(.+) lines=\d+-\d+ total_lines=\d+\]", raw)
        if header:
            current = normalize_file_path(header[1])
            continue
        source = re.fullmatch(r"(\d+):(?: (.*))?", raw)
        if not source or not current:
            continue
        number = int(source[1])
        if not any(
            item.get("file") == current
            and (positive_integer(item.get("start_line")) or 0) <= number
            <= (positive_integer(item.get("end_line")) or 0)
            for item in ranges if isinstance(item, Mapping)
        ):
            continue
        key, text = (current, number), source[2] or ""
        if key in result and result[key] != text:
            conflicts.add(key)
        result[key] = text
    return {key: value for key, value in result.items() if key not in conflicts}


def json_source_spans(content: str) -> dict[str, dict[str, int]]:
    """Index JSON tokens by pointer, including repeated values/nested records.

    Decode strings with the standard library so escaped keys cannot be confused
    with textual lookalikes. Reject duplicate keys rather than choosing a span.
    """
    decoder = json.JSONDecoder()
    offsets: dict[str, tuple[int, int]] = {}
    newlines = [-1, *(m.start() for m in re.finditer("\n", content))]

    def whitespace(pos: int) -> int:
        while pos < len(content) and content[pos] in " \t\r\n":
            pos += 1
        return pos

    def visit(pos: int, pointer: str) -> int:
        start = pos = whitespace(pos)
        if len(pointer) > MAX_EVIDENCE_SOURCE_REF_LENGTH:
            # Do not duplicate a package-controlled key for every child field.
            _, end = decoder.raw_decode(content, pos)
            return end
        if content[pos] in "{[":
            is_object = content[pos] == "{"
            close = "}" if is_object else "]"
            pos = whitespace(pos + 1)
            keys: set[str] = set()
            index = 0
            while content[pos] != close:
                if is_object:
                    key, pos = decoder.raw_decode(content, pos)
                    if not isinstance(key, str) or key in keys:
                        raise ValueError("ambiguous JSON key")
                    keys.add(key)
                    pos = whitespace(pos)
                    if content[pos] != ":":
                        raise ValueError("missing colon")
                    pos += 1
                    token = key.replace("~", "~0").replace("/", "~1")
                else:
                    token = str(index)
                pos = whitespace(visit(pos, f"{pointer}/{token}"))
                index += 1
                if content[pos] == close:
                    break
                if content[pos] != ",":
                    raise ValueError("missing comma")
                pos = whitespace(pos + 1)
                if content[pos] == close:
                    raise ValueError("trailing comma")
            pos += 1
        else:
            _, pos = decoder.raw_decode(content, pos)
        offsets[pointer] = (start, pos - 1)
        return pos

    try:
        if whitespace(visit(0, "#")) != len(content):
            return {}
    except (ValueError, IndexError, RecursionError):
        return {}
    spans = {}
    for pointer, (start, end) in offsets.items():
        line = bisect_right(newlines, start)
        end_line = bisect_right(newlines, end)
        spans[pointer] = {
            "line": line, "end_line": end_line,
            "column": start - newlines[line - 1],
            "end_column": end - newlines[end_line - 1],
        }
    return spans


def _resolve_location_evidence(
    location: dict[str, Any],
    files: Mapping[str, str] | None,
    indexes: dict[str, dict[str, dict[str, int]]] | None,
) -> str | None:
    """Resolve one normalized location; return its missing-evidence reason."""
    source_ref = location.get("source_ref")
    structured = isinstance(source_ref, str) and source_ref.startswith("#/")
    path = location["file"]
    content = files.get(path) if files is not None else None
    if files is not None and not isinstance(content, str):
        return "source_missing"
    if location.get("missing_reason"):
        return location["missing_reason"]
    missing_reason = None
    if structured and content is not None:
        indexes = indexes if indexes is not None else {}
        if path not in indexes:
            indexes[path] = json_source_spans(content)
        spans = indexes[path]
        span = spans.get(source_ref)
        if span is None:
            # A stale line must not stand in for an unresolved structured field.
            for field in ("line", "end_line", "column", "end_column"):
                location.pop(field, None)
            return "field_missing"
        location.update(span)
        if location.get("dependency_name"):
            fields = {}
            for field in ("version", "resolved", "integrity"):
                pointer = f"{source_ref}/{field}"
                field_span = spans.get(pointer)
                # package.json dependency values are version declarations.
                if field == "version" and not field_span and path.rsplit("/", 1)[-1] == "package.json":
                    pointer, field_span = source_ref, span
                reference = source_reference(pointer)
                if reference.get("missing_reason"):
                    fields[field] = reference
                    missing_reason = reference["missing_reason"]
                else:
                    fields[field] = (
                        {**reference, **field_span} if field_span
                        else {**reference, "missing_reason": "field_missing"}
                    )
            location["field_locations"] = fields
    if location.get("line"):
        location.setdefault("end_line", location["line"])
        if location["end_line"] < location["line"]:
            return "invalid_span"
        elif content is not None and location["end_line"] > len(content.splitlines()):
            return "line_out_of_range"
    return missing_reason


def normalize_occurrence_evidence(
    items: list[dict[str, Any]],
    files: Mapping[str, str],
    indexes: dict[str, dict[str, dict[str, int]]],
) -> tuple[list[dict[str, Any]], str | None]:
    """Copy valid locations, retaining evidence gaps without empty placeholders."""
    locations = []
    first_missing_reason = None
    for item in items:
        location = normalize_location(item)
        if location:
            reason = _resolve_location_evidence(location, files, indexes)
            if not reason and item.get("line") is not None and not location.get("line"):
                reason = "invalid_span"
            if reason:
                location["missing_reason"] = reason
            locations.append(location)
        else:
            reason = _missing_location_reason(item)
        if reason and first_missing_reason is None:
            first_missing_reason = reason
    return locations, first_missing_reason


def _review_already_adjudicated(finding: Mapping[str, Any]) -> bool:
    """Whether the LLM already recorded a decision for this finding.

    An evidence gap is established by the scanner, but the manual-review
    requirement it implies can afterwards be cleared by the adjudicator.  The
    adjudication fields are the only durable record of that decision in a
    persisted report, so they make re-normalization idempotent instead of
    silently restoring a review flag the reviewer deliberately cleared.
    """
    action = finding.get("llm_adjudication_action")
    if isinstance(action, str) and action:
        return True
    state = finding.get("llm_review_state")
    return isinstance(state, str) and state not in {"", "pending"}


def normalize_finding_evidence(
    finding: dict[str, Any],
    files: Mapping[str, str] | None = None,
    indexes: dict[str, dict[str, dict[str, int]]] | None = None,
) -> None:
    """Normalize in place at generation; preserve explicit absence in reports.

    Escalation to manual review is authoritative only at generation time.  A
    finding that already carries an adjudication decision keeps that decision,
    so re-aggregating or re-rendering a reviewed report cannot reopen it.
    """
    raw = finding.get("location")
    location = finding_location(finding)
    finding["location"] = location
    if not location:
        finding.setdefault("evidence_type", "synthetic")
        reason = _missing_location_reason(raw if isinstance(raw, Mapping) else finding)
        finding.setdefault("evidence_missing_reason", reason)
        if not _review_already_adjudicated(finding):
            finding["requires_manual_review"] = True
        return
    source_ref = location.get("source_ref")
    structured = isinstance(source_ref, str) and source_ref.startswith("#/")
    dependency = location.get("dependency_name") or (
        structured and source_ref.startswith((
            "#/packages/", "#/dependencies/", "#/devDependencies/", "#/optionalDependencies/",
        ))
    )
    evidence_type = "dependency" if dependency else "source" if structured or location.get("line") else "file"
    finding.setdefault("evidence_type", evidence_type)
    if files is not None:
        finding.pop("evidence_missing_reason", None)
    reason = _resolve_location_evidence(location, files, indexes)
    if reason:
        finding["evidence_missing_reason"] = reason
    elif not location.get("line") and finding["evidence_type"] != "file":
        finding.setdefault("evidence_missing_reason", "missing_line")
    elif not location.get("line") and isinstance(raw, Mapping) and raw.get("line") is not None:
        finding["evidence_type"] = "source"
        finding["evidence_missing_reason"] = "invalid_span"
    if finding.get("evidence_missing_reason") and not _review_already_adjudicated(
        finding
    ):
        finding["requires_manual_review"] = True


def summarize_context_audits(audits: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Count reasons by finding, even when several locations share a failure."""
    states = Counter(str(item.get("delivery_status", "missing")) for item in audits.values())
    reasons: Counter[str] = Counter()
    files: Counter[str] = Counter()
    for item in audits.values():
        reasons.update(set(item.get("reason_codes") or []))
        files.update({loc["file"] for loc in item.get("locations") or [] if loc.get("file")})
    return {
        "candidates": len(audits),
        **{state: states[state] for state in ("complete", "partial", "missing")},
        **{reason: reasons[reason] for reason in (
            "source_missing", "location_unresolved", "evidence_limit",
            "context_budget", "delivery_missing",
        )},
        "reason_counts": dict(sorted(reasons.items())),
        "top_finding_files": dict(files.most_common(20)),
        "total_context_bytes": sum(int(item.get("context_bytes", 0)) for item in audits.values()),
    }
