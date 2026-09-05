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
    max_lines: int = 60,
    max_bytes_per_finding: int = 8192,
    max_total_bytes: int = 64 * 1024,
) -> dict[str, str]:
    """Return redacted source excerpts for backward-compatible callers."""
    contexts, _ = build_finding_context_bundle(
        findings,
        file_cache,
        max_lines=max_lines,
        max_bytes_per_finding=max_bytes_per_finding,
        max_total_bytes=max_total_bytes,
    )
    return contexts


def _reviewable_finding(finding: dict[str, Any]) -> bool:
    review_severity = str(
        finding.get("candidate_severity")
        or finding.get("static_severity")
        or finding.get("severity", "")
    ).lower()
    semantic_candidate = finding.get("requires_llm_validation") is True
    adjudication_candidate = finding.get("llm_adjudication_eligible") is True
    return review_severity in {"critical", "high"} or (
        (semantic_candidate or adjudication_candidate)
        and review_severity == "medium"
    )


def _finding_locations(finding: dict[str, Any]) -> list[tuple[str, int]]:
    candidates: list[dict[str, Any]] = []
    location = finding.get("location")
    if isinstance(location, dict):
        candidates.append(location)
    for hit in finding.get("detector_hits") or []:
        if isinstance(hit, dict) and isinstance(hit.get("location"), dict):
            candidates.append(hit["location"])
    occurrences = finding.get("occurrences") or {}
    if isinstance(occurrences, dict):
        candidates.extend(
            item
            for item in occurrences.get("items") or []
            if isinstance(item, dict)
        )

    locations: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for item in candidates:
        file_path = str(item.get("file") or "")
        try:
            line = max(1, int(item.get("line", 1) or 1))
        except (TypeError, ValueError):
            line = 1
        key = (file_path, line)
        if file_path and key not in seen:
            seen.add(key)
            locations.append(key)
    return locations


def _truncate_utf8(value: str, max_bytes: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value, False
    return encoded[:max_bytes].decode("utf-8", errors="ignore"), True


def build_finding_context_bundle(
    findings: list[dict[str, Any]],
    file_cache: dict[str, str],
    *,
    max_lines: int = 60,
    max_locations_per_finding: int = 4,
    max_bytes_per_finding: int = 8192,
    max_total_bytes: int = 64 * 1024,
) -> tuple[dict[str, str], dict[str, Any]]:
    """Build review excerpts plus an explicit, non-secret coverage audit.

    ``delivery_status=complete`` means every scanner-referenced location was
    delivered without transport truncation. It does not claim that the whole
    source file was sent; ``source_line_coverage`` and ``full_file_included``
    make that distinction visible to reviewers and report consumers.
    """
    contexts: dict[str, str] = {}
    finding_audits: dict[str, dict[str, Any]] = {}
    total = 0
    for finding in findings:
        if not _reviewable_finding(finding):
            continue
        fid = str(finding.get("id", ""))
        if not fid:
            continue

        all_locations = _finding_locations(finding)
        selected_locations = all_locations[:max_locations_per_finding]
        reasons: list[str] = []
        if len(all_locations) > len(selected_locations):
            reasons.append("location_limit")

        excerpts: list[str] = []
        ranges: list[dict[str, Any]] = []
        source_line_keys: set[tuple[str, int]] = set()
        source_file_lines: dict[str, int] = {}
        transport_truncated = False
        for file_path, line in selected_locations:
            content = file_cache.get(file_path)
            if content is None:
                reasons.append(f"source_missing:{file_path}")
                continue
            lines = content.splitlines()
            source_file_lines[file_path] = len(lines)
            if not lines:
                reasons.append(f"source_empty:{file_path}")
                continue
            half = max_lines // 2
            start = max(0, min(line - 1, len(lines) - 1) - half)
            end = min(len(lines), start + max_lines)
            start = max(0, end - max_lines)
            excerpt = "\n".join(
                f"{idx + 1}: {lines[idx]}" for idx in range(start, end)
            )
            excerpt = redact_text(excerpt)
            header = (
                f"[SOURCE file={file_path} lines={start + 1}-{end} "
                f"total_lines={len(lines)}]"
            )
            candidate = f"{header}\n{excerpt}"
            used = sum(len(item.encode("utf-8")) + 2 for item in excerpts)
            per_finding_remaining = max(0, max_bytes_per_finding - used)
            total_remaining = max(0, max_total_bytes - total - used)
            allowance = min(per_finding_remaining, total_remaining)
            candidate, truncated = _truncate_utf8(
                candidate,
                allowance,
            )
            if truncated:
                transport_truncated = True
                reasons.append(
                    "per_finding_byte_limit"
                    if per_finding_remaining <= total_remaining
                    else "total_byte_limit"
                )
            if not candidate:
                break
            delivered_lines = [
                int(value)
                for value in re.findall(r"(?m)^(\d+):", candidate)
            ]
            if not delivered_lines:
                transport_truncated = True
                reasons.append("source_lines_not_delivered")
                break
            excerpts.append(candidate)
            ranges.append({
                "file": file_path,
                "start_line": min(delivered_lines),
                "end_line": max(delivered_lines),
            })
            source_line_keys.update(
                (file_path, source_line) for source_line in delivered_lines
            )
            if truncated:
                break

        context = "\n\n".join(excerpts)
        encoded_size = len(context.encode("utf-8"))
        if context:
            contexts[fid] = context
            total += encoded_size

        requested = len(all_locations)
        included = len(ranges)
        if not context or included == 0:
            delivery_status = "missing"
        elif included < requested or transport_truncated:
            delivery_status = "partial"
        else:
            delivery_status = "complete"
        total_source_lines = sum(source_file_lines.values())
        finding_audits[fid] = {
            "delivery_status": delivery_status,
            "requested_locations": requested,
            "included_locations": included,
            "files": sorted(source_file_lines),
            "line_ranges": ranges,
            "included_line_count": len(source_line_keys),
            "total_source_lines": total_source_lines,
            "source_line_coverage": (
                round(len(source_line_keys) / total_source_lines, 4)
                if total_source_lines
                else 0.0
            ),
            "full_file_included": bool(source_file_lines) and all(
                any(
                    item["file"] == file_path
                    and item["start_line"] == 1
                    and item["end_line"] == line_count
                    for item in ranges
                )
                for file_path, line_count in source_file_lines.items()
            ),
            "context_bytes": encoded_size,
            "transport_truncated": transport_truncated,
            "reasons": sorted(set(reasons)),
        }

    statuses = [item["delivery_status"] for item in finding_audits.values()]
    audit = {
        "findings": finding_audits,
        "summary": {
            "candidates": len(finding_audits),
            "complete": statuses.count("complete"),
            "partial": statuses.count("partial"),
            "missing": statuses.count("missing"),
            "total_context_bytes": total,
            "max_total_bytes": max_total_bytes,
        },
    }
    return contexts, audit
