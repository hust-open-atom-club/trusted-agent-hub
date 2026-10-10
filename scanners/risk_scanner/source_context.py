"""Bounded, line-preserving delivery of finding evidence to reviewers."""

from __future__ import annotations

from typing import Any

from scanners.risk_scanner.evidence import (
    evidence_reason_code,
    finding_locations,
    normalize_file_path,
    normalize_finding_evidence,
    positive_integer,
    summarize_context_audits,
)
from scanners.risk_scanner.llm_candidates import is_semantic_candidate
from scanners.risk_scanner.redaction import credential_redactions, redact_text
from scanners.risk_scanner.credentials import LiteralRedactions, mask_literals


DEFAULT_FINDING_CONTEXT_BYTES = 8192
DEFAULT_CONTEXT_BATCH_BYTES = 64 * 1024


class FindingContextSources:
    """One immutable source snapshot with lazy indexes/redaction per review run."""

    def __init__(
        self, file_cache: dict[str, str], *, literal_redactions: LiteralRedactions | None = None,
    ) -> None:
        self.files: dict[str, str] = {}
        self.conflicts: set[str] = set()
        self.indexes: dict[str, dict[str, dict[str, int]]] = {}
        self._lines: dict[str, list[str]] = {}
        for raw_path, content in file_cache.items():
            path = normalize_file_path(raw_path)
            if path and isinstance(content, str):
                if path in self.files and self.files[path] != content:
                    self.conflicts.add(path)
                self.files[path] = content
        for path in self.conflicts:
            self.files.pop(path, None)
        self._literal_redactions = (
            literal_redactions if literal_redactions is not None else credential_redactions(self.files.values())
        )

    def redacted_lines(self, path: str) -> list[str]:
        if path not in self._lines:
            self._lines[path] = redact_text(mask_literals(self.files[path], self._literal_redactions)).splitlines()
        return self._lines[path]


def build_finding_context_bundle(
    findings: list[dict[str, Any]],
    file_cache: dict[str, str] | FindingContextSources,
    *,
    max_lines: int = 60,
    max_locations_per_finding: int = 4,
    max_bytes_per_finding: int = DEFAULT_FINDING_CONTEXT_BYTES,
    max_total_bytes: int = DEFAULT_CONTEXT_BATCH_BYTES,
) -> tuple[dict[str, str], dict[str, Any]]:
    sources = (
        file_cache if isinstance(file_cache, FindingContextSources)
        else FindingContextSources(file_cache)
    )
    files, conflicts, indexes = sources.files, sources.conflicts, sources.indexes

    contexts: dict[str, str] = {}
    audits: dict[str, dict[str, Any]] = {}
    total = 0
    for finding in findings:
        if not is_semantic_candidate(finding):
            continue
        normalize_finding_evidence(finding, files, indexes)
        fid = str(finding["id"])
        locations = finding_locations(finding)
        selected = locations[:max(0, max_locations_per_finding)]
        reasons: set[str] = set()
        codes: set[str] = set()
        if not locations:
            reasons.add(str(finding.get("evidence_missing_reason") or "missing_location"))
            codes.add(evidence_reason_code(
                str(finding.get("evidence_missing_reason") or "missing_location")
            ))
        occurrences = finding.get("occurrences") or {}
        omitted = max(
            0,
            int(occurrences.get("count", 0)) - len(occurrences.get("items") or []),
        )
        if len(selected) < len(locations) or occurrences.get("truncated") or omitted:
            reasons.add("location_limit")
            codes.add("context_budget")
        if finding.get("evidence_missing_reason"):
            path = (finding.get("location") or {}).get("file", "")
            reasons.add(f"{finding['evidence_missing_reason']}:{path}")
            codes.add(evidence_reason_code(finding["evidence_missing_reason"]))

        excerpts: list[str] = []
        ranges: list[dict[str, Any]] = []
        delivered: set[tuple[str, int]] = set()
        source_lengths: dict[str, int] = {}
        included = 0
        used = 0
        for location in selected:
            path = location["file"]
            content = files.get(path)
            if content is None:
                reasons.add(f"source_missing:{path}")
                if path in conflicts:
                    reasons.add(f"source_cache_conflict:{path}")
                codes.add("source_missing")
                continue
            if location.get("missing_reason"):
                reason = location["missing_reason"]
                reasons.add(f"{reason}:{path}")
                codes.add(evidence_reason_code(reason))
                continue
            # Redact before numbering; redact_text preserves every newline.
            lines = sources.redacted_lines(path)
            source_lengths[path] = len(lines)
            line = positive_integer(location.get("line"))
            last = positive_integer(location.get("end_line")) or line
            if line is None or last is None or last < line or last > len(lines):
                reasons.add(f"source_span_missing:{path}")
                codes.add("location_unresolved")
                continue
            width = max(1, max_lines)
            start = max(1, line - max(0, (width - (last - line + 1)) // 2))
            end = min(len(lines), start + width - 1)
            header = f"[SOURCE file={path} lines={start}-{end} total_lines={len(lines)}]"
            separator = 2 if excerpts else 0
            finding_remaining = max_bytes_per_finding - used
            total_remaining = max_total_bytes - total - used
            allowance = min(finding_remaining, total_remaining) - separator
            payload = [header]
            payload_bytes = len(header.encode("utf-8"))
            included_lines = []
            for number in range(start, end + 1):
                text = f"{number}: {lines[number - 1]}"
                size = len(text.encode("utf-8")) + 1
                if payload_bytes + size > allowance:
                    reasons.add(
                        "per_finding_byte_limit"
                        if finding_remaining <= total_remaining
                        else "total_byte_limit"
                    )
                    codes.add("context_budget")
                    break
                payload.append(text)
                payload_bytes += size
                included_lines.append(number)
            # A partial line is never evidence. Even a numbered prefix would
            # make the citation validator trust bytes that were never sent.
            if not included_lines:
                reasons.add(f"delivery_missing:{path}:{line}")
                codes.add("delivery_missing")
                continue
            payload[0] = (
                f"[SOURCE file={path} lines={start}-{included_lines[-1]} "
                f"total_lines={len(lines)}]"
            )
            excerpt = "\n".join(payload)
            excerpts.append(excerpt)
            used += len(excerpt.encode("utf-8")) + separator
            ranges.append({
                "file": path,
                "start_line": start,
                "end_line": included_lines[-1],
            })
            delivered.update((path, number) for number in included_lines)
            if all((path, number) in delivered for number in range(line, last + 1)):
                included += 1
            else:
                reasons.add(f"delivery_missing:{path}:{line}-{last}")
                codes.add("delivery_missing")
                if last > end:
                    reasons.add("line_limit")
                    codes.add("context_budget")

        context = "\n\n".join(excerpts)
        if context:
            contexts[fid] = context
            total += used
        if not context:
            status = "missing"
        elif codes or included < len(locations):
            status = "partial"
        else:
            status = "complete"
        if status != "complete":
            finding["llm_context_status"] = status
            finding["llm_context_reasons"] = sorted(codes)
            finding["requires_manual_review"] = True
        total_lines = sum(source_lengths.values())
        audits[fid] = {
            "delivery_status": status,
            "requested_locations": len(locations) + omitted,
            "included_locations": included,
            "locations": locations,
            "files": sorted({item["file"] for item in locations}),
            "line_ranges": ranges,
            "included_line_count": len(delivered),
            "total_source_lines": total_lines,
            "source_line_coverage": (
                round(len(delivered) / total_lines, 4) if total_lines else 0.0
            ),
            "full_file_included": (
                status == "complete"
                and bool(source_lengths)
                and len(delivered) == total_lines
            ),
            "context_bytes": used,
            "transport_truncated": "context_budget" in codes,
            "reasons": sorted(reasons),
            "reason_codes": sorted(codes),
        }
    return contexts, {
        "findings": audits,
        "summary": {
            **summarize_context_audits(audits),
            "max_total_bytes": max_total_bytes,
        },
    }
