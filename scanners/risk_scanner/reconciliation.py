"""Normalize detector hits into stable, score-facing root findings.

Rules intentionally remain high-recall detectors.  This module is the single
boundary where their immutable observations are grouped into issues that can
be reviewed and scored.  It keeps the raw detector evidence attached to every
root finding so later semantic review never has to overwrite the original
severity or provenance of a match.
"""

from __future__ import annotations

import hashlib
import re
from copy import deepcopy
from typing import Any


SEVERITY_RANK = {"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

_CATEGORY_FAMILY = {
    "dangerous_shell": "command_execution",
    "remote_code_execution": "command_execution",
    "output_handling": "command_execution",
    "installation_security": "installation",
    "supply_chain": "supply_chain",
    "network_access": "network",
    "ssrf": "network",
    "credential_access": "credential_access",
    "hardcoded_secret": "credential_access",
}

_SINK_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "download_execute",
        re.compile(r"(?:curl|wget).{0,200}(?:\||;|&&)\s*(?:ba)?sh\b", re.I),
    ),
    (
        "shell_exec",
        re.compile(
            r"(?:child_process\s*\.\s*exec|\bcp\s*\.\s*exec|\bexec\s*\(|"
            r"\bos\s*\.\s*system|\bos\s*\.\s*popen|\bsubprocess\s*\.\s*"
            r"(?:run|call|Popen)|shell\s*=\s*True)",
            re.I,
        ),
    ),
    (
        "dynamic_eval",
        re.compile(r"(?:^|[^.\w])(?:eval|exec)\s*\(", re.I),
    ),
    (
        "network_request",
        re.compile(r"(?:\bfetch|requests\s*\.|https?\s*\.\s*(?:get|request))\s*\(", re.I),
    ),
    (
        "filesystem_delete",
        re.compile(r"(?:\brm\s+-|\bunlink\s*\(|\brmtree\s*\(|\bremove\s*\()", re.I),
    ),
)

_SOURCE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("request", re.compile(r"\b(?:request|req)\s*\.\s*(?:query|body|params|path)\b", re.I)),
    ("environment", re.compile(r"\b(?:process\s*\.\s*env|os\s*\.\s*environ|getenv)\b", re.I)),
    ("user_input", re.compile(r"\b(?:user[_-]?input|input\s*\()", re.I)),
)


def _normalized_text(value: object, *, limit: int = 240) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def _finding_text(finding: dict[str, Any]) -> str:
    location = finding.get("location") or {}
    return " ".join(
        _normalized_text(value)
        for value in (
            location.get("snippet"),
            finding.get("evidence"),
            finding.get("title"),
            finding.get("description"),
        )
        if value
    )


def _infer_sink_kind(finding: dict[str, Any]) -> str:
    explicit = str(finding.get("sink_kind") or "").strip()
    if explicit:
        return explicit
    text = _finding_text(finding)
    for name, pattern in _SINK_PATTERNS:
        if pattern.search(text):
            return name
    category = str(finding.get("category") or "unknown")
    return _CATEGORY_FAMILY.get(category, category)


def _infer_source_kind(finding: dict[str, Any]) -> str:
    explicit = str(finding.get("source_kind") or "").strip()
    if explicit:
        return explicit
    text = _finding_text(finding)
    for name, pattern in _SOURCE_PATTERNS:
        if pattern.search(text):
            return name
    return "unknown"


def _severity(finding: dict[str, Any], field: str, fallback: str = "info") -> str:
    value = str(finding.get(field) or fallback).lower()
    return value if value in SEVERITY_RANK else "info"


def _static_severity(finding: dict[str, Any]) -> str:
    return _severity(
        finding,
        "static_severity",
        str(finding.get("candidate_severity") or finding.get("severity") or "info"),
    )


def _effective_severity(finding: dict[str, Any]) -> str:
    return _severity(
        finding,
        "effective_severity",
        str(finding.get("severity") or _static_severity(finding)),
    )


def _location_parts(finding: dict[str, Any]) -> tuple[str, int, int]:
    location = finding.get("location") or {}
    file_name = str(location.get("file") or "(unknown)").replace("\\", "/")
    try:
        line_start = max(0, int(location.get("line") or 0))
    except (TypeError, ValueError):
        line_start = 0
    try:
        line_end = max(line_start, int(location.get("end_line") or line_start))
    except (TypeError, ValueError):
        line_end = line_start
    return file_name, line_start, line_end


def _root_material(finding: dict[str, Any]) -> str:
    explicit = _normalized_text(finding.get("root_cause_key"), limit=500)
    if explicit:
        return f"explicit:{explicit}"

    file_name, line_start, line_end = _location_parts(finding)
    sink_kind = _infer_sink_kind(finding)
    source_kind = _infer_source_kind(finding)
    sink_symbol = _normalized_text(finding.get("sink_symbol"), limit=120).lower()
    source_symbol = _normalized_text(finding.get("source_symbol"), limit=120).lower()

    # A precise source span plus semantic sink/source identity is the safest
    # cross-rule grouping boundary.  Findings without a line retain a compact
    # evidence discriminator so unrelated manifest advisories do not collapse.
    discriminator = ""
    if line_start == 0:
        discriminator = _normalized_text(finding.get("evidence"), limit=160).lower()
    return "|".join(
        (
            file_name,
            str(line_start),
            str(line_end),
            sink_kind,
            source_kind,
            sink_symbol,
            source_symbol,
            discriminator,
        )
    )


def _root_cause_id(finding: dict[str, Any]) -> str:
    digest = hashlib.sha256(_root_material(finding).encode("utf-8")).hexdigest()
    return f"root-{digest[:20]}"


def _detector_hit(finding: dict[str, Any]) -> dict[str, Any]:
    hit: dict[str, Any] = {
        "id": str(finding.get("id") or ""),
        "rule_id": str(finding.get("rule_id") or "UNKNOWN"),
        "static_severity": _static_severity(finding),
        "effective_severity": _effective_severity(finding),
        "category": str(finding.get("category") or "unknown"),
        "sink_kind": _infer_sink_kind(finding),
        "source_kind": _infer_source_kind(finding),
        "location": deepcopy(finding.get("location") or {}),
    }
    for key in ("evidence", "remediation", "cwe_id", "requires_confirmation"):
        if finding.get(key) not in (None, "", False):
            hit[key] = deepcopy(finding[key])
    return hit


def _occurrences(hits: list[dict[str, Any]], max_items: int) -> dict[str, Any]:
    unique: dict[tuple[str, int], dict[str, Any]] = {}
    for hit in hits:
        location = hit.get("location") or {}
        file_name = str(location.get("file") or "(unknown)")
        try:
            line = max(0, int(location.get("line") or 0))
        except (TypeError, ValueError):
            line = 0
        key = (file_name, line)
        if key in unique:
            continue
        item: dict[str, Any] = {"file": file_name}
        if line:
            item["line"] = line
        unique[key] = item
    items = list(unique.values())
    return {
        "count": len(items),
        "items": items[:max_items],
        "truncated": len(items) > max_items,
    }


def reconcile_findings(
    findings: list[dict[str, Any]], *, max_occurrence_items: int = 100
) -> list[dict[str, Any]]:
    """Return stable root findings without mutating detector output."""
    groups: dict[str, list[dict[str, Any]]] = {}
    order: list[str] = []
    for finding in findings:
        root_id = str(finding.get("root_cause_id") or _root_cause_id(finding))
        if root_id not in groups:
            groups[root_id] = []
            order.append(root_id)
        groups[root_id].append(deepcopy(finding))

    roots: list[dict[str, Any]] = []
    for root_id in order:
        members = groups[root_id]
        members.sort(
            key=lambda item: (
                -SEVERITY_RANK[_effective_severity(item)],
                -SEVERITY_RANK[_static_severity(item)],
                str(item.get("rule_id") or ""),
                str(item.get("id") or ""),
            )
        )
        primary = deepcopy(members[0])
        hits = [_detector_hit(member) for member in members]
        static_severity = max(
            (_static_severity(member) for member in members),
            key=lambda value: SEVERITY_RANK[value],
        )
        effective_severity = max(
            (_effective_severity(member) for member in members),
            key=lambda value: SEVERITY_RANK[value],
        )

        primary["id"] = f"finding-{root_id.removeprefix('root-')[:12]}"
        primary["root_cause_id"] = root_id
        primary["detector_ids"] = sorted({hit["rule_id"] for hit in hits})
        primary["detector_hits"] = hits
        primary["sink_kind"] = _infer_sink_kind(primary)
        primary["source_kind"] = _infer_source_kind(primary)
        primary["static_severity"] = static_severity
        primary["effective_severity"] = effective_severity
        primary["severity"] = effective_severity  # v1 compatibility projection
        primary["kind"] = str(primary.get("kind") or "unclassified")
        primary["disposition"] = str(primary.get("disposition") or "pending")
        primary["occurrences"] = _occurrences(hits, max_occurrence_items)
        if any(member.get("requires_llm_validation") is True for member in members):
            primary["requires_llm_validation"] = True
        if any(member.get("requires_manual_review") is True for member in members):
            primary["requires_manual_review"] = True
        roots.append(primary)

    return roots
