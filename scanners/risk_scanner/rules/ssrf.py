"""SR-014: SSRF detection.

Checks for:
  - Internal network IP access (192.168.x, 10.x, 172.16-31.x)
  - localhost / 127.0.0.1 / 0.0.0.0 / [::1] access
  - Cloud metadata endpoint access (AWS 169.254.169.254, GCP metadata.google.internal)
  - Dynamic request target (string concatenation in URL)
  - Defensive context filtering (documentation examples)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from scanners.risk_scanner.analyzers.url_context import (
    URL_USAGE_COMPARISON,
    URL_USAGE_LOCAL_REFERENCE,
    URL_USAGE_NETWORK_REQUEST,
    URL_USAGE_STATIC_ASSET,
    classify_url_usage,
    request_controlled_aliases,
)
from scanners.risk_scanner.patterns import SSRF_DEFENSIVE_CONTEXT_WORDS, SSRF_PATTERNS


def _is_defensive_context(content: str, line_no: int) -> bool:
    lines = content.split("\n")
    start = max(0, line_no - 4)
    end = min(len(lines), line_no + 3)
    context = "\n".join(lines[start:end]).lower()
    return any(kw in context for kw in SSRF_DEFENSIVE_CONTEXT_WORDS)


def run(scanner: Any) -> None:
    rule_id = "SR-014"

    for fname in scanner.scanned_files:
        ext = Path(fname).suffix.lower()
        if ext in (".html", ".htm", ".css", ".svg", ".md", ".markdown"):
            continue

        content = scanner._read_file_content(fname)
        if not content:
            continue
        lines = content.split("\n")

        _report_dynamic_request_targets(scanner, fname, content, lines)

        for pattern, desc, severity in SSRF_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1):line_no])
                usage = classify_url_usage(content, line_no, match.group())

                is_metadata = "元数据" in desc
                is_loopback = any(value in desc for value in (
                    "localhost", "127.0.0.1", "0.0.0.0", "IPv6 localhost",
                ))
                if is_loopback:
                    # A literal loopback address describes a local service or
                    # comparison. SSRF requires attacker influence over the
                    # request destination, which this match does not prove.
                    continue
                if usage in {
                    URL_USAGE_COMPARISON,
                    URL_USAGE_LOCAL_REFERENCE,
                    URL_USAGE_STATIC_ASSET,
                }:
                    continue
                if not is_metadata and "内网 IP" in desc and usage != URL_USAGE_NETWORK_REQUEST:
                    continue

                finding_severity = severity
                if _is_defensive_context(content, line_no):
                    finding_severity = "info"
                if scanner._is_code_example(fname, line_no):
                    continue

                if is_metadata:
                    semantic = {
                        "kind": "vulnerability",
                        "disposition": "confirmed_vulnerability",
                        "sink_kind": "network_request",
                        "sink_symbol": "cloud_metadata_endpoint",
                        "source_kind": "fixed_sensitive_endpoint",
                        "source_control": "package_author",
                        "reachability": "runtime_reachable",
                        "activation": "direct",
                        "trust_boundary_crossed": True,
                        "preconditions": ["runtime has access to the instance metadata network"],
                    }
                else:
                    semantic = {
                        "kind": "context_dependent",
                        "disposition": "needs_context",
                        "sink_kind": "network_request",
                        "source_kind": "fixed_internal_endpoint",
                        "source_control": "package_author",
                        "reachability": "runtime_reachable",
                        "activation": "conditional",
                        "trust_boundary_crossed": True,
                        "requires_manual_review": True,
                    }

                scanner._add_finding(
                    rule_id=rule_id,
                    severity=finding_severity,
                    category="ssrf",
                    title=f"SSRF 风险 — {desc}",
                    description=f"在 {fname} 中发现可能访问内网或云元数据的请求：{match.group()[:80]}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配: {match.group()[:120]}",
                    remediation="使用 URL 白名单限制可访问的地址，禁止访问内网 IP 和云元数据端点。",
                    cwe_id="CWE-918",
                    **semantic,
                )


def _report_dynamic_request_targets(
    scanner: Any,
    filename: str,
    content: str,
    lines: list[str],
) -> None:
    analysis = getattr(getattr(scanner, "analysis", None), "javascript_ast", {}) or {}
    file_analysis = analysis.get(filename)
    if file_analysis is None:
        return
    aliases = request_controlled_aliases(content)
    for event in file_analysis.calls:
        if event.kind != "network":
            continue
        line_no = int(event.line)
        line = lines[max(0, line_no - 1)] if lines else ""
        source = str(event.input_source)
        if source == "variable" and any(
            re.search(rf"\b{re.escape(event.calling)}\s*\(\s*{re.escape(alias)}\b", line)
            for alias in aliases
        ):
            source = "user_input"
        if source != "user_input":
            continue
        scanner._add_finding(
            rule_id="SR-014",
            severity="high",
            category="ssrf",
            title="SSRF 风险 — 不可信请求目标",
            description=f"在 {filename} 中，请求字段控制了 {event.calling}() 的目标地址。",
            location={"file": filename, "line": line_no, "snippet": line[:200]},
            evidence=f"structured network call={event.calling}; input_source=request",
            remediation="不要直接请求客户端提供的 URL；解析后按协议、主机和解析 IP 执行白名单校验。",
            cwe_id="CWE-918",
            kind="vulnerability",
            disposition="confirmed_vulnerability",
            sink_kind="network_request",
            sink_symbol=str(event.calling),
            source_kind="request",
            source_control="remote_attacker",
            reachability="request_reachable",
            activation="direct",
            trust_boundary_crossed=True,
        )
