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

        for pattern, desc, severity in SSRF_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1):line_no])

                if _is_defensive_context(content, line_no):
                    severity = "info"
                if scanner._is_code_example(fname, line_no):
                    severity = "low" if severity in ("high", "critical") else severity

                scanner._add_finding(
                    rule_id=rule_id,
                    severity=severity,
                    category="ssrf",
                    title=f"SSRF 风险 — {desc}",
                    description=f"在 {fname} 中发现可能访问内网或云元数据的请求：{match.group()[:80]}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配: {match.group()[:120]}",
                    remediation="使用 URL 白名单限制可访问的地址，禁止访问内网 IP 和云元数据端点。",
                    cwe_id="CWE-918",
                )
