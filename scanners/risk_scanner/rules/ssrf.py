"""SR-014: SSRF detection.

Checks for:
  - Internal network IP access (192.168.x, 10.x, 172.16-31.x)
  - localhost / 127.0.0.1 / 0.0.0.0 / [::1] access
  - Cloud metadata endpoint access (AWS 169.254.169.254, GCP metadata.google.internal)
"""

from __future__ import annotations

import re
from typing import Any


SSRF_PATTERNS: list[tuple[str, str, str]] = [
    (r"https?://(?:192\.168\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.)", "访问内网 IP", "high"),
    (r"https?://localhost\b", "访问 localhost", "high"),
    (r"https?://127\.0\.0\.1\b", "访问 127.0.0.1", "high"),
    (r"169\.254\.169\.254", "访问 AWS 云元数据端点", "critical"),
    (r"metadata\.google\.internal", "访问 GCP 云元数据端点", "critical"),
    (r"https?://0\.0\.0\.0", "访问 0.0.0.0", "medium"),
    (r"https?://\[::1\]", "访问 IPv6 localhost", "medium"),
]


def run(scanner: Any) -> None:
    rule_id = "SR-014"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        lines = content.split("\n")

        for pattern, desc, severity in SSRF_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1) : line_no])
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
