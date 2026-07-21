"""SR-004: Hardcoded secrets detection."""

from __future__ import annotations

import re
from typing import Any

from scanners.risk_scanner.patterns import HARDCODED_SECRET_PATTERNS


def run(scanner: Any) -> None:
    rule_id = "SR-004"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        lines = content.split("\n")

        for pattern, desc in HARDCODED_SECRET_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                start_line = max(0, line_no - 1)
                end_line = min(len(lines) - 1, line_no)
                snippet = "\n".join(lines[start_line : end_line + 1])
                safe_snippet = re.sub(pattern, lambda m: m.group()[:8] + "***", snippet)

                scanner._add_finding(
                    rule_id=rule_id,
                    severity="high",
                    category="hardcoded_secret",
                    title=f"硬编码密钥: {desc}",
                    description=f"在 {fname} 中发现硬编码密钥：{desc}",
                    location={"file": fname, "line": line_no, "snippet": safe_snippet[:200]},
                    evidence=f"匹配模式: {pattern}",
                    remediation="将密钥移至环境变量或密钥管理服务，不要硬编码在源码中。",
                    cwe_id="CWE-798",
                )
