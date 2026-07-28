"""SR-011: Output handling risk detection.

Checks for:
  - Printing sensitive variables (token/key/secret/password)
  - User input directly concatenated into shell commands / file writes
  - Cross-context output (writing outside sandbox)
  - Unbounded output (DoS)
"""

from __future__ import annotations

import re
from typing import Any

from scanners.risk_scanner.patterns import OUTPUT_HANDLING_PATTERNS


def run(scanner: Any) -> None:
    rule_id = "SR-011"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        if not content:
            continue
        lines = content.split("\n")

        for pattern, desc, severity in OUTPUT_HANDLING_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1):line_no])
                if scanner._is_code_example(fname, line_no):
                    severity = "medium" if severity in ("high", "critical") else "low"

                scanner._add_finding(
                    rule_id=rule_id,
                    severity=severity,
                    category="output_handling",
                    title=f"输出处理风险 — {desc}",
                    description=f"在 {fname} 中发现输出处理风险：{match.group()[:80]}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配: {match.group()[:100]}",
                    remediation="使用参数化调用和安全输出方法，避免直接拼接用户输入。",
                    cwe_id="CWE-116",
                )
