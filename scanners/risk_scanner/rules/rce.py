"""SR-005: Remote code execution detection."""

from __future__ import annotations

import re
from typing import Any

from scanners.risk_scanner.patterns import RCE_PATTERNS


def run(scanner: Any) -> None:
    rule_id = "SR-005"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        lines = content.split("\n")

        for pattern, desc in RCE_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                start_line = max(0, line_no - 1)
                end_line = min(len(lines) - 1, line_no)
                snippet = "\n".join(lines[start_line : end_line + 1])

                scanner._add_finding(
                    rule_id=rule_id,
                    severity="high",
                    category="remote_code_execution",
                    title=f"远程代码执行风险: {desc}",
                    description=f"在 {fname} 中发现代码执行模式：{desc}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配模式: {pattern}",
                    remediation="避免使用 eval/exec。如果必须使用 subprocess，使用命令白名单和参数校验。",
                    cwe_id="CWE-94",
                )
