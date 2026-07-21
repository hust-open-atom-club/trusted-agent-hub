"""SR-002: Dangerous shell command detection."""

from __future__ import annotations

import re
from typing import Any

from scanners.risk_scanner.patterns import DANGEROUS_SHELL_PATTERNS


def run(scanner: Any) -> None:
    rule_id = "SR-002"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        lines = content.split("\n")

        for pattern, desc in DANGEROUS_SHELL_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                start_line = max(0, line_no - 1)
                end_line = min(len(lines) - 1, line_no)
                snippet = "\n".join(lines[start_line : end_line + 1])

                if any(kw in pattern for kw in ("rm -rf", "sudo", "mkfs", "dd if=")):
                    severity = "critical"
                elif "|" in pattern and "sh" in pattern:
                    severity = "critical"
                else:
                    severity = "high"

                scanner._add_finding(
                    rule_id=rule_id,
                    severity=severity,
                    category="dangerous_shell",
                    title=f"危险 Shell 命令: {desc}",
                    description=f"在 {fname} 中发现危险 Shell 命令：{desc}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:300]},
                    evidence=f"匹配模式: {pattern}",
                    remediation="避免在 Skill 中使用危险 Shell 命令。如需执行 Shell，请使用命令白名单限制。",
                    cwe_id="CWE-78",
                )
