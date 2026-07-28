"""SR-001: Prompt Injection + Anti-Refusal Detection (merged).

Checks ALL files in the package for prompt injection and anti-refusal patterns.
Uses is_code_example() to reduce false positives in documentation code blocks.
"""

from __future__ import annotations

import re
from typing import Any

from scanners.risk_scanner.patterns import PROMPT_INJECTION_PATTERNS


_SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _downgrade_severity(severity: str) -> str:
    if severity == "critical":
        return "high"
    if severity == "high":
        return "medium"
    if severity == "medium":
        return "low"
    return "info"


def run(scanner: Any) -> None:
    rule_id = "SR-001"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        if not content:
            continue
        lines = content.split("\n")

        for pattern, desc, default_severity in PROMPT_INJECTION_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                start_line = max(0, line_no - 1)
                end_line = min(len(lines) - 1, line_no)
                snippet = "\n".join(lines[start_line : end_line + 1])

                severity = default_severity
                if scanner._is_code_example(fname, line_no):
                    severity = _downgrade_severity(severity)

                category = "prompt_injection"

                scanner._add_finding(
                    rule_id=rule_id,
                    severity=severity,
                    category=category,
                    title=f"提示注入风险: {desc}",
                    description=f"在 {fname} 中发现提示注入/反拒绝模式：{desc}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配模式: {pattern}",
                    remediation="移除或重写该指令。确保 Skill 不会试图绕过 AI 模型的安全限制。",
                    cwe_id="CWE-77",
                )
