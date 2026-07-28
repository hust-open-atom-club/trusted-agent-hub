"""SR-012: System prompt leakage detection.

Checks for:
  - Reading system prompt files
  - Sending system prompt to external URLs
  - Indirect extraction (rephrase/summarize)
  - Tool-based exfiltration (write to file / network)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from scanners.risk_scanner.patterns import SYSTEM_PROMPT_LEAK_PATTERNS


def run(scanner: Any) -> None:
    rule_id = "SR-012"

    for fname in scanner.scanned_files:
        ext = Path(fname).suffix.lower()
        if ext in (".html", ".htm", ".css", ".svg"):
            continue

        content = scanner._read_file_content(fname)
        if not content:
            continue
        lines = content.split("\n")

        for pattern, desc, severity in SYSTEM_PROMPT_LEAK_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1):line_no])
                if scanner._is_code_example(fname, line_no):
                    severity = "medium" if severity == "critical" else severity

                scanner._add_finding(
                    rule_id=rule_id,
                    severity=severity,
                    category="system_prompt_leakage",
                    title=f"系统提示泄漏风险 — {desc}",
                    description=f"在 {fname} 中发现可能读取或泄露系统提示的代码：{match.group()[:80]}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配: {match.group()[:100]}",
                    remediation="不要读取或输出系统提示。系统提示是 AI 模型的安全边界。",
                )
