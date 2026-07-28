"""SR-013: Memory poisoning detection.

Checks for:
  - Writing to persistent memory/context/history files
  - Manipulating conversation history
  - Long-term memory storage injection
  - Context window stuffing (massive repeated content)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from scanners.risk_scanner.patterns import MEMORY_POISONING_PATTERNS


def run(scanner: Any) -> None:
    rule_id = "SR-013"

    for fname in scanner.scanned_files:
        ext = Path(fname).suffix.lower()
        if ext in (".html", ".htm", ".css", ".svg"):
            continue

        content = scanner._read_file_content(fname)
        if not content:
            continue
        lines = content.split("\n")

        for pattern, desc, severity in MEMORY_POISONING_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1):line_no])
                if scanner._is_code_example(fname, line_no):
                    severity = "medium" if severity == "high" else severity

                scanner._add_finding(
                    rule_id=rule_id,
                    severity=severity,
                    category="memory_poisoning",
                    title=f"记忆投毒风险 — {desc}",
                    description=f"在 {fname} 中发现可能篡改持久化记忆/上下文的行为：{match.group()[:80]}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配: {match.group()[:100]}",
                    remediation="Skill 不应写入或修改 AI Agent 的持久化记忆。仅在隔离的作用域内操作。",
                )
