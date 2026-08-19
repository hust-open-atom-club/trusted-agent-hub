"""SR-015: Agent snooping detection.

Checks for:
  - Reading other agent/skill directories
  - Scanning .claude/.cursor directories
  - Reading conversation history
  - MCP config file access
  - Cross-agent filesystem enumeration
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from scanners.risk_scanner.patterns import AGENT_SNOOPING_PATTERNS

# 指代「当前对话」的措辞——技能正文里引用本次对话（如 "earlier in this
# conversation"）属于正常技能行为，不是读取对话历史文件。
_CONVERSATION_REFERENCE_PHRASES: tuple[str, ...] = (
    "in this conversation",
    "in the conversation",
    "in our conversation",
    "in that conversation",
    "of this conversation",
    "of the conversation",
    "during this conversation",
    "during the conversation",
)


def _is_conversation_reference(line_text: str) -> bool:
    """命中行是指代当前对话的措辞 → 跳过（非窥探行为）。"""
    lowered = line_text.lower()
    return any(phrase in lowered for phrase in _CONVERSATION_REFERENCE_PHRASES)


def run(scanner: Any) -> None:
    rule_id = "SR-015"

    for fname in scanner.scanned_files:
        ext = Path(fname).suffix.lower()
        if ext in (".html", ".htm", ".css", ".svg"):
            continue

        content = scanner._read_file_content(fname)
        if not content:
            continue
        lines = content.split("\n")

        for pattern, desc, severity in AGENT_SNOOPING_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                line_text = lines[line_no - 1]
                if _is_conversation_reference(line_text):
                    continue
                snippet = "\n".join(lines[max(0, line_no - 1):line_no])
                if scanner._is_code_example(fname, line_no):
                    severity = "medium" if severity == "high" else severity

                scanner._add_finding(
                    rule_id=rule_id,
                    severity=severity,
                    category="agent_snooping",
                    title=f"Agent 窥探风险 — {desc}",
                    description=f"在 {fname} 中发现可能读取其他 Agent 数据的行为：{match.group()[:80]}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配: {match.group()[:100]}",
                    remediation="Skill 不应读取其他 Skill 或 Agent 的数据。仅访问自身目录内的文件。",
                )
