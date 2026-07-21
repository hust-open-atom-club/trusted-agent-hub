"""SR-015: Agent snooping detection.

Checks for:
  - Reading other skill directories
  - Scanning .claude/.cursor directories
  - Reading conversation history
  - Walking filesystem for user data
"""

from __future__ import annotations

import re
from typing import Any


AGENT_SNOOPING_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?:read|list|walk|scan).*(?:\.claude|\.cursor)", "读取 Agent 配置目录", "high"),
    (r"listdir.*(?:\.claude|\.cursor|skills)", "列举其他 skill 目录", "high"),
    (r"conversation.*(?:history|log)", "读取对话历史", "high"),
    (r"read.*(?:conversation|chat|message).*(?:history|log|file)", "读取聊天记录", "high"),
    (r"(?:glob|walk|list).*conversation", "遍历对话目录", "high"),
]


def run(scanner: Any) -> None:
    rule_id = "SR-015"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        lines = content.split("\n")

        for pattern, desc, severity in AGENT_SNOOPING_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1) : line_no])
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
