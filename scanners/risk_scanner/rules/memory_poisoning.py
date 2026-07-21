"""SR-013: Memory poisoning detection.

Checks for:
  - Writing to persistent memory/context/history files
  - Manipulating conversation history
  - Injecting into long-term memory storage
"""

from __future__ import annotations

import re
from typing import Any


def run(scanner: Any) -> None:
    rule_id = "SR-013"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        lines = content.split("\n")

        for pattern, desc in [
            (r"(?:write|append|save).*(?:memory|context|history)", "写入记忆/上下文"),
            (r"conversation_history", "操作对话历史"),
            (r"long.?term.*(?:memory|storage)", "操作长期记忆存储"),
            (r"(?:\.claude|\.cursor|skills).*(?:memory|context|history)", "操作 Agent 记忆文件"),
        ]:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1) : line_no])
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="high",
                    category="memory_poisoning",
                    title=f"记忆投毒风险 — {desc}",
                    description=f"在 {fname} 中发现可能篡改持久化记忆/上下文的行为：{match.group()[:80]}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配: {match.group()[:100]}",
                    remediation="Skill 不应写入或修改 AI Agent 的持久化记忆。仅在隔离的作用域内操作。",
                )
