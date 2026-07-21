"""SR-016: Tool misuse detection.

Checks for:
  - Parameter injection in descriptions
  - Tool name impersonation
  - Unicode homoglyph / zero-width character attacks
  - Hidden instructions in tool metadata
"""

from __future__ import annotations

import re
from typing import Any


TOOL_MISUSE_PATTERNS: list[tuple[str, str, str]] = [
    (r'(?:tool_name|toolName)\s*[=:]\s*["\'](?:Read|Write|Bash|Grep|Glob|WebFetch)', "伪装已有工具名称", "high"),
    (r'description\s*[=:].*"(?:ignore|bypass|skip)', "在参数描述中隐藏指令", "high"),
    (r'\\u[0-9a-fA-F]{4}', "Unicode 转义（可能同形异义攻击）", "medium"),
    (r'\\x[0-9a-fA-F]{2}', "十六进制转义序列", "low"),
    (r'[\u200b\u200c\u200d\u2060\uFEFF]', "零宽字符", "high"),
]


def run(scanner: Any) -> None:
    rule_id = "SR-016"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        lines = content.split("\n")

        for pattern, desc, severity in TOOL_MISUSE_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1) : line_no])
                scanner._add_finding(
                    rule_id=rule_id,
                    severity=severity,
                    category="tool_misuse",
                    title=f"工具滥用风险 — {desc}",
                    description=f"在 {fname} 中发现可能工具滥用的模式：{match.group()[:80]}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配: {repr(match.group()[:60])}",
                    remediation="移除隐藏指令和 Unicode 伪装。工具参数仅用于声明式配置，不应包含执行指令。",
                )
