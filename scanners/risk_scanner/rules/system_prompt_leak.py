"""SR-012: System prompt leakage detection.

Checks for:
  - Reading system prompt files
  - Sending system prompt to external URLs
  - Referencing system instructions in output
"""

from __future__ import annotations

import re
from typing import Any


def run(scanner: Any) -> None:
    rule_id = "SR-012"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        lines = content.split("\n")

        for pattern, desc in [
            (r"system\s*(?:prompt|instruction|message)", "引用系统提示"),
            (r"(?:read|print|output|send).*\bsystem\s*prompt", "读取/发送系统提示"),
        ]:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1) : line_no])
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="high",
                    category="system_prompt_leakage",
                    title=f"系统提示泄漏风险 — {desc}",
                    description=f"在 {fname} 中发现可能读取或泄露系统提示的代码：{match.group()[:80]}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配: {match.group()[:100]}",
                    remediation="不要读取或输出系统提示。系统提示是 AI 模型的安全边界。",
                )

        for pattern, desc in [
            (r"prompt\s*=\s*open\s*\(", "打开文件读取 prompt"),
            (r"(?:fetch|post|request|send)\s*\(.*system\s*prompt", "通过网络发送系统提示"),
        ]:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1) : line_no])
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="critical",
                    category="system_prompt_leakage",
                    title=f"系统提示泄漏风险 — {desc}",
                    description=f"在 {fname} 中发现读取或发送系统提示的行为：{match.group()[:80]}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配: {match.group()[:100]}",
                    remediation="不要在 Skill 中操作 AI 模型的系统提示。这是严重的隐私和安全风险。",
                )
