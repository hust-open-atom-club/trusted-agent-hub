"""SR-001b: Anti-refusal mechanism detection (merged into prompt injection category)."""

from __future__ import annotations

import re
from typing import Any

from scanners.risk_scanner.patterns import ANTI_REFUSAL_PATTERNS


def run(scanner: Any) -> None:
    target_files = ["SKILL.md", "README.md", "INSTRUCTIONS.md", "PROMPT.md"]
    rule_id = "SR-001b"

    for fname in target_files:
        full = scanner.target_dir / fname
        if not full.is_file():
            continue

        content = scanner._read_file_content(fname)
        lines = content.split("\n")

        for pattern, desc in ANTI_REFUSAL_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                start_line = max(0, line_no - 1)
                end_line = min(len(lines) - 1, line_no)
                snippet = "\n".join(lines[start_line : end_line + 1])

                scanner._add_finding(
                    rule_id=rule_id,
                    severity="critical",
                    category="prompt_injection",
                    title=f"反拒绝风险: {desc}",
                    description=f"在 {fname} 中发现反拒绝模式：{desc}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配模式: {pattern}",
                    remediation="移除试图禁止 AI 拒绝执行的指令。Skill 应尊重模型的安全限制。",
                    cwe_id="CWE-77",
                )
