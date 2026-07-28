"""SR-016: Tool misuse detection.

Checks for:
  - Parameter injection in descriptions
  - Tool name impersonation
  - Unicode homoglyph / zero-width character attacks
  - Chaining abuse (multiple tool calls combined)
  - Unsafe defaults (TLS verification disabled)
  - Privileged Kubernetes workload
"""

from __future__ import annotations

import re
from typing import Any

from scanners.risk_scanner.patterns import TOOL_MISUSE_PATTERNS


def run(scanner: Any) -> None:
    rule_id = "SR-016"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        if not content:
            continue
        lines = content.split("\n")

        for pattern, desc, severity in TOOL_MISUSE_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1):line_no])
                if scanner._is_code_example(fname, line_no):
                    severity = "medium" if severity in ("high", "critical") else severity

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
