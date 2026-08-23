"""SR-005: Remote code execution detection (regex layer).

For AST-level analysis (import alias resolution, reflective calls, dynamic import chains),
see behavioral_ast.py which runs alongside this rule.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from scanners.risk_scanner.patterns import RCE_PATTERNS


def run(scanner: Any) -> None:
    rule_id = "SR-005"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        if not content:
            continue
        lines = content.split("\n")

        for pattern, desc, severity in RCE_PATTERNS:
            if "execfile()" in desc and Path(fname).suffix.lower() != ".py":
                continue
            flags = 0 if "execfile()" in desc else re.IGNORECASE
            for match in re.finditer(pattern, content, flags):
                line_no = content[: match.start()].count("\n") + 1
                start_line = max(0, line_no - 1)
                end_line = min(len(lines) - 1, line_no)
                snippet = "\n".join(lines[start_line : end_line + 1])

                finding_severity = severity
                context = ""
                if "child_process.exec()" in desc:
                    event = _javascript_call_at(
                        scanner,
                        fname,
                        line_no,
                        match.start(),
                        match.end(),
                    )
                    if event is not None:
                        if event.dynamic:
                            finding_severity = "high"
                            context = f"；输入来源={event.input_source}"
                        elif not event.dynamic:
                            finding_severity = "medium"
                            context = "；命令参数为固定值，仍需确认是否必要"

                if scanner._is_code_example(fname, line_no):
                    finding_severity = "medium" if finding_severity in ("high", "critical") else "low"

                scanner._add_finding(
                    rule_id=rule_id,
                    severity=finding_severity,
                    category="remote_code_execution",
                    title=f"远程代码执行风险: {desc}",
                    description=f"在 {fname} 中发现代码执行模式：{desc}{context}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配模式: {match.group()[:120]}{context}",
                    remediation="避免使用 eval/exec。如果必须使用 subprocess，使用命令白名单和参数校验。",
                    cwe_id="CWE-94",
                )


def _javascript_call_at(
    scanner: Any,
    filename: str,
    line: int,
    start_offset: int = 0,
    end_offset: int | None = None,
) -> Any | None:
    """Return the structured JS call fact for a source location, if present."""
    analysis = getattr(getattr(scanner, "analysis", None), "javascript_ast", {}) or {}
    file_analysis = analysis.get(filename)
    if file_analysis is None:
        return None
    content = scanner._read_file_content(filename)
    line_start = content.rfind("\n", 0, start_offset) + 1
    start_column = start_offset - line_start
    end_column = (
        end_offset if end_offset is not None else start_offset + 1
    ) - line_start
    candidates = [
        event
        for event in file_analysis.calls
        if (
            event.line == line
            and event.shell_capable
            and start_column <= event.column < end_column
        )
    ]
    return min(candidates, key=lambda event: event.column, default=None)
