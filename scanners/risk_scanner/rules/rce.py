"""SR-005: Remote code execution detection (regex layer).

For AST-level analysis (import alias resolution, reflective calls, dynamic import chains),
see behavioral_ast.py which runs alongside this rule.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from scanners.risk_scanner.analyzers.url_context import request_controlled_aliases
from scanners.risk_scanner.patterns import RCE_PATTERNS


def run(scanner: Any) -> None:
    rule_id = "SR-005"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        if not content:
            continue
        lines = content.split("\n")
        javascript_analysis = _javascript_analysis(scanner, fname)

        if javascript_analysis is not None:
            _report_javascript_shell_calls(scanner, fname, content, javascript_analysis)

        for pattern, desc, severity in RCE_PATTERNS:
            if "execfile()" in desc and Path(fname).suffix.lower() != ".py":
                continue
            flags = 0 if "execfile()" in desc else re.IGNORECASE
            for match in re.finditer(pattern, content, flags):
                line_no = content[: match.start()].count("\n") + 1
                if scanner._is_code_example(fname, line_no):
                    # Ordinary documentation is inert input. The capability
                    # exists in the example, not in the scanned package.
                    continue
                if "child_process.exec()" in desc and javascript_analysis is not None:
                    # Structured events cover aliases, source context, and
                    # multiple calls on one line more accurately than regex.
                    continue
                start_line = max(0, line_no - 1)
                end_line = min(len(lines) - 1, line_no)
                snippet = "\n".join(lines[start_line : end_line + 1])

                finding_severity = severity
                context = ""
                semantic = _generic_execution_semantics(desc, snippet)
                if semantic["kind"] == "context_dependent":
                    finding_severity = "medium"
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
                    **semantic,
                )


def _javascript_analysis(scanner: Any, filename: str) -> Any | None:
    analysis = getattr(getattr(scanner, "analysis", None), "javascript_ast", {}) or {}
    return analysis.get(filename)


def _event_line(content: str, event: Any) -> str:
    lines = content.splitlines()
    index = max(0, int(getattr(event, "line", 1)) - 1)
    return lines[index] if index < len(lines) else ""


def _variable_is_request_controlled(content: str, event: Any) -> bool:
    line = _event_line(content, event)
    aliases = request_controlled_aliases(content)
    return any(
        re.search(rf"\.exec\s*\(\s*{re.escape(alias)}\b", line)
        for alias in aliases
    )


def _report_javascript_shell_calls(
    scanner: Any,
    filename: str,
    content: str,
    analysis: Any,
) -> None:
    for event in analysis.calls:
        if event.kind != "process" or not event.shell_capable:
            continue
        line_no = int(event.line)
        if scanner._is_code_example(filename, line_no):
            continue

        source = str(event.input_source)
        if source == "literal":
            # A fixed command is an executable capability, but no untrusted
            # source reaches it. The capability graph records it.
            continue
        if source == "variable" and _variable_is_request_controlled(content, event):
            source = "user_input"

        line = _event_line(content, event)
        if source == "user_input":
            severity = "critical"
            kind = "vulnerability"
            disposition = "confirmed_vulnerability"
            source_kind = "request"
            source_control = "remote_attacker"
            reachability = "request_reachable"
            activation = "direct"
            trust_boundary_crossed = True
            requires_manual_review = False
            context = "未经验证的请求输入可到达 shell"
            preconditions = ["attacker can supply the request field"]
        elif source == "environment":
            severity = "medium"
            kind = "context_dependent"
            disposition = "needs_context"
            source_kind = "environment"
            source_control = "operator"
            reachability = "deployment_configuration"
            activation = "conditional"
            trust_boundary_crossed = False
            requires_manual_review = True
            context = "命令来自部署者环境变量，需核对配置所有权与用途"
            preconditions = ["operator configures the command environment variable"]
        else:
            severity = "medium"
            kind = "context_dependent"
            disposition = "needs_context"
            source_kind = "unknown"
            source_control = "unknown"
            reachability = "unknown"
            activation = "conditional"
            trust_boundary_crossed = None
            requires_manual_review = True
            context = "命令来源无法由当前静态分析证明"
            preconditions = ["runtime value reaches the shell-capable call"]

        scanner._add_finding(
            rule_id="SR-005",
            severity=severity,
            category="remote_code_execution",
            title="Shell 命令执行数据流",
            description=f"在 {filename} 中发现 {event.calling}()：{context}。",
            location={"file": filename, "line": line_no, "snippet": line[:200]},
            evidence=f"structured call={event.calling}; input_source={source}",
            remediation="避免让不可信输入到达 shell；优先使用固定可执行文件、参数数组和显式白名单。",
            cwe_id="CWE-78",
            kind=kind,
            disposition=disposition,
            sink_kind="shell_exec",
            sink_symbol=str(event.calling),
            source_kind=source_kind,
            source_control=source_control,
            reachability=reachability,
            activation=activation,
            trust_boundary_crossed=trust_boundary_crossed,
            preconditions=preconditions,
            requires_manual_review=requires_manual_review,
        )


def _generic_execution_semantics(description: str, snippet: str) -> dict[str, Any]:
    request_controlled = bool(re.search(
        r"\b(?:request|req)\s*\.|\buser[_-]?input\b",
        snippet,
        re.IGNORECASE,
    ))
    if request_controlled:
        return {
            "kind": "vulnerability",
            "disposition": "confirmed_vulnerability",
            "sink_kind": "shell_exec" if "system" in description.lower() else "dynamic_eval",
            "source_kind": "request",
            "source_control": "remote_attacker",
            "reachability": "request_reachable",
            "activation": "direct",
            "trust_boundary_crossed": True,
        }
    return {
        "kind": "context_dependent",
        "disposition": "needs_context",
        "sink_kind": "shell_exec" if any(
            value in description.lower() for value in ("system", "subprocess", "popen", "exec*")
        ) else "dynamic_eval",
        "source_kind": "unknown",
        "source_control": "unknown",
        "reachability": "unknown",
        "activation": "conditional",
        "requires_manual_review": True,
    }


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
