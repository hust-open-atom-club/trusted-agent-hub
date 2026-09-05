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
from pathlib import Path
from typing import Any

from packages.schema.permission_semantics import analyze_delete_operations
from scanners.risk_scanner.patterns import TOOL_MISUSE_PATTERNS


def run(scanner: Any) -> None:
    rule_id = "SR-016"

    for fname in scanner.scanned_files:
        ext = Path(fname).suffix.lower()
        if ext in (".html", ".htm", ".css", ".svg"):
            continue

        content = scanner._read_file_content(fname)
        if not content:
            continue
        lines = content.split("\n")

        for operation in analyze_delete_operations(fname, content):
            if operation.scope == "package_owned":
                continue
            line = lines[operation.line - 1] if operation.line <= len(lines) else ""
            attacker_controlled = operation.source_control == "remote_attacker"
            if attacker_controlled:
                severity = "critical" if operation.recursive else "high"
                kind = "vulnerability"
                disposition = "confirmed_vulnerability"
                source_kind = "request"
                reachability = "request_reachable"
                activation = "direct"
                manual = False
            else:
                severity = "medium"
                kind = "context_dependent"
                disposition = "needs_context"
                source_kind = (
                    "operator_input"
                    if operation.source_control == "operator"
                    else "unknown"
                )
                reachability = "local_or_unknown"
                activation = "conditional"
                manual = True
            scanner._add_finding(
                rule_id=rule_id,
                severity=severity,
                category="tool_misuse",
                title="文件删除目标缺少安全边界",
                description=(
                    f"{fname} 中的 {operation.sink} 删除目标由"
                    f"{operation.source_control} 控制，静态分析范围为 {operation.scope}。"
                ),
                location={
                    "file": fname,
                    "line": operation.line,
                    "snippet": line[:200],
                },
                evidence=(
                    f"sink={operation.sink}; target={operation.target[:120]}; "
                    f"scope={operation.scope}; recursive={operation.recursive}"
                ),
                remediation=(
                    "将删除目标解析到包专用状态目录并验证 realpath 边界；"
                    "拒绝请求参数或任意外部路径。"
                ),
                cwe_id="CWE-22",
                kind=kind,
                disposition=disposition,
                sink_kind="filesystem_delete",
                sink_symbol=operation.sink,
                source_kind=source_kind,
                source_control=operation.source_control,
                reachability=reachability,
                activation=activation,
                trust_boundary_crossed=attacker_controlled,
                preconditions=(
                    ["attacker can select the deletion target"]
                    if attacker_controlled
                    else ["runtime value resolves outside package-owned state"]
                ),
                requires_manual_review=manual,
            )

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
