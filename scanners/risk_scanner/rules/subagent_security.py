"""SR-019: Subagent security.

Detects security risks specific to Subagent packages:
  - Autonomous mode: interaction_mode = "autonomous" without user supervision
  - Excessive iterations: high max_iterations in autonomous mode
  - Dangerous tools: tools[] granting shell execution or file write access
  - Global scope: scope = "global" extends the subagent's reach
  - System prompt path traversal: system_prompt_path pointing outside the package

Only applies to packages with type == "subagent"; other package types are skipped.
"""

from __future__ import annotations

from typing import Any

_DANGEROUS_TOOLS = frozenset({
    "Bash", "Write", "Edit",
    "shell", "exec", "subprocess",
    "terminal", "command", "Command",
    "code_execution", "code-execution",
    "CodeInterpreter", "allow_code_execution",
})

_AUTONOMOUS_ITER_THRESHOLD = 50


def run(scanner: Any) -> None:
    rule_id = "SR-019"
    meta = scanner._package_metadata
    if not meta:
        return

    pkg_type = meta.get("type", "")
    if pkg_type != "subagent":
        return

    subagent_config = meta.get("subagent_config")
    if subagent_config is None:
        subagent_config = {}

    _check_autonomous(scanner, rule_id, subagent_config)
    _check_dangerous_tools(scanner, rule_id, subagent_config)
    _check_global_scope(scanner, rule_id, subagent_config)
    _check_system_prompt_path(scanner, rule_id, subagent_config)


def _check_autonomous(
    scanner: Any, rule_id: str, subagent_config: dict[str, Any]
) -> None:
    mode = subagent_config.get("interaction_mode", "supervised")
    if mode != "autonomous":
        return

    max_iterations = subagent_config.get("max_iterations", 10)

    if max_iterations >= _AUTONOMOUS_ITER_THRESHOLD:
        scanner._add_finding(
            rule_id=rule_id,
            severity="high",
            category="subagent_security",
            title=f"自主模式 + 高迭代次数 — interaction_mode=autonomous, max_iterations={max_iterations}",
            description=(
                f"Subagent 以 autonomous 模式运行且 max_iterations={max_iterations}。"
                f"无用户监管的情况下可执行大量操作，存在不可控风险。"
            ),
            location={"file": "agent.json"},
            evidence=f"interaction_mode: {mode}, max_iterations: {max_iterations}",
            remediation="降低 max_iterations 到合理范围，或改为 supervised 模式以保留人工审核环节。",
        )
    else:
        scanner._add_finding(
            rule_id=rule_id,
            severity="medium",
            category="subagent_security",
            title=f"自主模式 — interaction_mode=autonomous",
            description=(
                f"Subagent 以 autonomous 模式运行，无需用户监管即可执行操作。"
            ),
            location={"file": "agent.json"},
            evidence=f"interaction_mode: {mode}, max_iterations: {max_iterations}",
            remediation="在信任度充分之前，建议使用 supervised 模式，保留人工审核。",
        )


def _check_dangerous_tools(
    scanner: Any, rule_id: str, subagent_config: dict[str, Any]
) -> None:
    tools = subagent_config.get("tools", []) or []
    mode = subagent_config.get("interaction_mode", "supervised")

    dangerous_found = [t for t in tools if t in _DANGEROUS_TOOLS]
    if not dangerous_found:
        return

    severity = "high" if mode == "autonomous" else "medium"
    title_suffix = "（autonomous 模式，无需用户同意）" if mode == "autonomous" else ""

    scanner._add_finding(
        rule_id=rule_id,
        severity=severity,
        category="subagent_security",
        title=f"Subagent 授予危险工具 — {', '.join(dangerous_found)}{title_suffix}",
        description=(
            f"Subagent 的 tools 列表包含危险工具: {', '.join(dangerous_found)}。"
            f"{'结合 autonomous 模式，Subagent 可在无用户许可的情况下执行 Shell 命令或写入文件。' if mode == 'autonomous' else '建议审查是否需要这些工具权限。'}"
        ),
        location={"file": "agent.json"},
        evidence=f"tools: {tools}, interaction_mode: {mode}",
        remediation=(
            "移除不必要的危险工具（Bash/shell/exec/Write）。"
            "若确实需要，使用 supervised 模式确保用户在工具执行前审批。"
        ),
    )


def _check_global_scope(
    scanner: Any, rule_id: str, subagent_config: dict[str, Any]
) -> None:
    scope = subagent_config.get("scope", "project")
    if scope == "global":
        scanner._add_finding(
            rule_id=rule_id,
            severity="medium",
            category="subagent_security",
            title="Subagent 作用域为 global",
            description=(
                "Subagent 的 scope 设置为 'global'，可跨项目/跨用户访问资源。"
                "对不可信包来说此作用域过于宽泛。"
            ),
            location={"file": "agent.json"},
            evidence=f"scope: {scope}",
            remediation="将 scope 改为 project 以限制访问范围，仅在受信任的企业级 packages 中使用 global。",
        )


def _check_system_prompt_path(
    scanner: Any, rule_id: str, subagent_config: dict[str, Any]
) -> None:
    path = subagent_config.get("system_prompt_path", "")
    if not path:
        # schema requires it; if it's missing, the structure check already
        # catches the missing agent.json.  Don't double-report here.
        return

    if ".." in path:
        scanner._add_finding(
            rule_id=rule_id,
            severity="medium",
            category="subagent_security",
            title=f"system_prompt_path 路径遍历 — {path}",
            description=(
                f"Subagent 的 system_prompt_path '{path}' 含 '..'，"
                f"可能指向 package 目录外的恶意文件。"
            ),
            location={"file": "agent.json"},
            evidence=f"system_prompt_path: {path}",
            remediation="将 system_prompt_path 限制在 package 目录内，移除 '../'。",
        )

    if path.startswith("/") or path.startswith("\\"):
        scanner._add_finding(
            rule_id=rule_id,
            severity="medium",
            category="subagent_security",
            title=f"system_prompt_path 绝对路径 — {path}",
            description=(
                f"Subagent 的 system_prompt_path '{path}' 使用了绝对路径，"
                f"应仅引用 package 目录内的文件。"
            ),
            location={"file": "agent.json"},
            evidence=f"system_prompt_path: {path}",
            remediation="将路径改为相对路径（如 ./system_prompt.md）。",
        )
