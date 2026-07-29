"""SR-018: Plugin security.

Detects security risks specific to Plugin packages:
  - Inline MCP server dangerous command: plugin_config.components.mcp_servers[]
    command/args containing shell injection or path traversal risks
  - Hook string injection: plugin_config.hooks[] strings that look like
    shell commands rather than lifecycle event names
  - Component path traversal: plugin_config.components paths pointing
    outside the plugin directory

Only applies to packages with type == "plugin"; other package types are skipped.
"""

from __future__ import annotations

import re
from typing import Any

_SHELL_INTERPRETERS = frozenset({"bash", "sh", "zsh", "cmd", "powershell", "pwsh"})

_SHELL_METACHAR_PATTERN = re.compile(r"[|;&`$()[\]<>]")

_DANGEROUS_COMMAND_PATTERNS: list[tuple[str, str]] = [
    (r"curl\s+.*\|\s*(?:ba)?sh\b", "curl pipe shell"),
    (r"wget\s+.*\|\s*(?:ba)?sh\b", "wget pipe shell"),
    (r"rm\s+-rf\s+[/~]", "recursive force delete"),
    (r"sudo\s+", "sudo privilege escalation"),
    (r">\s*/dev/sda", "write to block device"),
    (r"mkfs\.", "format filesystem"),
    (r"dd\s+if=", "dd disk operation"),
]


def run(scanner: Any) -> None:
    rule_id = "SR-018"
    meta = scanner._package_metadata
    if not meta:
        return

    pkg_type = meta.get("type", "")
    if pkg_type != "plugin":
        return

    plugin_config = meta.get("plugin_config")
    if plugin_config is None:
        plugin_config = {}

    _check_inline_mcp_servers(scanner, rule_id, plugin_config)
    _check_hooks(scanner, rule_id, plugin_config)
    _check_component_paths(scanner, rule_id, plugin_config)


def _check_inline_mcp_servers(
    scanner: Any, rule_id: str, plugin_config: dict[str, Any]
) -> None:
    components = plugin_config.get("components", {}) or {}
    mcp_servers = components.get("mcp_servers", []) or []

    for server in mcp_servers:
        if not isinstance(server, dict):
            continue

        command = server.get("command", "")
        args = server.get("args", []) or []

        if command.lower() in _SHELL_INTERPRETERS:
            scanner._add_finding(
                rule_id=rule_id,
                severity="high",
                category="plugin_security",
                title=f"内联 MCP Server 使用 Shell 解释器 — command={command}",
                description=(
                    f"Plugin 内联 MCP Server '{server.get('name', '?')}' "
                    f"使用 Shell 解释器 '{command}' 作为启动命令，"
                    f"args 可注入任意脚本。"
                ),
                location={"file": "plugin.json"},
                evidence=f"command: {command}, args: {args}",
                remediation=(
                    "避免将 Shell 解释器作为 MCP Server 的 command，"
                    "改用 Python/Node 等语言的直接脚本执行。"
                ),
            )
            continue

        dangerous_pattern_found = False
        for pattern, desc in _DANGEROUS_COMMAND_PATTERNS:
            combined = command + " " + " ".join(str(a) for a in args)
            if re.search(pattern, combined, re.IGNORECASE):
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="high",
                    category="plugin_security",
                    title=f"内联 MCP Server 危险命令 — {desc}",
                    description=(
                        f"Plugin 内联 MCP Server '{server.get('name', '?')}' "
                        f"的 command+args 中含危险命令模式: {desc}"
                    ),
                    location={"file": "plugin.json"},
                    evidence=f"command: {command}, args: {args}",
                    remediation=(
                        "移除危险命令，MCP Server 的 command 应仅为解释器名"
                        "（如 python/node），args 应为脚本文件路径。"
                    ),
                )
                dangerous_pattern_found = True
                break

        if dangerous_pattern_found:
            continue

        combined = command + " " + " ".join(str(a) for a in args)
        if _SHELL_METACHAR_PATTERN.search(combined):
            scanner._add_finding(
                rule_id=rule_id,
                severity="medium",
                category="plugin_security",
                title="内联 MCP Server 命令含 Shell 元字符",
                description=(
                    f"Plugin 内联 MCP Server '{server.get('name', '?')}' "
                    f"的 command+args 中含 Shell 元字符，不应将管道/重定向"
                    f"嵌入启动命令。"
                ),
                location={"file": "plugin.json"},
                evidence=f"command: {command}, args: {args}",
                remediation="移除 Shell 元字符。args 数组中每个元素应为独立参数，不应使用管道或重定向。",
            )

        if ".." in command or command.startswith("/") or command.startswith("\\"):
            scanner._add_finding(
                rule_id=rule_id,
                severity="high",
                category="plugin_security",
                title="内联 MCP Server 命令路径遍历",
                description=(
                    f"Plugin 内联 MCP Server '{server.get('name', '?')}' "
                    f"的 command 使用了路径遍历或绝对路径。"
                ),
                location={"file": "plugin.json"},
                evidence=f"command: {command}",
                remediation="command 应为解释器名称（如 python/node），不应包含路径遍历。",
            )


def _check_hooks(
    scanner: Any, rule_id: str, plugin_config: dict[str, Any]
) -> None:
    hooks = plugin_config.get("hooks", []) or []

    for hook in hooks:
        if not isinstance(hook, str):
            continue

        for pattern, desc in _DANGEROUS_COMMAND_PATTERNS:
            if re.search(pattern, hook, re.IGNORECASE):
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="high",
                    category="plugin_security",
                    title=f"Hook 含危险命令 — {desc}",
                    description=(
                        f"Plugin hooks 中的字符串 '{hook[:80]}' "
                        f"匹配危险命令模式: {desc}。"
                        f"Hooks 应为生命周期事件名（如 pre-install），"
                        f"不应包含可执行命令。"
                    ),
                    location={"file": "plugin.json"},
                    evidence=f"hook: {hook}",
                    remediation="将 hook 改为事件名声明（如 pre-install、post-install），可执行逻辑放入组件代码中。",
                )
                return

        if _SHELL_METACHAR_PATTERN.search(hook):
            scanner._add_finding(
                rule_id=rule_id,
                severity="medium",
                category="plugin_security",
                title="Hook 字符串含 Shell 元字符",
                description=(
                    f"Plugin hooks 中的字符串 '{hook[:80]}' "
                    f"含 Shell 元字符。Hooks 应为生命周期事件名"
                    f"（如 pre-install），不应包含管道/重定向等 Shell 语法。"
                ),
                location={"file": "plugin.json"},
                evidence=f"hook: {hook}",
                remediation="将 hook 改为事件名声明。可执行逻辑放入组件代码中。",
            )
            return


def _check_component_paths(
    scanner: Any, rule_id: str, plugin_config: dict[str, Any]
) -> None:
    components = plugin_config.get("components", {}) or {}
    path_fields = [
        ("skills", "内嵌 Skill"),
        ("agents", "内嵌 Agent"),
        ("commands", "内嵌 Command"),
    ]

    for field, label in path_fields:
        for path in components.get(field, []) or []:
            if not isinstance(path, str):
                continue
            if ".." in path:
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="medium",
                    category="plugin_security",
                    title=f"{label} 路径遍历 — {path}",
                    description=(
                        f"Plugin components.{field} 中的路径 '{path}' "
                        f"含 '..'，可能指向 Plugin 目录外的文件。"
                    ),
                    location={"file": "plugin.json"},
                    evidence=f"path: {path}",
                    remediation=f"将 components.{field} 路径限制在 Plugin 目录内，移除 '../'。",
                )
            if path.startswith("/") or path.startswith("\\"):
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="medium",
                    category="plugin_security",
                    title=f"{label} 绝对路径 — {path}",
                    description=(
                        f"Plugin components.{field} 中的路径 '{path}' "
                        f"使用了绝对路径，Plugin 应仅引用自身目录内的组件。"
                    ),
                    location={"file": "plugin.json"},
                    evidence=f"path: {path}",
                    remediation="将路径改为相对路径（如 ./skills/code-review）。",
                )
