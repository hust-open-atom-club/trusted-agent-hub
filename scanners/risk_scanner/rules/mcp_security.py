"""SR-017: MCP Server security.

Detects security risks specific to MCP (Model Context Protocol) server packages:
  - Hidden tool detection: tools registered in code but not declared in manifest.json
  - Non-encrypted HTTP transport: remote endpoints using http:// instead of https://

Not implemented (documented limitations, see D6 安全设计说明):
  - Tool description poisoning detection (requires LLM semantic analysis)
  - Version drift detection (low severity, minimal practical impact)

Only applies to packages with type == "mcp_server"; other package types are skipped.
Supports both manifest structures:
  - Simple: top-level "tools" and "transport" fields
  - Full: nested under "mcp_server_config"
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from scanners.risk_scanner.common import CODE_FILE_EXTENSIONS
from scanners.risk_scanner.patterns import MCP_TOOL_REGISTER_PATTERNS


def run(scanner: Any) -> None:
    rule_id = "SR-017"
    meta = scanner._package_metadata
    if not meta:
        return

    pkg_type = meta.get("type", "")
    if pkg_type != "mcp_server":
        return

    mcp_config = meta.get("mcp_server_config")
    if mcp_config is None:
        mcp_config = {}

    declared_tools = _extract_declared_tools(meta, mcp_config)

    _check_hidden_tools(scanner, rule_id, declared_tools)
    _check_http_transport(scanner, rule_id, meta, mcp_config)


def _extract_declared_tools(meta: dict[str, Any], mcp_config: dict[str, Any]) -> set[str]:
    declared: set[str] = set()

    tools_raw = mcp_config.get("tools")
    if tools_raw is None:
        tools_raw = meta.get("tools", [])

    for tool in tools_raw:
        if isinstance(tool, dict) and tool.get("name"):
            declared.add(tool["name"])

    return declared


def _check_hidden_tools(
    scanner: Any, rule_id: str, declared: set[str]
) -> None:
    for fname in scanner.scanned_files:
        ext = Path(fname).suffix.lower()
        if ext not in CODE_FILE_EXTENSIONS:
            continue

        content = scanner._read_file_content(fname)
        if not content:
            continue

        tool_locations: dict[str, int] = {}
        for pattern in MCP_TOOL_REGISTER_PATTERNS:
            for match in re.finditer(pattern, content):
                tool_name = match.group(1)
                if tool_name not in tool_locations:
                    line_no = content[: match.start()].count("\n") + 1
                    tool_locations[tool_name] = line_no

        hidden = set(tool_locations.keys()) - declared
        for tool_name in hidden:
            line_no = tool_locations[tool_name]
            scanner._add_finding(
                rule_id=rule_id,
                severity="high",
                category="mcp_security",
                title=f"隐藏工具检测 — 代码注册了 manifest 未声明的工具: {tool_name}",
                description=(
                    f"在 {fname} 中发现工具 '{tool_name}' 的注册/分发代码，"
                    f"但 manifest.json 的 tools 列表中未声明此工具。"
                ),
                location={"file": fname, "line": line_no},
                evidence=f"Hidden tool: {tool_name}",
                remediation=(
                    f"在 manifest.json 的 mcp_server_config.tools 中声明工具 '{tool_name}'，"
                    f"或从代码中移除该工具。"
                ),
            )


def _check_http_transport(
    scanner: Any,
    rule_id: str,
    meta: dict[str, Any],
    mcp_config: dict[str, Any],
) -> None:
    remote_endpoint = mcp_config.get("remote_endpoint")
    if remote_endpoint is None:
        remote_endpoint = meta.get("remote_endpoint", "")

    if not remote_endpoint:
        return

    if not remote_endpoint.startswith("http://"):
        return

    lower_endpoint = remote_endpoint.lower()
    if "localhost" in lower_endpoint or "127.0.0.1" in lower_endpoint:
        return

    manifest_file = "manifest.json"
    scanner._add_finding(
        rule_id=rule_id,
        severity="high",
        category="mcp_security",
        title="非加密 HTTP 传输 — remote_endpoint 使用 http:// 而非 https://",
        description=(
            f"MCP Server 的 remote_endpoint 使用明文 HTTP 传输: {remote_endpoint}。"
            f"网络流量可被中间人截获或篡改。"
        ),
        location={"file": manifest_file},
        evidence=f"remote_endpoint: {remote_endpoint}",
        remediation=(
            "将 remote_endpoint 改为 https:// 加密传输，"
            "或仅在本地开发时使用 http://localhost。"
        ),
    )
