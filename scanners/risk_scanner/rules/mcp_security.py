"""SR-017: MCP Server security.

Detects security risks specific to MCP (Model Context Protocol) server packages:
  - Hidden tool detection: tools registered in code but not declared in manifest.json
  - Non-encrypted HTTP transport: remote endpoints using http:// instead of https://
  - Tool description poisoning:
      ① Keyword rule (deterministic): tool description claims a risky capability
        (shell / delete / credential / network exfiltration) that the declared
        permissions do NOT grant -> factual contradiction, high severity.
      ② Semantic drift (requires fastembed, optional): cosine similarity between
        the tool description and the declared permissions text below threshold
        -> low severity hint for human reviewer.
      Code-side supplement: descriptions registered in code that contain risky
      keywords while the manifest description does not -> hidden danger signal.

Only applies to packages with type == "mcp_server"; other package types are skipped.
Supports both manifest structures:
  - Simple: top-level "tools" and "transport" fields
  - Full: nested under "mcp_server_config"
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from scanners.risk_scanner.common import CODE_FILE_EXTENSIONS
from scanners.risk_scanner.patterns import (
    MCP_TOOL_DESC_RISK_KEYWORDS,
    MCP_TOOL_REGISTER_DESC_PATTERNS,
    MCP_TOOL_REGISTER_PATTERNS,
)
from scanners.risk_scanner.weights import (
    TOOL_POISONING_DESC_PERM_THRESHOLD,
    TOOL_POISONING_DRIFT_SEVERITY,
    TOOL_POISONING_KEYWORD_SEVERITY,
    TOOL_POISONING_MULTI_COUNT,
    TOOL_POISONING_MULTI_SEVERITY,
    TOOL_POISONING_NO_PERM_SEVERITY,
)

logger = logging.getLogger(__name__)

_SEMANTIC_MODEL: Any = None
_SEMANTIC_MODEL_NAME = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"


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
    _check_tool_description_poisoning(scanner, rule_id, meta, mcp_config)
    _check_code_description_mismatch(scanner, rule_id, meta, mcp_config)


def _extract_declared_tools(meta: dict[str, Any], mcp_config: dict[str, Any]) -> set[str]:
    declared: set[str] = set()

    tools_raw = mcp_config.get("tools")
    if tools_raw is None:
        tools_raw = meta.get("tools", [])

    for tool in tools_raw:
        if isinstance(tool, dict) and tool.get("name"):
            declared.add(tool["name"])

    return declared


def _extract_tools_with_desc(
    meta: dict[str, Any], mcp_config: dict[str, Any]
) -> list[dict[str, str]]:
    tools_raw = mcp_config.get("tools")
    if tools_raw is None:
        tools_raw = meta.get("tools", [])

    result: list[dict[str, str]] = []
    for tool in tools_raw:
        if isinstance(tool, dict) and tool.get("name"):
            result.append({
                "name": str(tool["name"]),
                "description": str(tool.get("description", "") or ""),
            })
    return result


# ---------------------------------------------------------------------------
# Hidden tool detection
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# HTTP transport detection
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Tool description poisoning detection
# ---------------------------------------------------------------------------

def _match_risk_keywords(description: str) -> dict[str, list[str]]:
    """Return {capability: [matched keywords]} for a tool description."""
    lower = description.lower()
    matched: dict[str, list[str]] = {}
    for keyword, capability in MCP_TOOL_DESC_RISK_KEYWORDS:
        if keyword in lower:
            matched.setdefault(capability, []).append(keyword)
    return matched


def _capability_granted(permissions: dict[str, Any], capability: str) -> bool:
    """Whether the declared permissions explicitly grant the capability.

    Undeclared fields are treated as NOT granted (safe default).
    """
    if not permissions or not isinstance(permissions, dict):
        return False

    if capability in ("shell", "system"):
        return permissions.get("shell", {}).get("allowed") is True
    if capability == "delete":
        fs = permissions.get("filesystem", {})
        if isinstance(fs, dict):
            if fs.get("delete") is True:
                return True
            return bool(fs.get("write"))
        return False
    if capability == "credential":
        env = permissions.get("environment", {})
        if isinstance(env, dict) and env.get("read"):
            return True
        fs = permissions.get("filesystem", {})
        if isinstance(fs, dict) and fs.get("read"):
            return True
        return False
    if capability == "network":
        return permissions.get("network", {}).get("allowed") is True
    return False


def _permissions_to_text(permissions: dict[str, Any]) -> str:
    """Render declared permissions as a semantic text for embedding comparison."""
    parts: list[str] = []
    fs = permissions.get("filesystem", {})
    if isinstance(fs, dict):
        if fs.get("read"):
            parts.append("读取文件系统")
        if fs.get("write"):
            parts.append("写入文件系统")
        if fs.get("delete") is True:
            parts.append("删除文件")
    shell = permissions.get("shell", {})
    if isinstance(shell, dict) and shell.get("allowed") is True:
        parts.append("执行 shell 命令")
    net = permissions.get("network", {})
    if isinstance(net, dict) and net.get("allowed") is True:
        domains = net.get("domains")
        if domains:
            parts.append(f"访问网络域名 {', '.join(str(d) for d in domains)}")
        else:
            parts.append("访问网络")
    env = permissions.get("environment", {})
    if isinstance(env, dict) and env.get("read"):
        parts.append("读取环境变量")
    db = permissions.get("database", {})
    if isinstance(db, dict) and db.get("allowed") is True:
        parts.append("访问数据库")
    return "；".join(parts)


def _load_semantic_model() -> Any | None:
    """Load the multilingual embedding model once (lazy, thread-safe by GIL).

    Returns None when fastembed is unavailable -> semantic check (②) is
    skipped and only the deterministic keyword rule (①) runs.
    """
    global _SEMANTIC_MODEL
    if _SEMANTIC_MODEL is not None:
        return _SEMANTIC_MODEL

    try:
        from fastembed import TextEmbedding

        _SEMANTIC_MODEL = TextEmbedding(_SEMANTIC_MODEL_NAME)
        logger.info("SR-017 semantic model loaded: %s", _SEMANTIC_MODEL_NAME)
        return _SEMANTIC_MODEL
    except ImportError:
        logger.warning(
            "SR-017: fastembed not installed — semantic drift check disabled, "
            "only keyword-based rules (①) will run"
        )
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "SR-017: semantic model load failed (%s) — semantic drift check "
            "disabled, only keyword-based rules (①) will run",
            exc,
        )
        return None


def _desc_perm_similarity(model: Any, description: str, perm_text: str) -> float:
    try:
        vecs = list(model.embed([description, perm_text]))
        a, b = vecs[0], vecs[1]
        dot = float(sum(x * y for x, y in zip(a, b)))
        norm_a = float(sum(x * x for x in a)) ** 0.5
        norm_b = float(sum(x * x for x in b)) ** 0.5
        if norm_a == 0 or norm_b == 0:
            return 1.0
        return dot / (norm_a * norm_b)
    except Exception as exc:  # noqa: BLE001
        logger.warning("SR-017: embedding similarity computation failed: %s", exc)
        return 1.0


def _check_tool_description_poisoning(
    scanner: Any,
    rule_id: str,
    meta: dict[str, Any],
    mcp_config: dict[str, Any],
) -> None:
    """① keyword + permission contradiction (deterministic) and ② semantic drift.

    Severity ladder:
      - ① single tool        -> high
      - ① >= 2 tools         -> critical
      - ① + ② same tool      -> critical
      - ② only               -> low
      - ① without permissions section -> low (cannot prove contradiction)
    """
    tools = _extract_tools_with_desc(meta, mcp_config)
    if not tools:
        return

    permissions = meta.get("permissions")
    has_permissions = isinstance(permissions, dict) and bool(permissions)
    model = _load_semantic_model()

    evaluated: list[dict[str, Any]] = []
    for tool in tools:
        name = tool["name"]
        desc = tool["description"]
        if not name or not desc:
            continue

        matched = _match_risk_keywords(desc)
        poisoned = False
        if matched:
            if has_permissions:
                for capability in matched:
                    if not _capability_granted(permissions, capability):
                        poisoned = True
                        break
            else:
                poisoned = True

        drift = False
        drift_sim = 0.0
        if model is not None and has_permissions:
            perm_text = _permissions_to_text(permissions)
            if perm_text:
                drift_sim = _desc_perm_similarity(model, desc, perm_text)
                logger.debug(
                    "SR-017 desc-perm similarity tool=%s sim=%.4f threshold=%.2f",
                    name, drift_sim, TOOL_POISONING_DESC_PERM_THRESHOLD,
                )
                drift = drift_sim < TOOL_POISONING_DESC_PERM_THRESHOLD

        if poisoned or drift:
            evaluated.append({
                "name": name,
                "desc": desc,
                "matched": matched,
                "poisoned": poisoned,
                "drift": drift,
                "drift_sim": drift_sim,
            })

    if not evaluated:
        return

    poisoned_count = sum(1 for e in evaluated if e["poisoned"])
    multi = poisoned_count >= TOOL_POISONING_MULTI_COUNT

    for entry in evaluated:
        name = entry["name"]
        desc = entry["desc"]
        matched = entry["matched"]
        poisoned = entry["poisoned"]
        drift = entry["drift"]
        drift_sim = entry["drift_sim"]

        if poisoned:
            if not has_permissions:
                severity = TOOL_POISONING_NO_PERM_SEVERITY
                title = (
                    f"工具描述含高危能力声明但未声明权限 — 工具: {name}"
                )
                description = (
                    f"工具 '{name}' 的描述包含高危能力关键词 "
                    f"({', '.join(matched)})，但 manifest.json 未声明 permissions。"
                    f"无法确认权限边界，建议人工审核。"
                )
            elif drift:
                severity = TOOL_POISONING_MULTI_SEVERITY
                title = f"工具描述投毒（高危+语义漂移）— 工具: {name}"
                description = (
                    f"工具 '{name}' 描述声称的能力 "
                    f"({', '.join(matched)}) 超出权限声明，且描述与权限声明的"
                    f"语义相似度仅为 {drift_sim:.2f}，存在系统性投毒嫌疑。"
                )
            elif multi:
                severity = TOOL_POISONING_MULTI_SEVERITY
                title = f"工具描述投毒（多个工具命中）— 工具: {name}"
                description = (
                    f"工具 '{name}' 描述声称的能力 "
                    f"({', '.join(matched)}) 超出权限声明。"
                    f"共 {poisoned_count} 个工具存在此问题，疑似系统性投毒。"
                )
            else:
                severity = TOOL_POISONING_KEYWORD_SEVERITY
                title = f"工具描述投毒 — 描述声称的能力超出权限声明: {name}"
                description = (
                    f"工具 '{name}' 的描述声称具备能力 "
                    f"({', '.join(matched)})，但 manifest.json 的 permissions 声明"
                    f"未授予对应权限。AI 模型可能被误导授予超出声明的权限。"
                )
            evidence = f"tool: {name}; capability: {', '.join(matched)}"
        else:
            severity = TOOL_POISONING_DRIFT_SEVERITY
            title = f"工具描述与权限声明语义漂移（提示）— 工具: {name}"
            description = (
                f"工具 '{name}' 的描述与 manifest 声明的权限在语义上相关性较低"
                f"（相似度 {drift_sim:.2f}，阈值 {TOOL_POISONING_DESC_PERM_THRESHOLD}）。"
                f"可能只是描述含糊，也可能是隐藏能力声明，建议人工确认。"
            )
            evidence = f"tool: {name}; desc_perm_sim: {drift_sim:.3f}"

        scanner._add_finding(
            rule_id=rule_id,
            severity=severity,
            category="mcp_security",
            title=title,
            description=description,
            location={"file": "manifest.json"},
            evidence=evidence,
            remediation=(
                "确保工具描述与权限声明一致：要么在 permissions 中声明实际需要的能力，"
                "要么修正描述使其不包含超出声明范围的能力。"
            ),
        )


# ---------------------------------------------------------------------------
# Code-side description supplement
# ---------------------------------------------------------------------------

def _check_code_description_mismatch(
    scanner: Any,
    rule_id: str,
    meta: dict[str, Any],
    mcp_config: dict[str, Any],
) -> None:
    """Descriptions registered in code vs manifest declarations.

    If a tool's code-registered description contains risky keywords while the
    manifest description does not, the package may be hiding a dangerous
    capability behind a benign facade.
    """
    manifest_desc_by_name: dict[str, str] = {
        t["name"]: t["description"] for t in _extract_tools_with_desc(meta, mcp_config)
    }

    for fname in scanner.scanned_files:
        ext = Path(fname).suffix.lower()
        if ext not in CODE_FILE_EXTENSIONS:
            continue

        content = scanner._read_file_content(fname)
        if not content:
            continue

        for pattern in MCP_TOOL_REGISTER_DESC_PATTERNS:
            for match in re.finditer(pattern, content):
                tool_name = match.group(1)
                code_desc = match.group(2)
                if tool_name not in manifest_desc_by_name:
                    continue
                manifest_desc = manifest_desc_by_name[tool_name]

                code_hits = _match_risk_keywords(code_desc)
                manifest_hits = _match_risk_keywords(manifest_desc)
                if code_hits and not manifest_hits:
                    line_no = content[: match.start()].count("\n") + 1
                    scanner._add_finding(
                        rule_id=rule_id,
                        severity=TOOL_POISONING_KEYWORD_SEVERITY,
                        category="mcp_security",
                        title=(
                            f"代码注册描述含未声明的高危能力 — 工具: {tool_name}"
                        ),
                        description=(
                            f"工具 '{tool_name}' 在代码注册时的描述包含高危能力关键词 "
                            f"({', '.join(code_hits)})，但 manifest.json 中该工具的"
                            f"描述未提及。AI 客户端实际看到的是代码注册的描述，"
                            f"可能存在明面一套、实际一套的风险。"
                        ),
                        location={"file": fname, "line": line_no},
                        evidence=f"tool: {tool_name}; code_desc: {code_desc[:80]}",
                        remediation=(
                            "在 manifest.json 中同步该工具的描述，或移除代码描述中"
                            "的高危能力声明。"
                        ),
                    )
