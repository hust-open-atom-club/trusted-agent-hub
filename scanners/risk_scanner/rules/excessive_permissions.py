"""SR-006: Excessive permission detection + Autonomous decision detection."""

from __future__ import annotations

import re
from typing import Any

from scanners.risk_scanner.patterns import AUTONOMOUS_DECISION_PATTERNS, EXCESSIVE_PERMISSION_PATTERNS


def run(scanner: Any) -> None:
    rule_id = "SR-006"

    meta = scanner._package_metadata
    if not meta:
        return

    pkg_type = meta.get("type", "unknown")
    if pkg_type in EXCESSIVE_PERMISSION_PATTERNS:
        rules = EXCESSIVE_PERMISSION_PATTERNS[pkg_type]
        permissions = meta.get("permissions", {}) or {}
        unexpected_found: list[str] = []
        for perm_key in rules["unexpected"]:
            perm_val = permissions.get(perm_key)
            if not perm_val:
                continue
            if isinstance(perm_val, dict):
                if perm_val.get("allowed", False):
                    unexpected_found.append(perm_key)
            elif isinstance(perm_val, (list, str)) and perm_val:
                    unexpected_found.append(perm_key)

        if unexpected_found:
            manifest_file = "manifest.json" if (scanner.target_dir / "manifest.json").is_file() else "SKILL.md"
            scanner._add_finding(
                rule_id=rule_id,
                severity="medium",
                category="excessive_permission",
                title=f"过度权限: 类型 '{pkg_type}' 声明了非预期权限",
                description=f"{rules['label']}。发现的额外权限: {', '.join(unexpected_found)}",
                location={"file": manifest_file},
                evidence=f"Package type: {pkg_type}, unexpected permissions: {unexpected_found}",
                remediation=f"审查并移除类型 '{pkg_type}' 不需要的权限，或提供合理的权限说明。",
            )

    _check_autonomous_decision(scanner, meta)
    _check_scope_creep(scanner, meta)


def _check_autonomous_decision(scanner: Any, meta: dict[str, Any]) -> None:
    description = meta.get("description", "")
    if not description:
        return
    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        if not content:
            continue
        for pattern, desc, severity in AUTONOMOUS_DECISION_PATTERNS:
            for match in re.finditer(pattern, description + "\n" + content, re.IGNORECASE):
                scanner._add_finding(
                    rule_id="SR-006",
                    severity=severity,
                    category="excessive_permission",
                    title=f"自主决策风险 — {desc}",
                    description=f"包描述或内容中含自主决策模式：{match.group()[:80]}",
                    location={"file": fname},
                    evidence=f"匹配: {match.group()[:100]}",
                    remediation="Skill 应始终在关键操作前请求用户确认，而非自主决策。",
                )
                return


def _check_scope_creep(scanner: Any, meta: dict[str, Any]) -> None:
    permissions = meta.get("permissions", {}) or {}
    description = meta.get("description", "").lower()
    if not description:
        return

    scope_pairs = [
        ("code.?review", "shell", "声称做代码审查但声明了 Shell 权限"),
        ("read.?only", "write", "声称只读但声明了写入权限"),
        ("safe", "network", "声称安全但声明了网络权限"),
    ]
    for desc_kw, perm_kw, label in scope_pairs:
        if re.search(desc_kw, description) and permissions.get(perm_kw):
            perm_val = permissions[perm_kw]
            if isinstance(perm_val, dict) and perm_val.get("allowed", False):
                manifest_file = "manifest.json" if (scanner.target_dir / "manifest.json").is_file() else "SKILL.md"
                scanner._add_finding(
                    rule_id="SR-006",
                    severity="medium",
                    category="excessive_permission",
                    title=f"权限范围蔓延: {label}",
                    description=f"包描述声称 {desc_kw}，但声明了 {perm_kw} 权限，存在范围不一致。",
                    location={"file": manifest_file},
                    evidence=f"Description: {description[:120]}, Permission: {perm_kw}",
                    remediation="确保声明的权限与描述的功能范围一致。",
                )
