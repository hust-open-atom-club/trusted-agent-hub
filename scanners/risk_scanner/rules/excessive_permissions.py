"""SR-006: Excessive permission detection."""

from __future__ import annotations

from typing import Any

from scanners.risk_scanner.patterns import EXCESSIVE_PERMISSION_PATTERNS


def run(scanner: Any) -> None:
    rule_id = "SR-006"

    meta = scanner._package_metadata
    if not meta:
        return

    pkg_type = meta.get("type", "unknown")
    if pkg_type not in EXCESSIVE_PERMISSION_PATTERNS:
        return

    rules = EXCESSIVE_PERMISSION_PATTERNS[pkg_type]
    permissions = meta.get("permissions", {}) or {}

    unexpected_found: list[str] = []
    for perm_key in rules["unexpected"]:
        perm_val = permissions.get(perm_key)
        if perm_val:
            if isinstance(perm_val, dict):
                if perm_val.get("allowed", False) or perm_val:
                    unexpected_found.append(perm_key)
            elif isinstance(perm_val, list) and perm_val:
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
