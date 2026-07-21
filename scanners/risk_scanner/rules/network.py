"""SR-007: Network access without domain whitelist detection."""

from __future__ import annotations

from typing import Any


def run(scanner: Any) -> None:
    rule_id = "SR-007"

    meta = scanner._package_metadata
    if not meta:
        return

    permissions = meta.get("permissions", {}) or {}
    network = permissions.get("network", {}) or {}

    if network.get("allowed", False) and not network.get("domains"):
        manifest_file = "manifest.json" if (scanner.target_dir / "manifest.json").is_file() else "SKILL.md"
        scanner._add_finding(
            rule_id=rule_id,
            severity="medium",
            category="network_access",
            title="网络访问无域名白名单",
            description="网络权限已开启 (network.allowed=true)，但未设置域名白名单 (domains=[])，可以访问任意域名。",
            location={"file": manifest_file},
            evidence="network.allowed=true, network.domains is empty or missing",
            remediation="设置 network.domains 白名单，仅允许访问必要的域名。",
        )
