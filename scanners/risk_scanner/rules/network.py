"""SR-007: Network access without domain whitelist detection."""

from __future__ import annotations

import re
from typing import Any


def run(scanner: Any) -> None:
    rule_id = "SR-007"

    for filename in scanner.scanned_files:
        content = scanner._read_file_content(filename)
        if not content:
            continue
        for match in re.finditer(
            r"\.listen\s*\([^)]*[\"'](?:0\.0\.0\.0|::)[\"']\s*\)",
            content,
            re.IGNORECASE,
        ):
            line_no = content[:match.start()].count("\n") + 1
            if any(
                finding.get("rule_id") == "SR-005"
                and finding.get("kind") == "vulnerability"
                and (finding.get("location") or {}).get("file") == filename
                for finding in scanner.findings
            ):
                # The request-to-shell issue already describes the exploitable
                # public service. Keep bind scope in the capability graph
                # without adding a second score-facing root cause.
                continue
            line = content.splitlines()[line_no - 1]
            scanner._add_finding(
                rule_id=rule_id,
                severity="medium",
                category="network_access",
                title="服务监听公共网络接口",
                description=(
                    f"{filename} 将服务绑定到所有网络接口；是否安全取决于认证、"
                    "部署边界和防火墙配置。"
                ),
                location={"file": filename, "line": line_no, "snippet": line[:200]},
                evidence=f"public listener: {match.group()[:120]}",
                remediation="默认绑定 loopback；确需公开服务时增加认证、访问控制和部署说明。",
                kind="context_dependent",
                disposition="needs_context",
                sink_kind="network_listener",
                sink_symbol="listen",
                source_kind="bind_configuration",
                source_control="operator_or_package_author",
                reachability="network_exposed",
                activation="deployment_dependent",
                trust_boundary_crossed=True,
                preconditions=["deployment permits inbound network traffic"],
                requires_manual_review=True,
            )

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
            kind="policy",
            disposition="needs_context",
            sink_kind="network_permission",
            source_kind="manifest_declaration",
            source_control="package_author",
            activation="conditional",
            requires_manual_review=True,
        )
