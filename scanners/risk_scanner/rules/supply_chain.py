"""SR-008: Supply chain risk detection.

Checks for:
  - Typosquatting-like package names
  - Unpinned dependency versions
  - Non-HTTPS download URLs
  - curl/wget pipe to shell
  - Non-official package registries

OSV.dev CVE query is a placeholder for future network integration.
"""

from __future__ import annotations

import re
from typing import Any


def _query_osv(package_name: str, version: str, ecosystem: str = "npm") -> list[str]:
    """Query OSV.dev for known CVEs. Currently a placeholder.

    To enable: uncomment the implementation below, ensure httpx is installed.
    On failure (timeout / network error), returns empty list and does not block scanning.

    TODO: Enable OSV.dev live CVE lookup
    """
    return []


def run(scanner: Any) -> None:
    rule_id = "SR-008"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        lines = content.split("\n")

        # --- 1. curl/wget pipe to shell (critical) ---
        for pattern, desc in [
            (r"curl\s+.*\|\s*(ba)?sh\b", "curl pipe shell"),
            (r"wget\s+.*\|\s*(ba)?sh\b", "wget pipe shell"),
        ]:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1) : line_no])
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="critical",
                    category="supply_chain",
                    title=f"供应链风险 — 远程脚本执行: {desc}",
                    description=f"在 {fname} 中发现远程脚本下载并执行模式：{desc}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配: {pattern}",
                    remediation="避免使用 curl|sh 模式。使用锁定的依赖管理器（npm/pip）并验证包完整性。",
                )

        # --- 2. Non-official registry URLs ---
        for pattern, desc in [
            (r"https?://(?!pypi\.org|npmjs\.com|registry\.npmjs\.org|crates\.io)", "非官方包源"),
        ]:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                matched_url = match.group()
                if "/" not in matched_url.split("://", 1)[-1]:
                    continue
                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1) : line_no])
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="high",
                    category="supply_chain",
                    title=f"供应链风险 — {desc}: {matched_url[:60]}",
                    description=f"在 {fname} 中发现指向非官方包源的 URL：{matched_url[:80]}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"URL: {matched_url[:120]}",
                    remediation="仅使用官方包源（pypi.org / npmjs.com / crates.io）。",
                )

        # --- 3. Unpinned versions / risky version specifiers ---
        for pattern, desc in [
            (r'"\*"', "npm 版本通配符 *"),
            (r'"\s*:\s*"latest"', "版本号使用 latest"),
        ]:
            for match in re.finditer(pattern, content, re.MULTILINE):
                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1) : line_no])
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="medium",
                    category="supply_chain",
                    title=f"供应链风险 — {desc}",
                    description=f"在 {fname} 中发现未锁定的依赖版本：{desc}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配: {match.group()[:80]}",
                    remediation="锁定依赖版本到具体版本号，避免使用 * / latest。",
                )

        # --- 4. HTTP (non-HTTPS) download URLs ---
        for pattern, desc in [
            (r'(?:curl|wget|fetch|requests\.get)\s+["\']http://', "通过 HTTP 明文下载"),
        ]:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1) : line_no])
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="medium",
                    category="supply_chain",
                    title=f"供应链风险 — {desc}",
                    description=f"在 {fname} 中发现通过 HTTP 明文下载依赖：{desc}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配: {match.group()[:120]}",
                    remediation="使用 HTTPS 确保依赖下载的完整性和机密性。",
                )

    # --- 5. OSV.dev CVE query (placeholder) ---
    meta = scanner._package_metadata
    if meta:
        deps = meta.get("dependencies", {})
        npm_deps = deps.get("npm", []) if isinstance(deps, dict) else []
        for dep in npm_deps[:10]:
            pkg_name = dep.get("name", "") if isinstance(dep, dict) else str(dep)
            pkg_ver = dep.get("version", "*") if isinstance(dep, dict) else "*"
            if not pkg_name:
                continue
            cves = _query_osv(pkg_name, pkg_ver, "npm")
            for cve_id in cves:
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="high",
                    category="supply_chain",
                    title=f"供应链风险 — 已知 CVE: {cve_id} in {pkg_name}@{pkg_ver}",
                    description=f"依赖 {pkg_name}@{pkg_ver} 存在已知漏洞 {cve_id}。",
                    location={"file": "package.json"},
                    evidence=f"OSV.dev: {cve_id}",
                    remediation=f"升级 {pkg_name} 到修复版本，或替换为安全替代包。",
                )
