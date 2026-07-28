"""SR-008: Supply chain risk detection.

Checks for:
  - curl/wget pipe to shell (critical)
  - Non-official package registries (high)
  - Unpinned / risky dependency versions (medium)
  - HTTP download URLs (medium)
  - Abandoned / deprecated packages (medium)
  - Typosquatting (Levenshtein distance < 2)
  - Live CVE lookup via OSV.dev API
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
import urllib.error
from typing import Any

from scanners.risk_scanner.patterns import (
    BUILTIN_WELL_KNOWN_PACKAGES,
    DOMAIN_WHITELIST,
    SUPPLY_CHAIN_PATTERNS,
    TRIGGER_RISK_PATTERNS,
)

_CVE_CACHE: dict[str, tuple[float, list[str]]] = {}
_CVE_CACHE_TTL = 3600


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1, 1):
        curr = [i]
        for j, c2 in enumerate(s2, 1):
            curr.append(min(
                curr[j - 1] + 1,
                prev[j] + 1,
                prev[j - 1] + (0 if c1 == c2 else 1),
            ))
        prev = curr
    return prev[-1]


def _query_osv(package_name: str, version: str, ecosystem: str = "PyPI") -> list[str]:
    cache_key = f"{ecosystem}:{package_name}:{version}"
    now = time.time()
    if cache_key in _CVE_CACHE:
        ts, result = _CVE_CACHE[cache_key]
        if now - ts < _CVE_CACHE_TTL:
            return result

    try:
        body = json.dumps({
            "package": {"name": package_name, "ecosystem": ecosystem},
            "version": version,
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read().decode("utf-8"))
        vulns = [v.get("id", "CVE-UNKNOWN") for v in data.get("vulns", [])]
        _CVE_CACHE[cache_key] = (now, vulns)
        return vulns
    except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
        _CVE_CACHE[cache_key] = (now, [])
        return []


def _check_typosquatting(scanner: Any, meta: dict[str, Any]) -> None:
    dep_names: list[str] = []
    deps = meta.get("dependencies", {})
    if isinstance(deps, dict):
        for ecosystem_deps in deps.values():
            if isinstance(ecosystem_deps, list):
                for dep in ecosystem_deps:
                    name = dep.get("name", "") if isinstance(dep, dict) else str(dep)
                    if name:
                        dep_names.append(name.lower())
    pkg_name = meta.get("name", "").lower()

    for dep_name in dep_names:
        for known in BUILTIN_WELL_KNOWN_PACKAGES:
            if len(dep_name) < 3:
                continue
            dist = _levenshtein(dep_name, known.lower())
            if 0 < dist <= 2 and dep_name != known.lower():
                manifest_file = "manifest.json" if (scanner.target_dir / "manifest.json").is_file() else "SKILL.md"
                scanner._add_finding(
                    rule_id="SR-008",
                    severity="high",
                    category="supply_chain",
                    title=f"Typosquatting 检测: '{dep_name}' 与已知包 '{known}' 相似",
                    description=f"依赖包名 '{dep_name}' 与已知包 '{known}' Levenshtein 距离为 {dist}，可能存在 typosquatting 攻击。",
                    location={"file": manifest_file},
                    evidence=f"Levenshtein distance: {dist}, package: {dep_name} vs {known}",
                    remediation=f"验证包 '{dep_name}' 是否为官方包，检查其来源和发布历史。",
                )
        if pkg_name and _levenshtein(pkg_name, dep_name) <= 2 and pkg_name != dep_name:
            pass


def run(scanner: Any) -> None:
    rule_id = "SR-008"

    # ── 1. Pattern-based checks across all files ──
    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        if not content:
            continue
        lines = content.split("\n")

        for pattern, desc, severity in SUPPLY_CHAIN_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                matched_url = match.group()
                if "non-official" in desc.lower() or "non-official" in pattern.lower() or (
                    "://" in matched_url and "whitelist" not in desc.lower()
                ):
                    if "://" in matched_url:
                        domain = matched_url.split("://", 1)[-1].split("/")[0].split(":")[0]
                        if any(wl in domain for wl in DOMAIN_WHITELIST):
                            continue

                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1):line_no])
                if scanner._is_code_example(fname, line_no):
                    severity = "medium" if severity == "critical" else "low"

                scanner._add_finding(
                    rule_id=rule_id,
                    severity=severity,
                    category="supply_chain",
                    title=f"供应链风险 — {desc}",
                    description=f"在 {fname} 中发现供应链风险模式：{desc}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配: {matched_url[:120]}",
                    remediation="使用锁定的依赖管理器（npm/pip）并验证包完整性。仅使用官方源和 HTTPS。",
                )

    # ── 2. Trigger risk in metadata ──
    meta = scanner._package_metadata
    if meta:
        triggers = meta.get("triggers", meta.get("trigger", []))
        if isinstance(triggers, list):
            if len(triggers) > 10:
                manifest_file = "manifest.json" if (scanner.target_dir / "manifest.json").is_file() else "SKILL.md"
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="low",
                    category="supply_chain",
                    title="过度触发: 声明了超过 10 个触发器",
                    description=f"包声明了 {len(triggers)} 个触发器，可能过度触发。",
                    location={"file": manifest_file},
                    evidence=f"Trigger count: {len(triggers)}",
                    remediation="减少触发器数量至 10 个以内，确保仅对必要关键词响应。",
                )
            if any("*" in str(t) for t in triggers):
                manifest_file = "manifest.json" if (scanner.target_dir / "manifest.json").is_file() else "SKILL.md"
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="low",
                    category="supply_chain",
                    title="触发器使用通配符",
                    description="触发器列表包含 * 通配符，可能匹配过多内容。",
                    location={"file": manifest_file},
                    evidence="Wildcard trigger detected",
                    remediation="将通配符替换为具体关键词。",
                )

        # ── 3. Typosquatting check ──
        _check_typosquatting(scanner, meta)

        # ── 4. OSV CVE query ──
        deps = meta.get("dependencies", {})
        if isinstance(deps, dict):
            for ecosystem, dep_list in deps.items():
                if not isinstance(dep_list, list):
                    continue
                osv_ecosystem = ecosystem.upper() if ecosystem in ("npm", "pypi") else "PyPI"
                for dep in dep_list[:10]:
                    pkg_name = dep.get("name", "") if isinstance(dep, dict) else str(dep)
                    pkg_ver = dep.get("version", "*") if isinstance(dep, dict) else "*"
                    if not pkg_name:
                        continue
                    cves = _query_osv(pkg_name, pkg_ver, osv_ecosystem)
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
