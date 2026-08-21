"""SR-008: Supply chain risk detection.

Checks for:
  - curl/wget pipe to shell (critical)
  - Non-official package registries (high)
  - Unpinned / risky dependency versions (medium)
  - HTTP download URLs (medium)
  - Abandoned / deprecated packages (medium)
  - Typosquatting (Levenshtein distance < 2)
  - Live CVE lookup via OSV.dev API

URL-based patterns run only on code files (.py, .js, .ts, .sh, etc.)
to avoid flagging normal hyperlinks in HTML/MD files.
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
import urllib.error
from urllib.parse import urlsplit
from pathlib import Path
from typing import Any

from scanners.risk_scanner.common import CODE_FILE_EXTENSIONS
from scanners.risk_scanner.patterns import (
    BUILTIN_WELL_KNOWN_PACKAGES,
    DOMAIN_WHITELIST,
    SUPPLY_CHAIN_PATTERNS,
    TRIGGER_RISK_PATTERNS,
)
from scanners.risk_scanner.dependency_parsers import parse_dependencies
from scanners.risk_scanner.dependency_parsers.models import DependencyRecord
from scanners.risk_scanner.dependency_parsers.osv_client import OSVClient

_CVE_CACHE: dict[str, tuple[float, list[str]]] = {}
_CVE_CACHE_TTL = 3600
_LOCKFILE_NAMES = frozenset({
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
})

_URL_BASED_DESCS = frozenset({
    "非官方包源 URL",
    "HTTP 请求指向未知地址",
    "使用 HTTP 明文下载",
    "通过 HTTP 明文下载",
    "依赖解析地址使用 HTTP 明文",
    "全局 npm install",
    "直接 pip install（可能恶意包）",
    "curl pipe shell — 远程脚本下载并执行",
    "wget pipe shell — 远程脚本下载并执行",
})

_DEPRECATION_BASED_DESCS = frozenset({
    "包声明已废弃/不再维护",
})

_DEPENDENCY_CONTEXT = re.compile(
    r"\b(?:pip|npm|pnpm|yarn|cargo|install|registry|dependency|download|curl|wget)\b",
    re.IGNORECASE,
)


def _is_code_file(fname: str) -> bool:
    ext = Path(fname).suffix.lower()
    return ext in CODE_FILE_EXTENSIONS


def _is_whitelisted_url(value: str) -> bool:
    """Match a parsed hostname exactly or as a real subdomain of an allowlisted host."""
    try:
        url_match = re.search(r"https?://[^\s\"'<>`)]+", value, re.IGNORECASE)
        url = (url_match.group(0) if url_match else value).rstrip(".,;:!?")
        hostname = (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    return any(hostname == host or hostname.endswith(f".{host}") for host in DOMAIN_WHITELIST)


def _is_inside_html_comment(lines: list[str], line_no: int) -> bool:
    idx = max(0, line_no - 1)
    line = lines[idx] if idx < len(lines) else ""
    stripped = line.strip()
    return "<!--" in stripped and "-->" in stripped


def _is_lockfile(path: str) -> bool:
    return Path(path).name.lower() in _LOCKFILE_NAMES


def _is_unlocked_version(version: str | None) -> bool:
    value = (version or "").strip()
    return (
        not value
        or value.startswith(("^", "~", ">", "<", "*"))
        or "x" in value.lower()
        or value.lower() in {"latest", "stable", "next"}
    )


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
        pkg_dist = _levenshtein(pkg_name, dep_name)
        if pkg_name and pkg_dist <= 2 and pkg_name != dep_name:
            manifest_file = "manifest.json" if (scanner.target_dir / "manifest.json").is_file() else "SKILL.md"
            scanner._add_finding(
                rule_id="SR-008",
                severity="high",
                category="supply_chain",
                title=f"Typosquatting 检测: 依赖 '{dep_name}' 与包自身名 '{pkg_name}' 相似",
                description=f"依赖包名 '{dep_name}' 与包自身名称 '{pkg_name}' Levenshtein 距离为 {pkg_dist}，可能存在 typosquatting 攻击。",
                location={"file": manifest_file},
                evidence=f"Levenshtein distance: {pkg_dist}, package: {dep_name} vs {pkg_name}",
                remediation=f"验证依赖 '{dep_name}' 是否为包 '{pkg_name}' 的合法依赖，检查其来源和发布历史。",
            )


def _manifest_records(meta: dict[str, Any], source_file: str = "manifest.json") -> list[DependencyRecord]:
    records: list[DependencyRecord] = []
    deps = meta.get("dependencies", {})
    if not isinstance(deps, dict):
        return records
    for ecosystem, values in deps.items():
        if not isinstance(values, list):
            continue
        normalized_ecosystem = {"pypi": "PyPI", "python": "PyPI", "npm": "npm", "rust": "crates.io"}.get(str(ecosystem).lower(), str(ecosystem))
        for value in values:
            if isinstance(value, dict):
                records.append(DependencyRecord(str(value.get("name", "")), value.get("version"), normalized_ecosystem,
                                                True, source_file, value.get("registry"), value.get("integrity")))
            elif value:
                records.append(DependencyRecord(str(value), None, normalized_ecosystem, True, source_file))
    return [record for record in records if record.name]


def _check_dependency_records(scanner: Any, records: list[DependencyRecord]) -> None:
    if not records:
        scanner.dependency_scan = {"status": "complete", "dependencies_found": 0,
                                   "dependencies_queried": 0, "query_failures": 0}
        return
    manifest_file = records[0].source_file
    locked_keys = {
        (record.ecosystem.lower(), record.name.lower())
        for record in records
        if _is_lockfile(record.source_file) and record.version and not _is_unlocked_version(record.version)
    }
    for record in records:
        version = record.version or ""
        reconciled_with_lockfile = (
            not _is_lockfile(record.source_file)
            and (record.ecosystem.lower(), record.name.lower()) in locked_keys
        )
        if _is_unlocked_version(record.version) and not reconciled_with_lockfile:
            scanner._add_finding(
                rule_id="SR-008", severity="medium", category="supply_chain",
                title=f"依赖版本未锁定: {record.name}",
                description=f"依赖 {record.name} 未使用精确版本（当前: {record.version or '未声明'}）。",
                location={"file": record.source_file},
                evidence=f"Dependency version: {record.version or 'missing'}",
                remediation="在清单和锁文件中使用可复现的精确依赖版本。",
            )
        if record.registry and not _is_whitelisted_url(record.registry):
            scanner._add_finding(
                rule_id="SR-008", severity="high", category="supply_chain",
                title=f"非官方依赖源: {record.name}",
                description=f"依赖 {record.name} 使用未列入白名单的 registry。",
                location={"file": record.source_file}, evidence=f"Registry: {record.registry}",
                remediation="仅使用受信任的官方 HTTPS registry。",
            )
    client = getattr(scanner, "osv_client", None)
    compatibility_mode = client is None
    client = client or OSVClient(max_queries=10)
    queried = 0
    failures = 0
    limit_reached = False
    for record in records:
        if compatibility_mode:
            vulnerabilities = _query_osv(record.name, record.version or "*", record.ecosystem)
            result_error = None
            queried += 1
        else:
            result = client.query(record)
            vulnerabilities = result.vulnerability_ids
            result_error = result.error
            if result_error:
                failures += 1
                limit_reached = result_error == "query_limit_exceeded"
            queried = client.queried
        for cve_id in vulnerabilities:
            scanner._add_finding(
                rule_id="SR-008", severity="high", category="supply_chain",
                title=f"供应链风险 — 已知 CVE: {cve_id} in {record.name}@{record.version or '*'}",
                description=f"依赖 {record.name}@{record.version or '*'} 存在已知漏洞 {cve_id}。",
                location={"file": record.source_file}, evidence=f"OSV.dev: {cve_id}",
                remediation=f"升级 {record.name} 到修复版本，或替换为安全替代包。",
            )
    scanner.dependency_scan = {
        "status": "partial" if failures or limit_reached else "complete",
        "dependencies_found": len(records),
        "dependencies_queried": queried,
        "query_failures": failures,
    }
    if limit_reached:
        scanner.dependency_scan["query_limit"] = getattr(client, "max_queries", 10)


def run(scanner: Any) -> None:
    rule_id = "SR-008"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        if not content:
            continue
        lines = content.split("\n")

        for pattern, desc, severity in SUPPLY_CHAIN_PATTERNS:
            is_url_based = desc in _URL_BASED_DESCS
            is_deprecation = desc in _DEPRECATION_BASED_DESCS

            if is_url_based and not _is_code_file(fname):
                continue

            if is_deprecation and not _is_code_file(fname):
                continue

            for match in re.finditer(pattern, content, re.IGNORECASE):
                matched_url = match.group()

                if is_url_based:
                    if "://" in matched_url:
                        if _is_whitelisted_url(matched_url):
                            continue

                line_no = content[: match.start()].count("\n") + 1

                if is_deprecation and _is_inside_html_comment(lines, line_no):
                    continue

                snippet = "\n".join(lines[max(0, line_no - 1):line_no])
                finding_severity = severity
                if desc == "非官方包源 URL" and not _DEPENDENCY_CONTEXT.search(snippet):
                    # A logo/API/static-resource URL is not evidence of dependency
                    # compromise. Keep it visible as a low-confidence review hint.
                    finding_severity = "low"
                if scanner._is_code_example(fname, line_no):
                    finding_severity = "medium" if finding_severity == "critical" else "low"

                scanner._add_finding(
                    rule_id=rule_id,
                    severity=finding_severity,
                    category="supply_chain",
                    title=f"供应链风险 — {desc}",
                    description=f"在 {fname} 中发现供应链风险模式：{desc}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配: {matched_url[:120]}",
                    remediation="使用锁定的依赖管理器（npm/pip）并验证包完整性。仅使用官方源和 HTTPS。",
                )

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

    # Lockfiles/manifests are parsed once into normalized records. Lockfiles are
    # intentionally absent from scanner.scanned_files, so generic regex rules do
    # not inspect their structured contents.
    records = parse_dependencies(getattr(scanner, "_file_contents", {}))
    if not records and meta:
        records = _manifest_records(meta)
    if records and meta:
        normalized_meta = dict(meta)
        normalized_meta["dependencies"] = {
            "normalized": [{"name": record.name, "version": record.version} for record in records]
        }
        _check_typosquatting(scanner, normalized_meta)
    _check_dependency_records(scanner, records)
