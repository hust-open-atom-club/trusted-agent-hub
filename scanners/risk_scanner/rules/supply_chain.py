"""SR-008: Supply chain risk detection.

Checks for:
  - curl/wget pipe to shell (critical)
  - Dependency registry policy mismatches (grouped review advisories)
  - Unpinned / risky dependency versions (medium)
  - HTTP download URLs (medium)
  - Abandoned / deprecated packages (medium)
  - Typosquatting (Levenshtein distance < 2)
  - Live CVE lookup via OSV.dev API

URL-based patterns run only on code files (.py, .js, .ts, .sh, etc.)
to avoid flagging normal hyperlinks in HTML/MD files.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
import time
import urllib.request
import urllib.error
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from scanners.risk_scanner.common import CODE_FILE_EXTENSIONS
from scanners.risk_scanner.analyzers.url_context import (
    URL_USAGE_DEPENDENCY,
    URL_USAGE_DOWNLOAD_EXECUTE,
    URL_USAGE_NETWORK_REQUEST,
    classify_url_usage,
    is_loopback_url,
)
from scanners.risk_scanner.patterns import (
    BUILTIN_WELL_KNOWN_PACKAGES,
    SUPPLY_CHAIN_PATTERNS,
)
from scanners.risk_scanner.dependency_parsers import (
    parse_dependencies,
    parse_dependency_sources,
)
from scanners.risk_scanner.dependency_parsers.models import (
    DependencyRecord,
    DependencySourceObservation,
    DependencySourceUsage,
)
from scanners.risk_scanner.dependency_parsers.osv_client import OSVClient
from scanners.risk_scanner.registry_policy import (
    DEFAULT_REGISTRY_POLICY,
    RegistryPolicy,
    normalize_ecosystem,
)
from scanners.risk_scanner.redaction import redact_text

_CVE_CACHE: dict[str, tuple[float, list[str]]] = {}
_CVE_CACHE_TTL = 3600
_LOCKFILE_NAMES = frozenset({
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
})
_MAX_REGISTRY_POLICY_GROUPS = 25
_MAX_REGISTRY_POLICY_OCCURRENCES_PER_GROUP = 100
_MAX_REGISTRY_POLICY_OCCURRENCES_TOTAL = 500

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

_TRIGGER_WILDCARD_PATTERN = re.compile(
    r"\btriggers?\b[\"']?\s*[=:]\s*\[[^\]]*?\*[^\]]*?\]",
    re.IGNORECASE,
)
_TRIGGER_DECLARATION_EXTENSIONS = frozenset({
    ".json",
    ".jsonc",
    ".toml",
    ".yaml",
    ".yml",
})
# ``#`` is a line-comment marker for these syntaxes.  It is intentionally
# not treated as a comment in JavaScript/JSON-like files, where it can be a
# private-field or other language token.
_HASH_COMMENT_EXTENSIONS = frozenset({
    ".bash",
    ".ps1",
    ".py",
    ".rb",
    ".sh",
    ".toml",
    ".yml",
    ".yaml",
    ".zsh",
})
_UNAPPROVED_SOURCE_REASONS = frozenset({
    "invalid_url",
    "non_registry_source",
    "unknown_host",
})
_POLICY_MISMATCH_REASONS = frozenset({
    "canonical_url_mismatch",
    "unapproved_port",
    "usage_not_allowed",
    "wrong_ecosystem",
})
_UNSAFE_TRANSPORT_REASONS = frozenset({
    "credentials_in_url",
    "insecure_scheme",
})


def _is_code_file(fname: str) -> bool:
    ext = Path(fname).suffix.lower()
    return ext in CODE_FILE_EXTENSIONS


def _dependency_ecosystem_near_line(
    lines: list[str], line_no: int
) -> str | None:
    """Infer ecosystem only when installer/registry syntax makes it explicit."""
    start = max(0, line_no - 3)
    end = min(len(lines), line_no + 2)
    context = "\n".join(lines[start:end]).casefold()
    if re.search(r"\b(?:npm|pnpm|yarn|node)\b|\.npmrc", context):
        return "npm"
    if re.search(r"\b(?:pip|pip3|poetry|pypi|python\s+-m\s+pip)\b", context):
        return "pypi"
    if re.search(r"\b(?:cargo|crates\.io)\b", context):
        return "cargo"
    if re.search(r"\b(?:nuget|dotnet\s+(?:add|restore))\b", context):
        return "nuget"
    return None


def _dependency_usage_near_line(
    lines: list[str], line_no: int
) -> DependencySourceUsage:
    line = lines[line_no - 1].casefold() if 0 < line_no <= len(lines) else ""
    if 1 < line_no <= len(lines):
        previous_line = lines[line_no - 2].rstrip()
        if previous_line.endswith("\\"):
            line = f"{previous_line[:-1].casefold()} {line}"
    if re.search(r"(?:^|\s)--find-links(?:\s|=)", line):
        return "resolved_download"
    if (
        re.search(r"(?:^|\s)-f(?:\s|=)", line)
        and _dependency_ecosystem_near_line(lines, line_no) == "pypi"
    ):
        return "resolved_download"
    if re.search(
        r"\bregistry\b|--(?:extra-)?index-url\b"
        r"|(?:^|\s)-i(?=\s|=|$)|\badd\s+source\b",
        line,
    ):
        return "registry_api"
    return "resolved_download"


def _has_unquoted_line_comment(prefix: str, filename: str) -> bool:
    hash_comments = Path(filename).suffix.casefold() in _HASH_COMMENT_EXTENSIONS
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(prefix):
        char = prefix[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in {"\"", "'", "`"}:
            quote = char
        elif (hash_comments and char == "#") or (
            prefix.startswith("//", index)
            and (index == 0 or prefix[index - 1] != ":")
        ):
            return True
        elif prefix.startswith("<!--", index):
            return True
        index += 1
    return False


def _match_is_commented(content: str, match_start: int, filename: str) -> bool:
    line_start = content.rfind("\n", 0, match_start) + 1
    if _has_unquoted_line_comment(
        content[line_start:match_start], filename
    ):
        return True
    preceding = content[:match_start]
    return (
        preceding.rfind("/*") > preceding.rfind("*/")
        or preceding.rfind("<!--") > preceding.rfind("-->")
    )


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
        # A source_ref is a JSON Pointer into the input manifest, so its token
        # must use the original key rather than the normalized ecosystem label.
        ecosystem_pointer = str(ecosystem).replace("~", "~0").replace("/", "~1")
        for index, value in enumerate(values):
            if isinstance(value, dict):
                registry = value.get("registry")
                scope = value.get("scope", "runtime")
                if not isinstance(scope, str) or scope not in {"runtime", "dev", "test", "optional", "mixed", "unknown"}:
                    scope = "unknown"
                records.append(
                    DependencyRecord(
                        str(value.get("name", "")),
                        value.get("version"),
                        normalized_ecosystem,
                        True,
                        source_file,
                        registry=registry,
                        integrity=value.get("integrity") if isinstance(value.get("integrity"), str) else None,
                        registry_usage="registry_api" if registry else None,
                        scope=scope,
                        source_ref=f"#/dependencies/{ecosystem_pointer}/{index}",
                    )
                )
            elif value:
                records.append(DependencyRecord(
                    str(value), None, normalized_ecosystem, True, source_file,
                    scope="runtime",
                    source_ref=f"#/dependencies/{ecosystem_pointer}/{index}",
                ))
    return [record for record in records if record.name]


def _format_counter(counter: Counter[str], *, limit: int = 5) -> str:
    ordered = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    shown = ", ".join(f"{name} ({count})" for name, count in ordered[:limit])
    omitted = len(ordered) - limit
    return f"{shown}; 另有 {omitted} 个" if omitted > 0 else shown


def _source_evidence_url(value: str) -> str:
    """Retain the source address without exposing URL credentials or tokens."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return redact_text(value.split("?", 1)[0].split("#", 1)[0])
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    return redact_text(urlunsplit((parsed.scheme, netloc, parsed.path, "", "")))


def _evidence_sample(value: str | None, limit: int) -> str | None:
    if value is None or len(value) <= limit:
        return value
    return value[:limit - 1] + "…"


def _check_dependency_sources(
    scanner: Any,
    observations: list[DependencySourceObservation],
) -> None:
    policy: RegistryPolicy = (
        getattr(scanner, "registry_policy", None) or DEFAULT_REGISTRY_POLICY
    )
    rejected = []
    groups: dict[
        tuple[str, str, str, str],
        list[tuple[DependencySourceObservation, Any]],
    ] = {}
    # Exact duplicate observations are harmless, but URL-only deduplication
    # erases separate lockfile entries and their integrity claims.
    for observation in dict.fromkeys(observations):
        decision = policy.evaluate(
            observation.ecosystem,
            observation.url,
            observation.usage,
        )
        if not decision.allowed:
            rejected.append((observation, decision))
            key = (
                normalize_ecosystem(observation.ecosystem),
                decision.normalized_host or observation.url,
                observation.source_file,
                decision.reason,
            )
            groups.setdefault(key, []).append((observation, decision))
    if not rejected:
        return

    ordered_groups = sorted(
        groups.items(),
        key=lambda entry: (
            1 if {item.scope for item, _ in entry[1]} <= {"dev", "test"} else 0,
            -len(entry[1]),
            entry[0],
        ),
    )
    visible_groups = ordered_groups[:_MAX_REGISTRY_POLICY_GROUPS]
    base_quota = min(
        _MAX_REGISTRY_POLICY_OCCURRENCES_PER_GROUP,
        max(1, _MAX_REGISTRY_POLICY_OCCURRENCES_TOTAL // len(visible_groups)),
    )
    quotas = [min(len(items), base_quota) for _, items in visible_groups]
    remaining = _MAX_REGISTRY_POLICY_OCCURRENCES_TOTAL - sum(quotas)
    for index, (_, items) in enumerate(visible_groups):
        extra = min(
            remaining,
            len(items) - quotas[index],
            _MAX_REGISTRY_POLICY_OCCURRENCES_PER_GROUP - quotas[index],
        )
        quotas[index] += extra
        remaining -= extra

    for ((ecosystem, _registry_identity, source_file, reason), items), quota in zip(
        visible_groups, quotas,
    ):
        count = len(items)
        source_file_display = _evidence_sample(source_file, 512)
        sorted_items = sorted(
            items,
            key=lambda entry: (
                entry[0].source_file,
                entry[0].dependency_name or "",
                entry[0].line or 0,
                _source_evidence_url(entry[0].url),
                entry[0].source_ref or "",
                entry[0].dependency_version or "",
                entry[0].integrity or "",
                entry[0].scope,
                str(entry[0].usage),
            ),
        )
        scopes = {observation.scope for observation, _ in items}
        scope = next(iter(scopes)) if len(scopes) == 1 else "mixed"
        host = items[0][1].normalized_host or "<invalid-or-non-registry-url>"
        url_samples = ""
        if items[0][1].normalized_host is None:
            urls = sorted({
                _evidence_sample(_source_evidence_url(observation.url), 160)
                for observation, _ in items
            })
            url_samples = f"; url_samples={', '.join(urls[:5])}"
        if reason in _UNAPPROVED_SOURCE_REASONS:
            reason_group = "source_unapproved"
            action = (
                f"来源本身未经批准 {count} 条"
                "（改用官方源，或经运维审核后加入 "
                "TAH_APPROVED_PRIVATE_REGISTRIES_JSON）"
            )
        elif reason in _POLICY_MISMATCH_REASONS:
            reason_group = "policy_mismatch"
            action = (
                f"已批准端点的使用方式不匹配 {count} 条"
                "（修正路径、端口、生态或用途，通常无需新增审批）"
            )
        elif reason in _UNSAFE_TRANSPORT_REASONS:
            reason_group = "unsafe_transport"
            action = (
                f"传输或凭据不安全 {count} 条"
                "（改用 HTTPS 并移除 URL 内嵌凭据）"
            )
        else:
            reason_group = "other"
            action = f"其他策略拒绝 {count} 条（按 reason 人工复核）"
        affected_dependencies = {
            observation.dependency_name.casefold()
            for observation, _ in items
            if observation.dependency_name
        }
        dependency_summary = (
            f"影响 {len(affected_dependencies)} 个依赖名称；"
            if affected_dependencies else "未能关联到具体依赖；"
        )
        occurrences = [
            {
                "file": _evidence_sample(observation.source_file, 512),
                "source_ref": _evidence_sample(observation.source_ref, 256),
                "line": observation.line,
                "dependency_name": _evidence_sample(observation.dependency_name, 128),
                "version": _evidence_sample(observation.dependency_version, 128),
                "resolved_url": _evidence_sample(_source_evidence_url(observation.url), 512),
                "integrity": _evidence_sample(observation.integrity, 160),
                "scope": observation.scope,
                "usage": str(observation.usage),
            }
            for observation, _ in sorted_items[:quota]
        ]
        samples = [
            f"{_evidence_sample(observation.dependency_name, 128)}@"
            f"{_evidence_sample(observation.dependency_version, 128) or '?'}"
            for observation, _ in sorted_items
            if observation.dependency_name
        ][:5]
        scanner._add_advisory(
            code="dependency_registry_policy",
            category="registry_policy",
            level="warning" if scopes <= {"dev", "test"} else "high",
            title="依赖来源策略需要人工复核",
            description=(
                f"检测到 {count} 条依赖来源策略记录需要复核，"
                f"涉及 1 个来源端点，{dependency_summary}"
                f"处置分类：{action}。"
                "来源获批与依赖本身是否安全是两个独立判断。"
            ),
            deduction=0,
            affects_grade=False,
            requires_manual_review=True,
            evidence=(
                f"policy={policy.version}; hosts={host} ({count}); "
                f"reasons={reason} ({count}); groups={reason_group} ({count}); "
                f"files={source_file_display} ({count}); scope={scope}; "
                f"samples={', '.join(samples)}{url_samples}"
            ),
            location={"file": source_file_display},
            registry_policy={
                "ecosystem": ecosystem,
                "registry_host": host,
                "policy_reason": reason,
                "source_file": source_file_display,
                "scope": scope,
                "occurrence_count": count,
                "occurrences": occurrences,
                "truncated": count > len(occurrences),
            },
        )

    omitted_groups = ordered_groups[_MAX_REGISTRY_POLICY_GROUPS:]
    if omitted_groups:
        omitted_count = sum(len(items) for _, items in omitted_groups)
        omitted_hosts = Counter(
            decision.normalized_host or "<invalid-or-non-registry-url>"
            for _, items in omitted_groups
            for _, decision in items
        )
        omitted_reasons = Counter(
            key[3] for key, items in omitted_groups for _ in items
        )
        omitted_high = any(
            not {observation.scope for observation, _ in items} <= {"dev", "test"}
            for _, items in omitted_groups
        )
        scanner._add_advisory(
            code="dependency_registry_policy_overflow",
            category="registry_policy",
            level="high" if omitted_high else "warning",
            title="依赖来源策略分组超出报告上限",
            description=(
                f"另有 {len(omitted_groups)} 个来源策略分组、{omitted_count} 条记录"
                "未逐组展示；仍需人工复核这些来源。"
            ),
            deduction=0,
            affects_grade=False,
            requires_manual_review=True,
            evidence=(
                f"omitted_groups={len(omitted_groups)}; omitted_occurrences={omitted_count}; "
                f"hosts={_format_counter(omitted_hosts)}; "
                f"reasons={_format_counter(omitted_reasons)}"
            ),
            location={"file": _evidence_sample(omitted_groups[0][0][2], 512)},
        )

    insecure = [
        (observation, decision)
        for observation, decision in rejected
        if decision.reason == "insecure_scheme"
    ]
    if insecure:
        insecure_hosts: Counter[str] = Counter(
            decision.normalized_host or "<invalid-url>"
            for _, decision in insecure
        )
        scanner._add_finding(
            rule_id="SR-008",
            severity="medium",
            category="supply_chain",
            title="依赖来源使用 HTTP 明文传输",
            description=(
                f"检测到 {len(insecure)} 条通过 HTTP 访问依赖来源的记录，"
                "传输过程可能被篡改。"
            ),
            location={"file": insecure[0][0].source_file},
            evidence=f"Hosts: {_format_counter(insecure_hosts)}",
            remediation="将依赖源和下载地址改为经策略批准的 HTTPS 端点。",
            kind="vulnerability",
            disposition="confirmed_vulnerability",
            sink_kind="dependency_resolution",
            source_kind="dependency_registry",
            source_control="remote_publisher",
            reachability="dependency_installation",
            activation="direct",
            trust_boundary_crossed=True,
            llm_review_exempt=True,
        )


def _check_dependency_records(scanner: Any, records: list[DependencyRecord]) -> None:
    if not records:
        scanner.dependency_scan = {"status": "complete", "dependencies_found": 0,
                                   "dependencies_queried": 0, "query_failures": 0}
        return
    locked_keys = {
        (record.ecosystem.lower(), record.name.lower())
        for record in records
        if _is_lockfile(record.source_file) and record.version and not _is_unlocked_version(record.version)
    }
    for record in records:
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
                llm_review_exempt=True,
            )
    client = getattr(scanner, "osv_client", None)
    compatibility_mode = client is None
    client = client or OSVClient()
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
                llm_review_exempt=True,
            )
    scanner.dependency_scan = {
        "status": "partial" if failures or limit_reached else "complete",
        "dependencies_found": len(records),
        "dependencies_queried": queried,
        "query_failures": failures,
    }
    if limit_reached:
        scanner.dependency_scan["query_limit"] = getattr(client, "max_queries", None)


def _integrity_matches(content: bytes, claim: object) -> bool | None:
    """Verify the strongest usable SRI digest; None means the claim is unsupported."""
    if not isinstance(claim, str):
        return None
    algorithms = {"sha512": 4, "sha384": 3, "sha256": 2, "sha1": 1}
    candidates: list[tuple[int, str, bytes]] = []
    for token in claim.split():
        if ":" in token and "-" not in token:
            algorithm, encoded = token.split(":", 1)
            try:
                expected = bytes.fromhex(encoded)
            except ValueError:
                continue
        elif "-" in token:
            algorithm, encoded = token.split("-", 1)
            try:
                expected = base64.b64decode(encoded.split("?", 1)[0], validate=True)
            except (ValueError, binascii.Error):
                continue
        else:
            continue
        algorithm = algorithm.casefold()
        if algorithm in algorithms and len(expected) == hashlib.new(algorithm).digest_size:
            candidates.append((algorithms[algorithm], algorithm, expected))
    if not candidates:
        return None
    strongest = max(candidate[0] for candidate in candidates)
    return any(
        hmac.compare_digest(hashlib.new(algorithm, content).digest(), expected)
        for priority, algorithm, expected in candidates
        if priority == strongest
    )


def _check_dependency_integrity(scanner: Any, records: list[DependencyRecord]) -> None:
    """Check acquired bytes only; never fetch URLs authored by a package."""
    claims = [
        record for record in records
        if _is_lockfile(record.source_file)
        and record.integrity
        and record.registry
        and record.registry_usage == "resolved_download"
    ]
    artifacts = getattr(scanner, "dependency_artifacts", {})
    verified = 0
    unavailable = 0
    unsupported = 0
    mismatches: dict[str, list[DependencyRecord]] = {}
    for record in claims:
        content = artifacts.get(record.registry) if isinstance(artifacts, dict) else None
        if not isinstance(content, bytes):
            unavailable += 1
            continue
        matches = _integrity_matches(content, record.integrity)
        if matches is None:
            unsupported += 1
        else:
            verified += 1
            if not matches:
                mismatches.setdefault(record.source_file, []).append(record)
    mismatch_count = sum(len(items) for items in mismatches.values())
    for source_file, items in sorted(mismatches.items()):
        samples = ", ".join(
            f"{record.name}@{record.version or '?'} ({record.source_ref or '?'})"
            for record in items[:5]
        )
        scanner._add_finding(
            rule_id="SR-008", severity="high", category="supply_chain",
            title="依赖制品与锁文件完整性摘要不一致",
            description=f"已获取的依赖制品有 {len(items)} 条与锁文件声明的摘要不一致。",
            location={"file": source_file},
            evidence=f"mismatches={len(items)}; samples={samples}",
            remediation="核对获取的制品、锁文件摘要与发布来源，重新锁定可信版本。",
            llm_review_exempt=True,
        )
    if not claims:
        status = "not_applicable"
    elif mismatch_count:
        status = "mismatch"
    elif verified == len(claims):
        status = "verified"
    elif unsupported and not verified and not unavailable:
        status = "unsupported"
    elif verified or unsupported:
        status = "partial"
    else:
        status = "not_checked"
    scanner.dependency_scan["integrity"] = {
        "status": status,
        "claimed_count": len(claims),
        "verified_count": verified,
        "mismatch_count": mismatch_count,
        "unavailable_count": unavailable,
        "unsupported_count": unsupported,
    }


def _exact_npm_version(value: object) -> tuple[int, int, int, str, str] | None:
    if not isinstance(value, str):
        return None
    match = re.fullmatch(
        r"\s*=?\s*v?([0-9]{1,9})\.([0-9]{1,9})\.([0-9]{1,9})(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?\s*",
        value,
    )
    if not match:
        return None
    return (
        int(match.group(1)), int(match.group(2)), int(match.group(3)),
        match.group(4) or "", match.group(5) or "",
    )


def _same_npm_declaration(declared: object, locked: object) -> bool | None:
    if not isinstance(declared, str) or not isinstance(locked, str):
        return None
    if declared == locked:
        return True
    declared_exact = _exact_npm_version(declared)
    locked_exact = _exact_npm_version(locked)
    if declared_exact is not None and locked_exact is not None:
        return declared_exact == locked_exact
    return None


def _check_manifest_lock_consistency(scanner: Any, files: dict[str, str]) -> None:
    """Compare declarations when equality is provable without resolving ranges."""
    checked = 0
    mismatch_count = 0
    unchecked_count = 0
    for lock_file, content in sorted(files.items()):
        if PurePosixPath(lock_file).name.casefold() not in {
            "package-lock.json", "npm-shrinkwrap.json",
        }:
            continue
        manifest_file = str(PurePosixPath(lock_file).with_name("package.json"))
        if manifest_file not in files:
            continue
        try:
            manifest = json.loads(files[manifest_file])
            lock = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(manifest, dict) or not isinstance(lock, dict):
            continue
        packages = lock.get("packages")
        root = packages.get("") if isinstance(packages, dict) else None
        if not isinstance(root, dict):
            continue
        checked += 1
        differences: list[str] = []
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            declared = manifest.get(section, {})
            locked = root.get(section, {})
            if not isinstance(declared, dict) or not isinstance(locked, dict):
                differences.append(f"{section}: invalid declaration")
                continue
            for name in sorted(declared.keys() | locked.keys()):
                if name not in declared or name not in locked:
                    differences.append(f"{section}/{name}")
                    continue
                same = _same_npm_declaration(declared[name], locked[name])
                if same is False:
                    differences.append(f"{section}/{name}")
                elif same is None:
                    unchecked_count += 1
        if differences:
            mismatch_count += len(differences)
            scanner._add_finding(
                rule_id="SR-008", severity="medium", category="supply_chain",
                title="依赖清单与锁文件根声明不一致",
                description=f"{manifest_file} 与 {lock_file} 存在 {len(differences)} 项直接依赖声明差异。",
                location={"file": lock_file},
                evidence=f"differences={len(differences)}; samples={', '.join(differences[:5])}",
                remediation="重新生成锁文件并核对差异，再使用锁定的依赖安装。",
                llm_review_exempt=True,
            )
    scanner.dependency_scan["manifest_lock"] = {
        "status": (
            "not_checked" if not checked else "mismatch" if mismatch_count
            else "partial" if unchecked_count else "matched"
        ),
        "checked_pairs": checked,
        "mismatch_count": mismatch_count,
        "unchecked_count": unchecked_count,
    }


def run(scanner: Any) -> None:
    rule_id = "SR-008"
    inline_source_observations: list[DependencySourceObservation] = []
    wildcard_trigger_location: dict[str, Any] | None = None
    wildcard_trigger_evidence = ""

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        if not content:
            continue
        lines = content.split("\n")

        # Parsed metadata is the preferred trigger source, but projects without
        # a manifest still need deterministic coverage for code/config arrays.
        if wildcard_trigger_location is None and (
            _is_code_file(fname)
            or Path(fname).suffix.casefold() in _TRIGGER_DECLARATION_EXTENSIONS
        ):
            for trigger_match in _TRIGGER_WILDCARD_PATTERN.finditer(content):
                if _match_is_commented(content, trigger_match.start(), fname):
                    continue
                wildcard_offsets = (
                    trigger_match.start() + match.start()
                    for match in re.finditer(r"\*", trigger_match.group())
                )
                if not any(
                    not _match_is_commented(content, offset, fname)
                    for offset in wildcard_offsets
                ):
                    continue
                trigger_line = content[:trigger_match.start()].count("\n") + 1
                snippet = lines[trigger_line - 1] if trigger_line <= len(lines) else ""
                wildcard_trigger_location = {
                    "file": fname,
                    "line": trigger_line,
                    "snippet": snippet[:200],
                }
                wildcard_trigger_evidence = (
                    f"匹配: {trigger_match.group()[:120]}"
                )
                break

        for pattern, desc, severity in SUPPLY_CHAIN_PATTERNS:
            is_url_based = desc in _URL_BASED_DESCS
            is_deprecation = desc in _DEPRECATION_BASED_DESCS

            if is_url_based and not _is_code_file(fname):
                continue

            if is_deprecation and not _is_code_file(fname):
                continue

            for match in re.finditer(pattern, content, re.IGNORECASE):
                matched_url = match.group()
                line_no = content[: match.start()].count("\n") + 1
                url_usage = classify_url_usage(content, line_no, matched_url)

                if (
                    desc == "依赖版本号使用通配符 *"
                    and _match_is_commented(content, match.start(), fname)
                ):
                    continue

                if is_url_based:
                    if "://" in matched_url and is_loopback_url(matched_url):
                        continue
                    if desc == "非官方包源 URL":
                        # A URL literal is not a package source. Registry and
                        # installer context is required before SR-008 applies.
                        if url_usage != URL_USAGE_DEPENDENCY:
                            continue
                        inline_source_observations.append(
                            DependencySourceObservation(
                                ecosystem=(
                                    _dependency_ecosystem_near_line(
                                        lines, line_no
                                    )
                                    or "unknown"
                                ),
                                url=matched_url.rstrip(".,;:!?"),
                                usage=_dependency_usage_near_line(
                                    lines, line_no
                                ),
                                source_file=fname,
                                source_ref=f"L{line_no}",
                                line=line_no,
                            )
                        )
                        continue
                    elif desc == "HTTP 请求指向未知地址":
                        # Arbitrary outbound requests are network behavior,
                        # not evidence of dependency compromise.
                        continue
                    elif desc in {
                        "使用 HTTP 明文下载",
                        "通过 HTTP 明文下载",
                        "依赖解析地址使用 HTTP 明文",
                    }:
                        if url_usage == URL_USAGE_DEPENDENCY:
                            # Dependency HTTP is emitted once by the structured
                            # source-policy aggregation below.
                            continue
                        if url_usage not in {
                            URL_USAGE_DOWNLOAD_EXECUTE,
                            URL_USAGE_NETWORK_REQUEST,
                        }:
                            continue

                if is_deprecation and _is_inside_html_comment(lines, line_no):
                    continue

                snippet = "\n".join(lines[max(0, line_no - 1):line_no])
                finding_severity = severity
                if scanner._is_code_example(fname, line_no):
                    finding_severity = "medium" if finding_severity == "critical" else "low"

                semantic: dict[str, Any] = {}
                if url_usage == URL_USAGE_DOWNLOAD_EXECUTE:
                    semantic = {
                        "kind": "vulnerability",
                        "disposition": "confirmed_vulnerability",
                        "sink_kind": "download_execute",
                        "sink_symbol": "shell",
                        "source_kind": "remote_script",
                        "source_control": "remote_publisher",
                        "reachability": "install_or_script_execution",
                        "activation": "direct",
                        "trust_boundary_crossed": True,
                    }

                scanner._add_finding(
                    rule_id=rule_id,
                    severity=finding_severity,
                    category="supply_chain",
                    title=f"供应链风险 — {desc}",
                    description=f"在 {fname} 中发现供应链风险模式：{desc}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配: {matched_url[:120]}",
                    remediation="使用锁定的依赖管理器（npm/pip）并验证包完整性。仅使用官方源和 HTTPS。",
                    **semantic,
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
                if wildcard_trigger_location is None:
                    wildcard_trigger_location = {"file": manifest_file}
                    wildcard_trigger_evidence = "Wildcard trigger detected"

    if wildcard_trigger_location is not None:
        scanner._add_finding(
            rule_id=rule_id,
            severity="low",
            category="supply_chain",
            title="触发器使用通配符",
            description="触发器列表包含 * 通配符，可能匹配过多内容。",
            location=wildcard_trigger_location,
            evidence=wildcard_trigger_evidence,
            remediation="将通配符替换为具体关键词。",
        )

    # Lockfiles/manifests are parsed once into normalized records. Lockfiles are
    # intentionally absent from scanner.scanned_files, so generic regex rules do
    # not inspect their structured contents.
    metadata_source = next(
        (path for path in ("manifest.json", "plugin.json", "SKILL.md")
         if path in getattr(scanner, "_file_contents", {})),
        "manifest.json",
    )
    manifest_records = _manifest_records(meta, metadata_source) if meta else []
    records = parse_dependencies(getattr(scanner, "_file_contents", {}))
    if records:
        # Parsed files and manifest metadata can describe distinct sources.
        source_records = [*records, *manifest_records]
    else:
        records = manifest_records
        source_records = records
    sources = parse_dependency_sources(
        getattr(scanner, "_file_contents", {}),
        source_records,
    )
    sources.extend(inline_source_observations)
    _check_dependency_sources(scanner, sources)
    if records and meta:
        normalized_meta = dict(meta)
        normalized_meta["dependencies"] = {
            "normalized": [{"name": record.name, "version": record.version} for record in records]
        }
        _check_typosquatting(scanner, normalized_meta)
    _check_dependency_records(scanner, records)
    _check_dependency_integrity(scanner, records)
    _check_manifest_lock_consistency(scanner, getattr(scanner, "_file_contents", {}))
