"""SR-008: Supply chain risk detection.

Checks for:
  - curl/wget pipe to shell (critical)
  - Dependency registry policy mismatches (one review advisory per scan)
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
from collections import Counter
from pathlib import Path
from typing import Any

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
from scanners.risk_scanner.logical_lines import LogicalLine, iter_logical_lines
from scanners.risk_scanner.registry_policy import (
    DEFAULT_REGISTRY_POLICY,
    RegistryPolicy,
)

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
_COMMAND_TOKEN = re.compile(
    r'''(?:[^\s"';&|]+|"(?:\\.|[^"\\])*"|'[^']*')+|[;&|]+'''
)
_REGISTRY_OPTIONS = frozenset({
    "--index-url", "--extra-index-url", "-i", "--registry",
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


def _is_registry_config_key(value: str) -> bool:
    return value == "registry" or (
        value.startswith(("@", "//")) and value.endswith(":registry")
    )


def _dependency_usage_for_url(
    command: str, url_offset: int
) -> DependencySourceUsage:
    """Bind only this URL occurrence to its option in the logical command."""
    previous: list[str] = []
    options_ended = False
    for token in _COMMAND_TOKEN.finditer(command):
        if token.start() <= url_offset < token.end():
            if options_ended:
                break
            prefix = command[token.start():url_offset].strip("\"'").casefold()
            if prefix:
                # --index-url=URL (optionally quoted), or the short -iURL form.
                option = prefix[:-1] if prefix.endswith("=") else prefix
                if (
                    option in _REGISTRY_OPTIONS or _is_registry_config_key(option)
                ) and (
                    prefix.endswith("=") or option == "-i"
                ):
                    return "registry_api"
            elif previous:
                option = previous[-1]
                # Do not strip a trailing '=': --option= supplies an empty
                # value, leaving a whitespace-separated URL positional, even
                # when that whitespace is indentation on a continued line.
                if option == "=" and len(previous) > 1:
                    option = previous[-2]
                    if _is_registry_config_key(option):
                        return "registry_api"
                if (
                    option in _REGISTRY_OPTIONS
                    or (
                        previous[-2:-1] == ["set"]
                        and _is_registry_config_key(option)
                    )
                    or previous[-3:] == ["nuget", "add", "source"]
                ):
                    return "registry_api"
            break
        value = token.group().strip("\"'").casefold()
        if value in {";", "&", "&&", "|", "||"}:
            previous = []
            options_ended = False
        else:
            previous.append(value)
            if value == "--":
                options_ended = True
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
        for value in values:
            if isinstance(value, dict):
                registry = value.get("registry")
                records.append(
                    DependencyRecord(
                        str(value.get("name", "")),
                        value.get("version"),
                        normalized_ecosystem,
                        True,
                        source_file,
                        registry=registry,
                        integrity=value.get("integrity"),
                        registry_usage="registry_api" if registry else None,
                    )
                )
            elif value:
                records.append(DependencyRecord(str(value), None, normalized_ecosystem, True, source_file))
    return [record for record in records if record.name]


def _format_counter(counter: Counter[str], *, limit: int = 5) -> str:
    ordered = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    shown = ", ".join(f"{name} ({count})" for name, count in ordered[:limit])
    omitted = len(ordered) - limit
    return f"{shown}; 另有 {omitted} 个" if omitted > 0 else shown


def _check_dependency_sources(
    scanner: Any,
    observations: list[DependencySourceObservation],
) -> None:
    policy: RegistryPolicy = (
        getattr(scanner, "registry_policy", None) or DEFAULT_REGISTRY_POLICY
    )
    unique_observations: dict[
        tuple[str, str, DependencySourceUsage],
        DependencySourceObservation,
    ] = {}
    observation_files: dict[
        tuple[str, str, DependencySourceUsage], set[str]
    ] = {}
    for observation in observations:
        key = (
            observation.ecosystem.casefold(),
            observation.url,
            observation.usage,
        )
        observation_files.setdefault(key, set()).add(observation.source_file)
        existing = unique_observations.get(key)
        if existing is None or (
            existing.dependency_name is None
            and observation.dependency_name is not None
        ):
            unique_observations[key] = observation

    rejected = []
    file_counts: Counter[str] = Counter()
    for key, observation in unique_observations.items():
        decision = policy.evaluate(
            observation.ecosystem,
            observation.url,
            observation.usage,
        )
        if not decision.allowed:
            rejected.append((observation, decision))
            file_counts.update(observation_files[key])
    if not rejected:
        return

    host_counts: Counter[str] = Counter(
        decision.normalized_host or "<invalid-or-non-registry-url>"
        for _, decision in rejected
    )
    reason_counts: Counter[str] = Counter(
        decision.reason for _, decision in rejected
    )
    reason_group_counts: Counter[str] = Counter()
    for reason, count in reason_counts.items():
        if reason in _UNAPPROVED_SOURCE_REASONS:
            reason_group_counts["source_unapproved"] += count
        elif reason in _POLICY_MISMATCH_REASONS:
            reason_group_counts["policy_mismatch"] += count
        elif reason in _UNSAFE_TRANSPORT_REASONS:
            reason_group_counts["unsafe_transport"] += count
        else:
            reason_group_counts["other"] += count
    affected_dependencies = {
        (
            observation.ecosystem.casefold(),
            observation.dependency_name.casefold(),
        )
        for observation, _ in rejected
        if observation.dependency_name
    }
    source_files = sorted(file_counts)
    dependency_summary = (
        f"影响 {len(affected_dependencies)} 个依赖名称；"
        if affected_dependencies
        else "未能关联到具体依赖；"
    )
    review_actions: list[str] = []
    if reason_group_counts["source_unapproved"]:
        review_actions.append(
            f"来源本身未经批准 "
            f"{reason_group_counts['source_unapproved']} 条"
            "（改用官方源，或经运维审核后加入 "
            "TAH_APPROVED_PRIVATE_REGISTRIES_JSON）"
        )
    if reason_group_counts["policy_mismatch"]:
        review_actions.append(
            f"已批准端点的使用方式不匹配 "
            f"{reason_group_counts['policy_mismatch']} 条"
            "（修正路径、端口、生态或用途，通常无需新增审批）"
        )
    if reason_group_counts["unsafe_transport"]:
        review_actions.append(
            f"传输或凭据不安全 "
            f"{reason_group_counts['unsafe_transport']} 条"
            "（改用 HTTPS 并移除 URL 内嵌凭据）"
        )
    if reason_group_counts["other"]:
        review_actions.append(
            f"其他策略拒绝 {reason_group_counts['other']} 条"
            "（按 evidence 中的 reason 人工复核）"
        )
    scanner._add_advisory(
        code="dependency_registry_policy",
        category="registry_policy",
        level="high",
        title="依赖来源策略需要人工复核",
        description=(
            f"检测到 {len(rejected)} 条依赖来源策略记录需要复核，"
            f"涉及 {len(host_counts)} 个 host，{dependency_summary}"
            f"处置分类：{'；'.join(review_actions)}。"
            "来源获批与依赖本身是否安全是两个独立判断。"
        ),
        deduction=0,
        affects_grade=False,
        requires_manual_review=True,
        evidence=(
            f"policy={policy.version}; hosts={_format_counter(host_counts)}; "
            f"reasons={_format_counter(reason_counts)}; "
            f"groups={_format_counter(reason_group_counts)}; "
            f"files={_format_counter(file_counts)}"
        ),
        location={"file": source_files[0]} if source_files else None,
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
            )
    scanner.dependency_scan = {
        "status": "partial" if failures or limit_reached else "complete",
        "dependencies_found": len(records),
        "dependencies_queried": queried,
        "query_failures": failures,
    }
    if limit_reached:
        scanner.dependency_scan["query_limit"] = getattr(client, "max_queries", None)


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
        logical_lines: dict[int, tuple[LogicalLine, int]] | None = None

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
                        if logical_lines is None:
                            logical_lines = {
                                logical.start_line + index: (logical, offset)
                                for logical in iter_logical_lines(content)
                                for index, offset in enumerate(logical.line_offsets)
                            }
                        logical, line_offset = logical_lines.get(line_no, (None, 0))
                        command = logical.text if logical is not None else lines[line_no - 1]
                        url_offset = line_offset + match.start() - (
                            content.rfind("\n", 0, match.start()) + 1
                        )
                        # Broader context may reveal an installer, but a later
                        # pipeline must not erase an existing dependency use.
                        if (
                            url_usage != URL_USAGE_DEPENDENCY
                            and logical is not None
                            and len(logical.line_offsets) > 1
                            and classify_url_usage(command, 1, matched_url)
                            == URL_USAGE_DEPENDENCY
                        ):
                            url_usage = URL_USAGE_DEPENDENCY
                        # A URL literal is not a package source. Registry and
                        # installer context is required before SR-008 applies.
                        if url_usage != URL_USAGE_DEPENDENCY:
                            continue
                        inline_source_observations.append(
                            DependencySourceObservation(
                                ecosystem=(
                                    _dependency_ecosystem_near_line(
                                        [command], 1
                                    )
                                    or _dependency_ecosystem_near_line(lines, line_no)
                                    or "unknown"
                                ),
                                url=matched_url.rstrip(".,;:!?"),
                                usage=_dependency_usage_for_url(
                                    command, url_offset
                                ),
                                source_file=fname,
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
    manifest_records = _manifest_records(meta) if meta else []
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
