"""SR-003: Credential access detection."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from scanners.risk_scanner.common import CODE_FILE_EXTENSIONS
from scanners.risk_scanner.patterns import CREDENTIAL_ACCESS_PATTERNS


_SYSTEM_CRITICAL_KW = ("ssh", "passwd", "shadow", "browser", "chrome", "firefox", "edge")

_CODE_ONLY_PATTERNS = frozenset({
    "文件系统遍历搜索 .env",
    "文件系统遍历搜索凭据文件",
})

_DEFENSIVE_EXFIL_PHRASES = (
    "never leak", "do not leak", "don't leak", "avoid leaking",
    "must not leak", "prevent leaks", "not leak",
)
_ENV_CREDENTIAL_DESCS = frozenset({
    "读取敏感环境变量",
    "展开敏感环境变量",
    "设置敏感环境变量",
})
_ENV_CREDENTIAL_SOURCE = re.compile(
    r"(?:process\.env(?:\.|\[['\"])|os\.(?:getenv|environ(?:\.get)?)[\[(])"
    r"[^\n]{0,100}(?:DATABASE_URL|GITHUB_TOKEN|GITLAB_TOKEN|"
    r"OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_ACCESS_KEY|AWS_SECRET|"
    r"API_KEY|ACCESS_TOKEN|AUTH_TOKEN|CLIENT_SECRET)",
    re.IGNORECASE,
)
_NETWORK_OPERATION = re.compile(
    r"(?:urllib\.request\.(?:Request|urlopen)|requests?\.(?:post|put|request)|"
    r"httpx\.|fetch\s*\(|axios\.)",
    re.IGNORECASE,
)


def _is_code_file(fname: str) -> bool:
    ext = Path(fname).suffix.lower()
    return ext in CODE_FILE_EXTENSIONS


def _classify_severity(matched_text: str, default_severity: str) -> str:
    lower = matched_text.lower()
    if any(kw in lower for kw in _SYSTEM_CRITICAL_KW):
        return "critical"
    if any(kw in lower for kw in ("conversation", "exfiltrat", "leak", "steal")):
        return "critical"
    return default_severity


def _credential_exfiltration(content: str) -> tuple[int, str] | None:
    assignment = re.compile(
        r"\b([A-Za-z_]\w*)\s*=\s*([^\n]+)",
        re.IGNORECASE,
    )
    for source in assignment.finditer(content):
        variable = source.group(1)
        if not _ENV_CREDENTIAL_SOURCE.search(source.group(2)):
            continue
        tail = content[source.end():source.end() + 2000]
        use = re.search(
            rf"(?:\bdata\s*=|\bjson\s*=|\bbody\s*:|Authorization[^\n]{{0,80}})"
            rf"[^\n]{{0,160}}\b{re.escape(variable)}\b",
            tail,
            re.IGNORECASE,
        )
        if use is None:
            continue
        window_start = max(0, use.start() - 600)
        window_end = min(len(tail), use.end() + 600)
        window = tail[window_start:window_end]
        if not _NETWORK_OPERATION.search(window) or not re.search(r"https?://", window):
            continue
        absolute_offset = source.end() + use.start()
        return content.count("\n", 0, absolute_offset) + 1, variable
    return None


def run(scanner: Any) -> None:
    rule_id = "SR-003"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        if not content:
            continue
        lines = content.split("\n")
        exfiltration = _credential_exfiltration(content)

        for pattern, desc, default_severity in CREDENTIAL_ACCESS_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if (
                    desc in _CODE_ONLY_PATTERNS or desc in _ENV_CREDENTIAL_DESCS
                ) and not _is_code_file(fname):
                    continue
                if exfiltration is not None and desc in _ENV_CREDENTIAL_DESCS:
                    # The source read is represented by the stronger end-to-end
                    # exfiltration root below, avoiding duplicate score impact.
                    continue

                line_no = content[: match.start()].count("\n") + 1
                if desc == "外泄对话内容":
                    line_text = lines[line_no - 1].lower()
                    if any(phrase in line_text for phrase in _DEFENSIVE_EXFIL_PHRASES):
                        continue
                start_line = max(0, line_no - 1)
                end_line = min(len(lines) - 1, line_no)
                snippet = "\n".join(lines[start_line : end_line + 1])
                matched_text = match.group()

                severity = _classify_severity(matched_text, default_severity)
                semantic: dict[str, Any] = {}
                if desc in _ENV_CREDENTIAL_DESCS:
                    severity = "medium"
                    semantic = {
                        "kind": "context_dependent",
                        "disposition": "needs_context",
                        "sink_kind": "credential_read",
                        "source_kind": "environment_credential",
                        "source_control": "operator",
                        "reachability": "runtime_configuration",
                        "activation": "conditional",
                        "trust_boundary_crossed": False,
                        "preconditions": ["operator supplies the credential environment variable"],
                        "requires_manual_review": True,
                    }
                if scanner._is_code_example(fname, line_no):
                    severity = "medium" if severity == "critical" else "low"

                scanner._add_finding(
                    rule_id=rule_id,
                    severity=severity,
                    category="credential_access",
                    title=f"凭据访问风险: {desc}",
                    description=f"在 {fname} 中发现尝试访问凭据/敏感文件：{desc}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配模式: {pattern}",
                    remediation="移除对敏感文件和凭据的访问。使用安全的密钥管理方案（如环境变量注入）。",
                    cwe_id="CWE-200",
                    **semantic,
                )

        if exfiltration is not None:
            line_no, variable = exfiltration
            line = lines[line_no - 1] if line_no <= len(lines) else ""
            scanner._add_finding(
                rule_id=rule_id,
                severity="critical",
                category="credential_access",
                title="凭据从环境变量流向外部网络",
                description=f"{fname} 将操作员提供的凭据变量 {variable} 发送到外部 URL。",
                location={"file": fname, "line": line_no, "snippet": line[:200]},
                evidence=f"credential source=environment; outbound data={variable}",
                remediation="禁止向非必要域名发送凭据；使用目标域白名单、最小权限令牌和显式用户授权。",
                cwe_id="CWE-200",
                kind="vulnerability",
                disposition="confirmed_vulnerability",
                sink_kind="network_egress",
                sink_symbol="outbound_request",
                source_kind="environment_credential",
                source_symbol=variable,
                source_control="operator",
                reachability="runtime_reachable",
                activation="direct",
                trust_boundary_crossed=True,
            )
