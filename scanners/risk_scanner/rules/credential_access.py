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


def run(scanner: Any) -> None:
    rule_id = "SR-003"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        if not content:
            continue
        lines = content.split("\n")

        for pattern, desc, default_severity in CREDENTIAL_ACCESS_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                if desc in _CODE_ONLY_PATTERNS and not _is_code_file(fname):
                    continue

                line_no = content[: match.start()].count("\n") + 1
                start_line = max(0, line_no - 1)
                end_line = min(len(lines) - 1, line_no)
                snippet = "\n".join(lines[start_line : end_line + 1])
                matched_text = match.group()

                severity = _classify_severity(matched_text, default_severity)
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
                )
