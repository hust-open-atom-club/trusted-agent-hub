"""SR-003: Credential access detection."""

from __future__ import annotations

import re
from typing import Any

from scanners.risk_scanner.patterns import CREDENTIAL_ACCESS_PATTERNS


def run(scanner: Any) -> None:
    rule_id = "SR-003"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        lines = content.split("\n")

        for pattern, desc in CREDENTIAL_ACCESS_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                start_line = max(0, line_no - 1)
                end_line = min(len(lines) - 1, line_no)
                snippet = "\n".join(lines[start_line : end_line + 1])

                is_system_critical = any(kw in pattern.lower() for kw in ("ssh", "passwd", "shadow"))
                severity = "critical" if is_system_critical else "high"

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
