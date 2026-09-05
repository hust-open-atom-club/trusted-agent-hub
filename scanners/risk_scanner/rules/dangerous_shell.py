"""SR-002: Dangerous shell command detection."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from scanners.risk_scanner.patterns import DANGEROUS_SHELL_PATTERNS


def _classify_severity(matched_text: str, default_severity: str) -> str:
    lower = matched_text.lower()
    if any(kw in lower for kw in ("rm -rf", "sudo", "mkfs", "dd if=", "/dev/tcp")):
        return "critical"
    if "|" in lower and "sh" in lower:
        return "critical"
    if any(kw in lower for kw in ("fork bomb", "pipe shell")):
        return "critical"
    if any(kw in lower for kw in ("> /dev/sda",)):
        return "high"
    return default_severity


def run(scanner: Any) -> None:
    rule_id = "SR-002"

    for fname in scanner.scanned_files:
        ext = Path(fname).suffix.lower()
        if ext in (".html", ".htm", ".css", ".svg"):
            continue

        content = scanner._read_file_content(fname)
        if not content:
            continue
        lines = content.split("\n")

        for pattern, desc, default_severity in DANGEROUS_SHELL_PATTERNS:
            flags = 0 if "PATH" in pattern else re.IGNORECASE

            for match in re.finditer(pattern, content, flags):
                line_no = content[: match.start()].count("\n") + 1
                start_line = max(0, line_no - 1)
                end_line = min(len(lines) - 1, line_no)
                snippet = "\n".join(lines[start_line : end_line + 1])
                matched_text = match.group()

                severity = _classify_severity(matched_text, default_severity)
                if scanner._is_code_example(fname, line_no):
                    # Fenced examples in ordinary documentation are not part
                    # of the package's executable surface.
                    continue

                semantic: dict[str, Any] = {}
                if "|" in matched_text and re.search(r"\b(?:ba)?sh\b", matched_text, re.I):
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
                    severity=severity,
                    category="dangerous_shell",
                    title=f"危险 Shell 命令: {desc}",
                    description=f"在 {fname} 中发现危险 Shell 命令：{desc}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:300]},
                    evidence=f"匹配模式: {matched_text[:120]}",
                    remediation="避免在 Skill 中使用危险 Shell 命令。如需执行 Shell，请使用命令白名单限制。",
                    cwe_id="CWE-78",
                    **semantic,
                )
