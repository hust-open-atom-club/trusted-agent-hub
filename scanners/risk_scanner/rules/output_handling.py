"""SR-011: Output handling risk detection.

Checks for:
  - Printing sensitive variables (token/key/secret/password)
  - User input directly concatenated into shell commands
  - Writing output without sanitization
"""

from __future__ import annotations

import re
from typing import Any


def run(scanner: Any) -> None:
    rule_id = "SR-011"

    for fname in scanner.scanned_files:
        content = scanner._read_file_content(fname)
        lines = content.split("\n")

        for pattern, desc in [
            (r"print\s*\(\s*(?:token|key|secret|password|passwd)", "打印敏感变量"),
            (r"console\.log\s*\(\s*(?:token|key|secret|password)", "console.log 敏感变量"),
        ]:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1) : line_no])
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="high",
                    category="output_handling",
                    title=f"输出处理风险 — {desc}",
                    description=f"在 {fname} 中发现将敏感变量输出到 stdout/console：{match.group()[:80]}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配: {match.group()[:100]}",
                    remediation="不要在生产环境中打印密钥/Token。使用日志框架并配置敏感信息脱敏。",
                )

        for pattern, desc in [
            (r"(?:subprocess|os\.system|os\.popen|exec)\s*\(.*\+", "用户输入拼入 shell"),
            (r"\.write_text\s*\(.*\+", "用户输入拼入文件写入"),
        ]:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                line_no = content[: match.start()].count("\n") + 1
                snippet = "\n".join(lines[max(0, line_no - 1) : line_no])
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="medium",
                    category="output_handling",
                    title=f"输出处理风险 — {desc}",
                    description=f"在 {fname} 中发现用户输入直接拼入操作（可能命令注入）：{match.group()[:80]}",
                    location={"file": fname, "line": line_no, "snippet": snippet[:200]},
                    evidence=f"匹配: {match.group()[:100]}",
                    remediation="使用参数化调用（如 subprocess.run([cmd, arg])）而非字符串拼接。",
                )
