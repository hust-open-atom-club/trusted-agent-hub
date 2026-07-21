"""SR-010: Metadata quality + structure check."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scanners.risk_scanner.common import DANGEROUS_EXTENSIONS, REQUIRED_FILES_BY_TYPE


def run(scanner: Any) -> None:
    rule_id = "SR-010"
    meta = scanner._package_metadata

    if meta:
        required_fields = ["name", "version", "description", "author", "license"]
        missing = [f for f in required_fields if not meta.get(f)]

        if missing:
            manifest_file = "manifest.json" if (scanner.target_dir / "manifest.json").is_file() else "SKILL.md"
            scanner._add_finding(
                rule_id=rule_id,
                severity="low",
                category="metadata_quality",
                title=f"元数据不完整: 缺少 {', '.join(missing)}",
                description=f"包元数据缺少以下必填字段: {', '.join(missing)}",
                location={"file": manifest_file},
                evidence=f"Required fields missing: {missing}",
                remediation=f"在元数据中补充 {', '.join(missing)} 字段。",
            )

        description = meta.get("description", "")
        if description and len(description) < 10:
            manifest_file = "manifest.json" if (scanner.target_dir / "manifest.json").is_file() else "SKILL.md"
            scanner._add_finding(
                rule_id=rule_id,
                severity="info",
                category="metadata_quality",
                title="描述过短",
                description=f"包描述仅 {len(description)} 个字符，不足 10 个字符。",
                location={"file": manifest_file},
                remediation="提供更详细的包描述（建议 10-200 字符）。",
            )

    _check_structure(scanner)


def _check_structure(scanner: Any) -> None:
    rule_id = "SR-010"

    for fname in scanner.scanned_files:
        ext = Path(fname).suffix.lower()
        if ext in DANGEROUS_EXTENSIONS:
            scanner._add_finding(
                rule_id=rule_id,
                severity="medium",
                category="metadata_quality",
                title=f"可疑文件: {fname}",
                description=f"发现二进制/可执行文件 '{fname}'（扩展名 {ext}），Skill 包不应包含编译产物。",
                location={"file": fname},
                evidence=f"Suspicious file extension: {ext}",
                remediation="移除二进制文件，仅保留源代码和配置文件。",
            )

    if scanner._package_metadata:
        pkg_type = scanner._package_metadata.get("type", "")
        required = REQUIRED_FILES_BY_TYPE.get(pkg_type, [])
        for req_file in required:
            if not (scanner.target_dir / req_file).is_file():
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="medium",
                    category="metadata_quality",
                    title=f"缺少必要文件: {req_file}",
                    description=f"类型 '{pkg_type}' 的包缺少必要文件 '{req_file}'。",
                    location={"file": str(scanner.target_dir)},
                    remediation=f"添加 {req_file} 文件。",
                )
