"""SR-010: Metadata quality + structure check."""

from __future__ import annotations

import os
import json
from pathlib import Path
from typing import Any

from scanners.risk_scanner.common import BINARY_EXTENSIONS, REQUIRED_FILES_BY_TYPE

# 标准许可证文件名（大小写不敏感），与 extract_skills.extract_license 对齐
_LICENSE_FILE_NAMES: frozenset[str] = frozenset({
    "license", "licence", "copying",
    "license.md", "license.txt", "license.markdown",
    "licence.md", "licence.txt", "licence.markdown",
    "copying.md", "copying.txt", "copying.markdown",
})


def _find_license_file(target_dir: Path, max_up: int = 5) -> Path | None:
    """在包目录及其父目录（最多 max_up 层）查找许可证文件。

    GitHub 仓库常见布局是 LICENSE 在仓库根、skill 在子目录，
    因此需要像提取器一样向上遍历。
    """
    current = target_dir
    for _ in range(max_up + 1):
        try:
            names = os.listdir(current)
        except OSError:
            return None
        for name in names:
            if name.lower() in _LICENSE_FILE_NAMES:
                return current / name
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def run(scanner: Any) -> None:
    rule_id = "SR-010"
    meta = scanner._package_metadata

    if meta:
        required_fields = ["name", "version", "description", "author", "license"]
        missing = [f for f in required_fields if not meta.get(f)]
        # 与「缺少有效许可证」规则对齐：包内或父目录存在 LICENSE 文件
        # → license 视为已声明，不再列入缺失字段
        if "license" in missing and _find_license_file(scanner.target_dir) is not None:
            missing.remove("license")

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

        file_contents = getattr(scanner, "_file_contents", None)
        if isinstance(file_contents, dict) and "package.json" in file_contents:
            package_json = file_contents.get("package.json", "")
        else:
            # Unit-test adapters and older integrations may expose only the
            # read helper; do not silently skip package identity validation.
            package_json = scanner._read_file_content("package.json")
        if package_json:
            try:
                package_data = json.loads(package_json)
            except (json.JSONDecodeError, TypeError):
                package_data = {}
            package_name = package_data.get("name") if isinstance(package_data, dict) else None
            skill_name = meta.get("name")
            if package_name and skill_name and package_name != skill_name:
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="info",
                    category="metadata_quality",
                    title="技能名与分发包名不一致",
                    description=(
                        f"技能名称为 '{skill_name}'，package.json 分发包名为 '{package_name}'；"
                        "安装记录应使用分发包名。"
                    ),
                    location={"file": "package.json"},
                    evidence=f"skill={skill_name}; distribution={package_name}",
                    remediation="分别保存 skill name 和 distribution package name，不要互相覆盖。",
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

        license_val = meta.get("license", "")
        if not license_val or license_val.upper() in ("NONE", "UNLICENSED"):
            # 包内或父目录存在标准 LICENSE 文件 → 视为已声明许可证（与提取器对齐）
            if _find_license_file(scanner.target_dir) is None:
                manifest_file = "manifest.json" if (scanner.target_dir / "manifest.json").is_file() else "SKILL.md"
                scanner._add_finding(
                    rule_id=rule_id,
                    severity="low",
                    category="metadata_quality",
                    title="缺少有效许可证",
                    description=f"包未声明有效许可证 (当前值: '{license_val or '空'}')。",
                    location={"file": manifest_file},
                    evidence=f"License value: '{license_val}'",
                    remediation="选择并声明合适的开源许可证（如 MIT、Apache-2.0）。",
                )

    _check_structure(scanner)


def _check_structure(scanner: Any) -> None:
    rule_id = "SR-010"

    # Unit-test adapters and older integrations may only expose scanned_files;
    # the production scanner always supplies the complete inventory.
    records = getattr(getattr(scanner, "inventory", None), "files", None)
    if records is None:
        records = [type("Record", (), {"relative_path": fname, "extension": Path(fname).suffix.lower()})
                   for fname in scanner.scanned_files]
    for record in records:
        fname = record.relative_path
        ext = record.extension
        if ext in BINARY_EXTENSIONS:
            scanner._add_finding(
                rule_id=rule_id,
                severity="medium",
                category="metadata_quality",
                title=f"可疑文件: {fname}",
                description=f"发现二进制/编译产物 '{fname}'（扩展名 {ext}），Skill 包不应默认携带此类文件。",
                location={"file": fname},
                evidence=f"Suspicious file extension: {ext}",
                remediation="确认二进制文件是必要且可信的；不需要时移除，仅保留源代码和配置文件。",
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
                    location={"file": "."},
                    remediation=f"添加 {req_file} 文件。",
                )
