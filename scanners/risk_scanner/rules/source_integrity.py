"""SR-009: Source integrity validation."""

from __future__ import annotations

import re
from typing import Any


def run(scanner: Any) -> None:
    rule_id = "SR-009"

    meta = scanner._package_metadata
    if not meta:
        scanner._add_finding(
            rule_id=rule_id,
            severity="low",
            category="source_integrity",
            title="缺少包元数据",
            description="无法找到包元数据文件（manifest.json / plugin.json / SKILL.md frontmatter），无法验证来源完整性。",
            location={"file": str(scanner.target_dir)},
            remediation="添加 agent-package.schema.json 兼容的元数据文件。",
        )
        return

    integrity = meta.get("integrity", {}) or {}
    source = meta.get("source", {}) or {}

    issues: list[str] = []

    sha256 = integrity.get("sha256", "")
    if not re.fullmatch(r"^[a-f0-9]{64}$", sha256):
        issues.append("缺少 SHA256 完整性校验值")

    if not integrity.get("signature") and not integrity.get("attestation_url"):
        issues.append("缺少加密签名或构建证明")

    if not integrity.get("sbom_url"):
        issues.append("缺少 SBOM 文档 URL")

    commit_hash = source.get("commit_hash", "")
    if not re.fullmatch(r"^[a-f0-9]{40}$", commit_hash):
        issues.append("来源未锁定 commit hash")

    if issues:
        manifest_file = "manifest.json" if (scanner.target_dir / "manifest.json").is_file() else "SKILL.md"
        scanner._add_finding(
            rule_id=rule_id,
            severity="low",
            category="source_integrity",
            title="来源完整性不足",
            description="; ".join(issues),
            location={"file": manifest_file},
            evidence="integrity section is incomplete or missing",
            remediation="补充 integrity.sha256、signature/attestation_url、sbom_url，并在 source 中锁定 commit_hash。",
        )
