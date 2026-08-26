"""SR-009: Source integrity validation."""

from __future__ import annotations

import re
from typing import Any

from packages.schema.constants import HASH_SCOPE_SCANNED_SOURCE


def run(scanner: Any) -> None:
    rule_id = "SR-009"

    meta = scanner._package_metadata
    if not meta:
        scanner._add_finding(
            rule_id=rule_id,
            severity="medium",
            category="source_integrity",
            title="缺少包元数据",
            description="无法找到包元数据文件（manifest.json / plugin.json / SKILL.md frontmatter），无法验证来源完整性。",
            location={"file": str(scanner.target_dir)},
            remediation="添加 agent-package.schema.json 兼容的元数据文件。",
        )
        return

    # Acquisition facts are the only authority for this rule.  Missing facts
    # deliberately fail closed; older callers must provide an explicit facts
    # object instead of silently re-enabling manifest trust.
    acquisition_facts = getattr(scanner, "acquisition_facts", None)
    if not isinstance(acquisition_facts, dict):
        acquisition_facts = getattr(scanner, "_acquisition_facts", None)
    if not isinstance(acquisition_facts, dict):
        acquisition_facts = {}
    raw_integrity = acquisition_facts.get("integrity", {}) or {}
    raw_source = acquisition_facts.get("source", {}) or {}
    integrity = raw_integrity if isinstance(raw_integrity, dict) else {}
    source = raw_source if isinstance(raw_source, dict) else {}
    raw_claimed_integrity = meta.get("integrity", {}) or {}
    claimed_integrity = (
        raw_claimed_integrity if isinstance(raw_claimed_integrity, dict) else {}
    )
    raw_verification = (
        acquisition_facts.get("verification", {})
        if isinstance(acquisition_facts, dict)
        else {}
    ) or {}
    verification = raw_verification if isinstance(raw_verification, dict) else {}

    issues: list[str] = []

    sha256 = integrity.get("sha256", "")
    sha256_format_ok = isinstance(sha256, str) and bool(
        re.fullmatch(r"^[a-f0-9]{64}$", sha256)
    )
    hash_scope_ok = integrity.get("hash_scope") == HASH_SCOPE_SCANNED_SOURCE
    is_complete = integrity.get("is_complete") is True
    sha256_ok = sha256_format_ok and hash_scope_ok and is_complete
    if not sha256_format_ok:
        issues.append("缺少 SHA256 完整性校验值")
    elif not hash_scope_ok:
        issues.append("SHA256 校验范围未声明为采集源码")
    elif not is_complete:
        issues.append("SHA256 仅覆盖部分扫描内容")

    has_verified_signature = (
        sha256_ok
        and (
            verification.get("signature") is True
            or verification.get("attestation") is True
        )
    )
    has_verified_sbom = sha256_ok and verification.get("sbom") is True

    missing_sig = not has_verified_signature
    if missing_sig:
        if claimed_integrity.get("signature") or claimed_integrity.get("attestation_url"):
            issues.append("包声明的签名或构建证明未经独立验证")
        else:
            issues.append("缺少加密签名或构建证明")

    if not has_verified_sbom:
        if claimed_integrity.get("sbom_url"):
            issues.append("包声明的 SBOM 未经独立验证")
        else:
            issues.append("缺少 SBOM 文档 URL")

    commit_hash = source.get("commit_hash", "")
    commit_ok = isinstance(commit_hash, str) and bool(
        re.fullmatch(r"^[a-f0-9]{40}$", commit_hash)
    )
    if not commit_ok:
        issues.append("来源未锁定 commit hash")

    if issues:
        # 分级：sha256 或 commit_hash 缺失/非法 → medium；
        # 仅缺签名/证明/SBOM（生态常态）→ low
        severity = "medium" if (not sha256_ok or not commit_ok) else "low"
        manifest_file = "manifest.json" if (scanner.target_dir / "manifest.json").is_file() else "SKILL.md"
        scanner._add_finding(
            rule_id=rule_id,
            severity=severity,
            category="source_integrity",
            title="来源完整性不足",
            description="; ".join(issues),
            location={"file": manifest_file},
            evidence="integrity section is incomplete or missing",
            remediation="使用采集层计算的 SHA256/commit，并为签名、构建证明和 SBOM 提供绑定到该内容的独立验证结果。",
        )
