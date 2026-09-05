"""SR-009: Source integrity validation."""

from __future__ import annotations

import re
from typing import Any

from packages.schema.constants import HASH_SCOPE_SCANNED_SOURCE


def run(scanner: Any) -> None:
    rule_id = "SR-009"

    meta = scanner._package_metadata or {}

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

    core_issues: list[str] = []

    sha256 = integrity.get("sha256", "")
    sha256_format_ok = isinstance(sha256, str) and bool(
        re.fullmatch(r"^[a-f0-9]{64}$", sha256)
    )
    hash_scope_ok = integrity.get("hash_scope") == HASH_SCOPE_SCANNED_SOURCE
    is_complete = integrity.get("is_complete") is True
    sha256_ok = sha256_format_ok and hash_scope_ok and is_complete
    if not sha256_format_ok:
        core_issues.append("缺少 SHA256 完整性校验值")
    elif not hash_scope_ok:
        core_issues.append("SHA256 校验范围未声明为采集源码")
    elif not is_complete:
        core_issues.append("SHA256 仅覆盖部分扫描内容")

    has_verified_signature = sha256_ok and verification.get("signature") is True
    has_verified_attestation = sha256_ok and verification.get("attestation") is True
    has_verified_sbom = sha256_ok and verification.get("sbom") is True

    commit_hash = source.get("commit_hash", "")
    commit_ok = isinstance(commit_hash, str) and bool(
        re.fullmatch(r"^[a-f0-9]{40}$", commit_hash)
    )
    if not commit_ok:
        core_issues.append("来源未锁定 commit hash")

    manifest_file = (
        "manifest.json"
        if (scanner.target_dir / "manifest.json").is_file()
        else "plugin.json"
        if (scanner.target_dir / "plugin.json").is_file()
        else "SKILL.md"
        if (scanner.target_dir / "SKILL.md").is_file()
        else "."
    )

    if core_issues:
        scanner._add_finding(
            rule_id=rule_id,
            severity="medium",
            category="source_integrity",
            title="核心来源完整性不足",
            description="; ".join(core_issues),
            location={"file": manifest_file},
            evidence="scanned-source hash or acquired commit is incomplete",
            remediation="使用采集层计算的完整 SHA256，并将来源锁定到具体 commit。",
        )

    proof_advisories = (
        (
            "missing_signature",
            has_verified_signature,
            "缺少已验证的包签名",
            "包声明了签名，但尚未由采集层独立验证。"
            if claimed_integrity.get("signature")
            else "没有发现绑定到本次扫描内容的已验证加密签名。",
        ),
        (
            "missing_attestation",
            has_verified_attestation,
            "缺少已验证的供应链证明",
            "包声明了构建证明，但尚未由采集层独立验证。"
            if claimed_integrity.get("attestation_url")
            else "没有发现绑定到本次扫描内容的构建或供应链证明。",
        ),
        (
            "missing_sbom",
            has_verified_sbom,
            "缺少已验证的 SBOM",
            "包声明了 SBOM，但尚未由采集层独立验证。"
            if claimed_integrity.get("sbom_url")
            else "没有发现绑定到本次扫描内容的已验证 SBOM。",
        ),
    )
    for code, verified, title, description in proof_advisories:
        if verified:
            continue
        scanner._add_advisory(
            code=code,
            category="provenance",
            level="warning",
            title=title,
            description=description,
            location={"file": manifest_file},
            evidence="independent verification flag is false",
            deduction=2,
            affects_grade=False,
        )
