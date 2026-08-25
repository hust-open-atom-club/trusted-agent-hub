"""
Layer 1: Source Provenance Assessment

P1 — Source Verifiability: determines how trustworthy the package's origin is.
P2 — Content Signature Chain: evaluates integrity guarantees of the package contents.

All functions operate on plain dicts (JSON-deserialized) and return dict results.
Uses only the Python standard library.
"""

from __future__ import annotations

import re
from typing import Any

from packages.schema.constants import HASH_SCOPE_SCANNED_SOURCE


def _acquired_section(
    acquisition_facts: dict[str, Any] | None,
    key: str,
) -> dict[str, Any]:
    """Read a server-established acquisition section.

    Package metadata is intentionally not a fallback here.  A manifest is an
    untrusted claim source and must not be able to manufacture provenance by
    omitting the acquisition context.
    """
    if not isinstance(acquisition_facts, dict):
        return {}
    value = acquisition_facts.get(key, {})
    return value if isinstance(value, dict) else {}


def _verification_flag(
    acquisition_facts: dict[str, Any] | None,
    key: str,
) -> bool:
    verification = _acquired_section(acquisition_facts, "verification")
    return verification.get(key) is True


def has_complete_scanned_hash(integrity: dict[str, Any]) -> bool:
    """Return whether the facts contain a complete scanned-source hash."""
    sha256 = integrity.get("sha256", "")
    return (
        isinstance(sha256, str)
        and re.fullmatch(r"^[a-f0-9]{64}$", sha256) is not None
        and integrity.get("hash_scope") == HASH_SCOPE_SCANNED_SOURCE
        and integrity.get("hash_complete") is True
    )


def assess_source_verifiability(
    package_metadata: dict[str, Any],
    acquisition_facts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """P1: Assess how verifiable the package source is.

    Levels:
        verified  — verified owner, commit-hash-pinned, known source type
        traceable — source info present but not fully verified (missing commit, not verified)
        opaque    — minimal or no source provenance

    Args:
        package_metadata: package claims and descriptive metadata. Its source
            section is never trusted for this assessment.
        acquisition_facts: server-established facts from the acquisition and
            verification layers. If omitted, provenance is assessed fail-closed.

    Returns:
        dict with keys: level (str), score (int 0-100), evidence (list[str])
    """
    source = _acquired_section(acquisition_facts, "source")
    claimed_source = package_metadata.get("source", {}) or {}
    evidence: list[str] = []
    checks_passed: int = 0
    checks_total: int = 4

    source_type: str = source.get("type", "")
    verified_owner = _verification_flag(acquisition_facts, "owner")
    commit_hash: str = source.get("commit_hash", "")
    repository_url: str = source.get("repository_url", "")
    ref_type: str = source.get("ref_type", "")

    # Check 1: Has a known source type
    if source_type and source_type != "local_upload":
        checks_passed += 1
        evidence.append(f"Source type is '{source_type}'")
    else:
        evidence.append("Missing or unknown source type")

    # Check 2: Verified owner. This flag can only come from an independent
    # verifier; source.verified_owner in a package manifest is a claim.
    if verified_owner:
        checks_passed += 1
        evidence.append("Owner is verified")
    else:
        evidence.append("Owner is not verified")
        if isinstance(claimed_source, dict) and claimed_source.get("verified_owner") is True:
            evidence.append("Package-authored owner claim was ignored")

    # Check 3: Pinned commit hash (40 hex chars)
    if re.fullmatch(r"^[a-f0-9]{40}$", commit_hash):
        checks_passed += 1
        evidence.append("Commit hash is pinned")
    else:
        evidence.append("Missing or invalid commit hash")

    # Check 4: Has repository URL and a stable ref (tag or release)
    if repository_url:
        if ref_type in ("tag", "release"):
            checks_passed += 1
            evidence.append(f"Repository URL present with stable ref type '{ref_type}'")
        elif ref_type in ("branch", "commit"):
            checks_passed += 0.5  # partial credit
            evidence.append(f"Repository URL present but ref type is '{ref_type}' (less stable)")
        else:
            checks_passed += 0.5
            evidence.append("Repository URL present but ref type is unspecified")
    else:
        evidence.append("No repository URL")

    # Determine level
    if checks_passed >= 3.5:
        level = "verified"
    elif checks_passed >= 1.5:
        level = "traceable"
    else:
        level = "opaque"

    # Derive score from checks_passed
    score = _checks_to_score(checks_passed, checks_total)

    return {"level": level, "score": score, "evidence": evidence}


def assess_signature_chain(
    package_metadata: dict[str, Any],
    acquisition_facts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """P2: Assess the content signature / integrity chain.

    Levels:
        complete — complete scanned-source sha256 + signature/attestation + sbom present
        partial  — complete scanned-source hash present but missing other elements
        none     — no integrity info at all

    Args:
        package_metadata: package claims and descriptive metadata. Its
            integrity section is never trusted for this assessment.
        acquisition_facts: server-established complete artifact hash and
            verification results. If omitted, provenance is assessed fail-closed.

    Returns:
        dict with keys: level (str), score (int 0-100), evidence (list[str])
    """
    integrity = _acquired_section(acquisition_facts, "integrity")
    claimed_integrity = package_metadata.get("integrity", {}) or {}
    evidence: list[str] = []
    checks_passed: int = 0
    checks_total: int = 3

    hash_complete = has_complete_scanned_hash(integrity)
    sha256: str = integrity.get("sha256", "") if hash_complete else ""
    signature_verified = hash_complete and _verification_flag(
        acquisition_facts, "signature"
    )
    attestation_verified = hash_complete and _verification_flag(
        acquisition_facts, "attestation"
    )
    sbom_verified = hash_complete and _verification_flag(acquisition_facts, "sbom")

    # Check 1: SHA256 hash (64 hex chars)
    if re.fullmatch(r"^[a-f0-9]{64}$", sha256):
        checks_passed += 1
        evidence.append("Complete scanned-source SHA256 integrity hash is present")
    else:
        evidence.append("Missing or incomplete scanned-source SHA256 integrity hash")

    # Check 2: Signature or attestation
    if signature_verified or attestation_verified:
        checks_passed += 1
        if signature_verified:
            evidence.append("Cryptographic signature is independently verified")
        if attestation_verified:
            evidence.append("Build attestation is independently verified")
    else:
        evidence.append("No independently verified cryptographic signature or attestation")
        if isinstance(claimed_integrity, dict) and (
            claimed_integrity.get("signature")
            or claimed_integrity.get("attestation_url")
        ):
            evidence.append("Package-authored signature/attestation claim was ignored")

    # Check 3: SBOM
    if sbom_verified:
        checks_passed += 1
        evidence.append("SBOM is independently verified")
    else:
        evidence.append("No independently verified SBOM")
        if isinstance(claimed_integrity, dict) and claimed_integrity.get("sbom_url"):
            evidence.append("Package-authored SBOM claim was ignored")

    # Determine level
    if checks_passed == 3:
        level = "complete"
    elif checks_passed >= 1:
        level = "partial"
    else:
        level = "none"

    score = _checks_to_score(checks_passed, checks_total)

    return {"level": level, "score": score, "evidence": evidence}


def _checks_to_score(passed: float, total: int) -> int:
    """Convert a check-passed ratio to a 0-100 integer score."""
    ratio = passed / max(total, 1)
    # Map to 10-100 range (never 0 to leave room for truly broken cases)
    return max(10, min(100, round(10 + ratio * 90)))
