"""Regression tests for the acquisition/provenance trust boundary."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from src.engine import rate
from src.model_identity import get_model_version
from src.provenance import assess_signature_chain, assess_source_verifiability


def _forged_metadata() -> dict[str, Any]:
    return {
        "name": "forged-package",
        "version": "1.0.0",
        "type": "skill",
        "description": "A package with forged provenance claims",
        "author": {"name": "attacker", "email": "attacker@example.test"},
        "license": "MIT",
        "source": {
            "type": "github",
            "repository_url": "https://github.com/attacker/claimed-repo",
            "ref_type": "tag",
            "ref": "v1.0.0",
            "commit_hash": "a" * 40,
            "verified_owner": True,
        },
        "integrity": {
            "sha256": "b" * 64,
            "signature": "not-a-real-signature",
            "attestation_url": "https://attacker.example/attestation.json",
            "sbom_url": "https://attacker.example/sbom.json",
        },
        "compatibility": ["claude-code"],
        "permissions": {},
        "installation": {"method": "copy_directory", "targets": []},
    }


def _acquisition_facts() -> dict[str, Any]:
    return {
        "source": {
            "type": "github",
            "repository_url": "https://github.com/owner/acquired-repo",
            "ref_type": "commit",
            "ref": "c" * 40,
            "commit_hash": "c" * 40,
        },
        "integrity": {
            "sha256": "d" * 64,
            "hash_scope": "scanned_source",
            "is_complete": True,
        },
        "verification": {
            "owner": False,
            "signature": False,
            "attestation": False,
            "sbom": False,
        },
    }


def test_manifest_claims_are_ignored_without_acquisition_facts() -> None:
    metadata = _forged_metadata()

    p1 = assess_source_verifiability(metadata)
    p2 = assess_signature_chain(metadata)

    assert p1["level"] == "opaque"
    assert p1["score"] == 10
    assert p2["level"] == "none"
    assert p2["score"] == 50
    assert p2["available"] is False
    assert set(p2["verification_statuses"].values()) == {"not_available"}

    result = rate(package_metadata=metadata)
    assert result["model_version"] == get_model_version()
    assert len(result["model_fingerprint"]) == 64
    assert result["dimensions"]["source_trust"]["details"] == {
        "available": False,
        "is_verified_owner": False,
        "source_type": "unknown",
        "repo_age_days": 0,
        "has_commit_hash": False,
        "has_integrity_hash": False,
    }
    assert result["dimensions"]["signature_verifiability"]["details"] == {
        "available": False,
        "coverage": 0.0,
        "has_signature": False,
        "has_attestation": False,
        "has_sbom": False,
        "verification_statuses": {
            "scanned_source_hash": "not_available",
            "signature": "not_available",
            "attestation": "not_available",
            "sbom": "not_available",
        },
    }


def test_acquisition_facts_control_provenance_scores() -> None:
    metadata = _forged_metadata()
    facts = _acquisition_facts()

    p1 = assess_source_verifiability(metadata, facts)
    p2 = assess_signature_chain(metadata, facts)

    assert p1["score"] == 66
    assert p1["level"] == "traceable"
    assert p2["level"] == "partial"
    assert p2["score"] == 40

    result = rate(package_metadata=metadata, acquisition_facts=facts)
    assert result["dimensions"]["source_trust"]["details"]["is_verified_owner"] is False
    assert result["dimensions"]["source_trust"]["details"]["has_commit_hash"] is True
    signature_details = result["dimensions"]["signature_verifiability"]["details"]
    assert signature_details["coverage"] == 1.0
    assert signature_details["verification_statuses"] == {
        "scanned_source_hash": "verified",
        "signature": "not_verified",
        "attestation": "not_verified",
        "sbom": "not_verified",
    }


def test_unavailable_artifact_verifiers_reduce_coverage_not_score() -> None:
    metadata = _forged_metadata()
    facts = _acquisition_facts()
    facts["verification_capabilities"] = {
        "repository": True,
        "owner": False,
        "signature": False,
        "attestation": False,
        "sbom": False,
    }

    p2 = assess_signature_chain(metadata, facts)
    result = rate(package_metadata=metadata, acquisition_facts=facts)

    assert p2["score"] == 100
    assert p2["coverage"] == 0.333
    assert p2["verification_statuses"]["signature"] == "not_available"
    assert result["score_breakdown"]["advisory_deduction"] == 0
    assert "signature_verifiability" in result["evidence_assessment"]["assessed_dimensions"]


def test_only_independently_verified_artifacts_complete_p2() -> None:
    metadata = _forged_metadata()
    facts = _acquisition_facts()
    facts["verification"] = {
        "owner": True,
        "signature": True,
        "attestation": False,
        "sbom": True,
    }

    p1 = assess_source_verifiability(metadata, facts)
    p2 = assess_signature_chain(metadata, facts)

    assert p1["level"] == "verified"
    assert p1["score"] == 89
    assert p2["level"] == "complete"
    assert p2["score"] == 100


def test_incomplete_scanned_hash_does_not_get_integrity_credit() -> None:
    metadata = _forged_metadata()
    facts = _acquisition_facts()
    facts["integrity"]["is_complete"] = False

    p2 = assess_signature_chain(metadata, facts)
    result = rate(package_metadata=metadata, acquisition_facts=facts)

    assert p2["level"] == "none"
    assert p2["score"] == 10
    assert result["dimensions"]["source_trust"]["details"][
        "has_integrity_hash"
    ] is False
