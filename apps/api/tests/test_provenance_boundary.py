"""API-level regression tests for acquisition/manifest provenance separation."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from src.models.packages import ScanReport, VersionDetail
from src.routers.trust import (
    _apply_acquisition_facts,
    _build_acquisition_facts,
    _provenance_claims,
)
from src.services.producer import ProducerService
from scanners.risk_scanner.provenance import (
    build_verification_facts,
    verify_acquired_repository,
)


class _Scanner:
    acquisition_facts = {
        "source": {"commit_hash": "c" * 40},
        "integrity": {
            "sha256": "d" * 64,
            "hash_scope": "scanned_source",
            "hash_complete": True,
        },
    }
    package_claims = {
        "source": {
            "repository_url": "https://github.com/attacker/claimed",
            "verified_owner": True,
            "ref_type": "tag",
        },
        "integrity": {
            "signature": "fake",
            "attestation_url": "https://attacker.example/attestation",
            "sbom_url": "https://attacker.example/sbom",
        },
    }


class _VerifiedScanner(_Scanner):
    acquisition_facts = {
        **_Scanner.acquisition_facts,
        "verification": {
            "owner": True,
            "signature": True,
            "attestation": False,
            "sbom": True,
            "content_sha256": "d" * 64,
        },
    }


class _UnboundVerifiedScanner(_VerifiedScanner):
    acquisition_facts = {
        **_Scanner.acquisition_facts,
        "verification": {
            "owner": True,
            "signature": True,
            "attestation": False,
            "sbom": True,
            "content_sha256": "e" * 64,
        },
    }


class _SecretClaimsScanner:
    package_claims = {
        "source": {
            "repository_url": "https://user:password@example.test/repo",
        },
        "integrity": {
            "signature": "Bearer SUPERSECRET",
            "api_key": "raw-secret",
        },
    }


class _DetailRepository:
    def get_version(self, version_id: str) -> dict[str, object]:
        return {
            "id": version_id,
            "provenance_claims": {
                "source": {"repository_url": "https://u:p@example.test/repo"},
            },
        }

    def get_scan_report(self, version_id: str) -> dict[str, object]:
        return {
            "scan_json": {
                "summary": {"note": "Bearer SUPERSECRET"},
                "findings": [{"evidence": "api_key: raw-secret"}],
                "file_contents": {"secret.txt": "Bearer SUPERSECRET"},
                "provenance": {
                    "package_claims": {
                        "integrity": {"token": "raw-secret"},
                    },
                },
            }
        }


def test_acquisition_facts_ignore_manifest_provenance_claims() -> None:
    facts = _build_acquisition_facts(
        {
            "owner": "trusted",
            "repo": "acquired",
            "ref": "main",
        },
        "https://github.com/trusted/acquired",
        None,
        "git",
        "c" * 40,
        _Scanner(),
    )

    assert facts["source"]["repository_url"] == "https://github.com/trusted/acquired"
    assert facts["source"]["commit_hash"] == "c" * 40
    assert facts["source"]["verified_owner"] is False
    assert facts["integrity"] == {
        "sha256": "d" * 64,
        "hash_scope": "scanned_source",
        "hash_complete": True,
    }
    assert facts["verification"] == {
        "owner": False,
        "signature": False,
        "attestation": False,
        "sbom": False,
    }


class _ArtifactRepository:
    def __init__(self) -> None:
        self.version = {
            "id": "ver-1",
            "package_id": "pkg-1",
            "version": "1.0.0",
            "source": {"repository_url": "https://github.com/acme/demo"},
            "integrity": {"sha256": "a" * 64},
            "acquisition_facts": {
                "source": {"commit_hash": "c" * 40},
                "integrity": {
                    "sha256": "d" * 64,
                    "hash_scope": "scanned_source",
                    "hash_complete": True,
                },
            },
        }

    def get_version(self, _version_id: str) -> dict[str, object]:
        return self.version

    def get_package(self, _package_id: str) -> dict[str, object]:
        return {"type": "skill"}

    def update_version_data(
        self, _version_id: str, updates: dict[str, object]
    ) -> None:
        self.version.update(updates)


def test_only_server_verification_facts_are_carried_forward() -> None:
    facts = _build_acquisition_facts(
        {"owner": "trusted", "repo": "acquired", "ref": "main"},
        "https://github.com/trusted/acquired",
        None,
        "git",
        "c" * 40,
        _VerifiedScanner(),
    )

    assert facts["source"]["verified_owner"] is False
    assert facts["verification"] == {
        "owner": False,
        "signature": True,
        "attestation": False,
        "sbom": True,
    }


def test_artifact_verification_must_bind_to_acquired_content() -> None:
    facts = _build_acquisition_facts(
        {"owner": "trusted", "repo": "acquired", "ref": "main"},
        "https://github.com/trusted/acquired",
        None,
        "git",
        "c" * 40,
        _UnboundVerifiedScanner(),
    )

    assert facts["verification"] == {
        "owner": False,
        "signature": False,
        "attestation": False,
        "sbom": False,
    }


def test_repository_identity_mismatch_cannot_verify_owner() -> None:
    facts = _build_acquisition_facts(
        {"owner": "trusted", "repo": "acquired", "ref": "main"},
        "https://github.com/other/repository",
        None,
        "git",
        "c" * 40,
        _Scanner(),
    )

    assert facts["source"]["verified_owner"] is False
    assert facts["verification"]["owner"] is False


def test_repository_owner_requires_explicit_server_verification() -> None:
    base = {
        "owner": "trusted",
        "repo": "acquired",
    }
    for value in (None, False, "true", 1):
        parsed = {**base, "repository_verified": value}
        assert (
            verify_acquired_repository(
                parsed,
                "https://github.com/trusted/acquired",
                "git",
                "c" * 40,
            )
            is False
        )

    assert (
        verify_acquired_repository(
            {**base, "repository_verified": True},
            "https://github.com/trusted/acquired",
            "git",
            "c" * 40,
        )
        is True
    )


def test_artifact_verification_requires_valid_sha256_binding() -> None:
    for content_sha256 in ("", "not-a-hash", "A" * 64):
        facts = build_verification_facts(
            parsed={"owner": "trusted", "repo": "acquired"},
            repository_url="https://github.com/trusted/acquired",
            acquisition_method="git",
            commit_hash="c" * 40,
            content_sha256=content_sha256,
            server_verification={
                "content_sha256": content_sha256,
                "signature": True,
                "attestation": True,
                "sbom": True,
            },
        )

        assert facts == {
            "owner": False,
            "signature": False,
            "attestation": False,
            "sbom": False,
        }


def test_metadata_replacement_drops_untrusted_source_and_integrity_fields() -> None:
    metadata = {
        "name": "demo",
        "source": {
            "repository_url": "https://github.com/attacker/claimed",
            "verified_owner": True,
        },
        "integrity": {
            "sha256": "a" * 64,
            "signature": "fake",
            "sbom_url": "https://attacker.example/sbom",
        },
    }
    facts = {
        "source": {
            "type": "github",
            "repository_url": "https://github.com/trusted/acquired",
            "commit_hash": "c" * 40,
        },
        "integrity": {"sha256": "d" * 64},
    }

    safe = _apply_acquisition_facts(metadata, facts)

    assert safe["name"] == "demo"
    assert safe["source"] == facts["source"]
    assert safe["integrity"] == facts["integrity"]


def test_package_claims_are_redacted_before_audit_persistence() -> None:
    claims = _provenance_claims(_SecretClaimsScanner())

    assert claims["source"]["repository_url"] == (
        "https://user:[REDACTED]@example.test/repo"
    )
    assert claims["integrity"]["signature"] == "Bearer [REDACTED]"
    assert claims["integrity"]["api_key"] == "[REDACTED]"


def test_version_detail_redacts_all_scan_projections() -> None:
    detail = ProducerService(_DetailRepository()).get_version_detail("ver-1")

    assert detail is not None
    assert detail["scan_summary"]["note"] == "Bearer [REDACTED]"
    assert detail["findings"][0]["evidence"] == "api_key: [REDACTED]"
    assert "file_contents" not in detail["scan_report"]
    assert detail["scan_report"]["provenance"]["package_claims"]["integrity"][
        "token"
    ] == "[REDACTED]"
    assert detail["provenance_claims"]["source"]["repository_url"] == (
        "https://u:[REDACTED]@example.test/repo"
    )


def test_artifact_hash_is_scoped_separately_from_scan_hash() -> None:
    repository = _ArtifactRepository()
    ProducerService(repository)._apply_artifact_to_version(
        "ver-1",
        {
            "download_url": "/api/v0/artifacts/demo.zip",
            "sha256": "e" * 64,
            "download_size_bytes": 123,
        },
        "demo",
        "1.0.0",
        "c" * 40,
    )

    assert repository.version["integrity"] == {
        "sha256": "e" * 64,
        "hash_scope": "artifact_archive",
        "hash_complete": True,
        "download_size_bytes": 123,
    }
    assert repository.version["acquisition_facts"]["integrity"] == {
        "sha256": "d" * 64,
        "hash_scope": "scanned_source",
        "hash_complete": True,
    }


def test_public_version_integrity_accepts_server_hash_scope_fields() -> None:
    detail = VersionDetail.model_validate(
        {
            "id": "ver-1",
            "package_id": "pkg-1",
            "version": "1.0.0",
            "status": "published",
            "integrity": {
                "sha256": "e" * 64,
                "hash_scope": "artifact_archive",
                "hash_complete": True,
                "download_size_bytes": 123,
            },
        }
    )

    assert detail.integrity is not None
    assert detail.integrity.hash_scope == "artifact_archive"
    assert detail.integrity.hash_complete is True


def test_provenance_audit_shape_is_declared_in_scan_schema() -> None:
    schema_path = (
        Path(__file__).resolve().parents[3]
        / "packages"
        / "schema"
        / "scan-report.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    provenance = {
        "acquisition_facts": {
            "source": {"commit_hash": "c" * 40},
            "integrity": {
                "sha256": None,
                "hash_scope": "scanned_source",
                "hash_complete": False,
            },
            "verification": {
                "owner": False,
                "signature": False,
                "attestation": False,
                "sbom": False,
            },
            "acquisition_method": "git",
        },
        "package_claims": {
            "source": {"verified_owner": True},
            "integrity": {"signature": "fake"},
        },
    }

    jsonschema.validate(provenance, schema["properties"]["provenance"])
    report = ScanReport.model_validate(
        {
            "scan_id": "scan-test",
            "scanner_version": "0.6.0",
            "provenance": provenance,
        }
    )
    assert report.provenance is not None
