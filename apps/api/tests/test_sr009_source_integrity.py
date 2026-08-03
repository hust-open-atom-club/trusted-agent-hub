"""SR-009: Source integrity rule unit tests."""

import pytest

from scanners.risk_scanner.rules import source_integrity
from tests.scanner_mock import MockScanner


def _full_meta() -> dict:
    return {
        "name": "demo-pkg",
        "version": "1.0.0",
        "type": "skill",
        "description": "A trustworthy demo package",
        "integrity": {
            "sha256": "a" * 64,
            "signature": "sig-abc",
            "sbom_url": "https://sbom.example.com/demo.json",
        },
        "source": {
            "repository_url": "https://github.com/demo/demo",
            "commit_hash": "a" * 40,
        },
    }


class TestSR009SourceIntegrity:

    def test_missing_metadata(self, tmp_path):
        """No metadata file at all → medium finding."""
        s = MockScanner(files={"main.py": "print(1)\n"}, target_dir=tmp_path)
        source_integrity.run(s)
        assert len(s.findings) == 1
        f = s.findings[0]
        assert f["rule_id"] == "SR-009"
        assert f["severity"] == "medium"
        assert f["category"] == "source_integrity"
        assert "缺少包元数据" in f["title"]

    def test_incomplete_integrity_medium(self, tmp_path):
        """Metadata without sha256/signature/sbom/commit_hash → medium finding."""
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata={"name": "demo", "version": "1.0.0", "integrity": {}, "source": {}},
            target_dir=tmp_path,
        )
        source_integrity.run(s)
        assert len(s.findings) == 1
        f = s.findings[0]
        assert f["severity"] == "medium"
        assert "来源完整性不足" in f["title"]

    def test_missing_signature_is_medium_even_with_sha256(self, tmp_path):
        """sha256 present but no signature → still medium (missing_sig)."""
        meta = _full_meta()
        del meta["integrity"]["signature"]
        del meta["integrity"]["sbom_url"]
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata=meta,
            target_dir=tmp_path,
        )
        source_integrity.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "medium"

    def test_invalid_sha256_low_severity(self, tmp_path):
        """Signature present but sha256 invalid → low finding."""
        meta = _full_meta()
        meta["integrity"]["sha256"] = "not-a-hash"
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata=meta,
            target_dir=tmp_path,
        )
        source_integrity.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "low"

    def test_full_integrity_no_finding(self, tmp_path):
        """Complete integrity + locked commit hash → no findings."""
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata=_full_meta(),
            target_dir=tmp_path,
        )
        source_integrity.run(s)
        assert s.findings == []
