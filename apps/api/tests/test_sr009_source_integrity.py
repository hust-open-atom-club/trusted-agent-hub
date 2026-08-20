"""SR-009: Source integrity rule unit tests."""

import pytest

from scanners.risk_scanner.rules import source_integrity
from scanners.risk_scanner.scanner import RiskScanner
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

    def test_scanner_injects_acquired_commit_and_content_hash(self, tmp_path):
        """Acquisition facts make an ordinary GitHub package low, not medium."""
        (tmp_path / "SKILL.md").write_text(
            "---\nname: demo\nversion: 1.0.0\ndescription: demo\n"
            "author: demo\nlicense: MIT\ntype: skill\n---\n# Demo\n",
            encoding="utf-8",
        )
        scanner = RiskScanner(tmp_path, source_commit_hash="b" * 40)
        report = scanner.scan()

        finding = next(f for f in report["findings"] if f["rule_id"] == "SR-009")
        assert finding["severity"] == "low"
        assert "SHA256" not in finding["description"]
        assert "commit hash" not in finding["description"]
        assert scanner._package_metadata["integrity"]["sha256"]
        assert scanner._package_metadata["source"]["commit_hash"] == "b" * 40

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

    def test_missing_signature_only_is_low(self, tmp_path):
        """sha256/commit 齐全但无签名/SBOM（生态常态）→ low。"""
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
        assert s.findings[0]["severity"] == "low"

    def test_invalid_sha256_is_medium(self, tmp_path):
        """sha256 非法（核心完整性缺失）→ medium。"""
        meta = _full_meta()
        meta["integrity"]["sha256"] = "not-a-hash"
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata=meta,
            target_dir=tmp_path,
        )
        source_integrity.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "medium"

    def test_full_integrity_no_finding(self, tmp_path):
        """Complete integrity + locked commit hash → no findings."""
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata=_full_meta(),
            target_dir=tmp_path,
        )
        source_integrity.run(s)
        assert s.findings == []
