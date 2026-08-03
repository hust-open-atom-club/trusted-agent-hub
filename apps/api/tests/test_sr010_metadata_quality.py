"""SR-010: Metadata quality + structure check rule unit tests."""

import pytest

from scanners.risk_scanner.rules import metadata_quality
from tests.scanner_mock import MockScanner


def _full_meta() -> dict:
    return {
        "name": "demo-pkg",
        "version": "1.0.0",
        "type": "skill",
        "description": "A complete demo package with a long description",
        "author": "tester",
        "license": "MIT",
    }


class TestSR010MetadataQuality:

    def test_missing_required_fields(self, tmp_path):
        """Missing author/license → low finding listing the fields."""
        meta = _full_meta()
        del meta["author"]
        del meta["license"]
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata=meta,
            target_dir=tmp_path,
        )
        metadata_quality.run(s)
        titles = [f["title"] for f in s.findings]
        assert any("元数据不完整" in t for t in titles)
        missing = [f for f in s.findings if "元数据不完整" in f["title"]][0]
        assert missing["severity"] == "low"

    def test_missing_license_medium(self, tmp_path):
        """Empty / NONE license → medium finding."""
        meta = _full_meta()
        meta["license"] = "NONE"
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata=meta,
            target_dir=tmp_path,
        )
        metadata_quality.run(s)
        titles = [f["title"] for f in s.findings]
        assert any("缺少有效许可证" in t for t in titles)

    def test_short_description_info(self, tmp_path):
        """Description shorter than 10 chars → info finding."""
        meta = _full_meta()
        meta["description"] = "tiny"
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata=meta,
            target_dir=tmp_path,
        )
        metadata_quality.run(s)
        titles = [f["title"] for f in s.findings]
        assert any("描述过短" in t for t in titles)

    def test_dangerous_extension_file(self, tmp_path):
        """.exe file in package → medium finding."""
        s = MockScanner(
            files={"SKILL.md": "# hi", "tool.exe": "x"},
            _package_metadata=_full_meta(),
            target_dir=tmp_path,
        )
        metadata_quality.run(s)
        titles = [f["title"] for f in s.findings]
        assert any("可疑文件" in t for t in titles)

    def test_missing_required_file_for_type(self, tmp_path):
        """skill type without SKILL.md on disk → medium finding."""
        meta = _full_meta()
        s = MockScanner(
            files={"main.py": "print(1)\n"},
            _package_metadata=meta,
            target_dir=tmp_path,
        )
        metadata_quality.run(s)
        titles = [f["title"] for f in s.findings]
        assert any("缺少必要文件" in t for t in titles)

    def test_complete_metadata_no_finding(self, tmp_path):
        """Complete metadata + required file present + safe files → no findings."""
        (tmp_path / "SKILL.md").write_text("# hi", encoding="utf-8")
        s = MockScanner(
            files={"SKILL.md": "# hi", "main.py": "print(1)\n"},
            _package_metadata=_full_meta(),
            target_dir=tmp_path,
        )
        metadata_quality.run(s)
        assert s.findings == []
