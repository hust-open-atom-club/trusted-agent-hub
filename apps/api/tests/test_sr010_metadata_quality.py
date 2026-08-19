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

    def test_missing_license_low(self, tmp_path):
        """Empty / NONE license（且无 LICENSE 文件）→ low finding."""
        meta = _full_meta()
        meta["license"] = "NONE"
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata=meta,
            target_dir=tmp_path,
        )
        metadata_quality.run(s)
        findings = [f for f in s.findings if "缺少有效许可证" in f["title"]]
        assert len(findings) == 1
        assert findings[0]["severity"] == "low"

    def test_license_file_in_package_suppresses_finding(self, tmp_path):
        """包目录内有 LICENSE 文件 → 视为已声明许可证，不报。"""
        (tmp_path / "LICENSE").write_text("MIT License — Permission is hereby granted", encoding="utf-8")
        meta = _full_meta()
        meta["license"] = ""
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata=meta,
            target_dir=tmp_path,
        )
        metadata_quality.run(s)
        titles = [f["title"] for f in s.findings]
        assert not any("缺少有效许可证" in t for t in titles)

    def test_license_file_in_parent_dir_suppresses_finding(self, tmp_path):
        """LICENSE 在父目录（仓库根）→ 向上遍历同样视为已声明。"""
        (tmp_path / "LICENSE.md").write_text("Apache License, Version 2.0", encoding="utf-8")
        pkg_dir = tmp_path / "skills" / "demo"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "SKILL.md").write_text("# hi", encoding="utf-8")
        meta = _full_meta()
        meta["license"] = ""
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata=meta,
            target_dir=pkg_dir,
        )
        metadata_quality.run(s)
        titles = [f["title"] for f in s.findings]
        assert not any("缺少有效许可证" in t for t in titles)

    def test_license_file_exempts_required_field(self, tmp_path):
        """有 LICENSE 文件时，「元数据不完整」列表不应包含 license。"""
        (tmp_path / "LICENSE").write_text("MIT License", encoding="utf-8")
        meta = _full_meta()
        meta["license"] = ""
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata=meta,
            target_dir=tmp_path,
        )
        metadata_quality.run(s)
        missing = [f for f in s.findings if "元数据不完整" in f["title"]]
        assert not any("license" in str(f.get("description", "")) for f in missing)

    def test_package_json_backfills_version_and_license(self, tmp_path):
        """frontmatter 缺 version/license 但 package.json 有 → scanner 兜底，不报缺失。"""
        from scanners.risk_scanner.scanner import RiskScanner
        (tmp_path / "SKILL.md").write_text(
            "---\nname: demo\n---\n# hi\n", encoding="utf-8"
        )
        (tmp_path / "package.json").write_text(
            '{"name": "demo", "version": "0.1.0", "license": "MIT", '
            '"description": "a demo package description"}',
            encoding="utf-8",
        )
        report = RiskScanner(str(tmp_path)).scan()
        titles = [f["title"] for f in report["findings"]]
        assert not any(
            "元数据不完整" in t and ("version" in t or "license" in t)
            for t in titles
        ), f"version/license 应由 package.json 兜底: {titles}"

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
