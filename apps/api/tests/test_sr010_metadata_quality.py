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
        titles = [f["title"] for f in s.review_advisories]
        assert any("元数据不完整" in t for t in titles)
        missing = [f for f in s.review_advisories if "元数据不完整" in f["title"]][0]
        assert missing["level"] == "warning"
        assert missing["deduction"] == 0
        assert not any("元数据不完整" in f["title"] for f in s.findings)

    def test_missing_license_low(self, tmp_path, monkeypatch):
        """Empty / NONE license（且无 LICENSE 文件）→ low finding."""
        meta = _full_meta()
        meta["license"] = "NONE"
        monkeypatch.setattr(metadata_quality, "_find_license_file", lambda *_args: None)
        s = MockScanner(
            files={"SKILL.md": "# hi"},
            _package_metadata=meta,
            target_dir=tmp_path,
        )
        metadata_quality.run(s)
        advisories = [f for f in s.review_advisories if f["code"] == "metadata_incomplete"]
        assert len(advisories) == 1
        assert "license" in advisories[0]["description"]
        assert advisories[0]["deduction"] == 0

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
        assert not any(
            f["code"] == "metadata_incomplete" and "license" in f["description"]
            for f in s.review_advisories
        )

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
        assert not any(
            f["code"] == "metadata_incomplete" and "license" in f["description"]
            for f in s.review_advisories
        )

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
        missing = [f for f in s.review_advisories if f["code"] == "metadata_incomplete"]
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
        titles = [f["title"] for f in report["review_advisories"]]
        assert not any(
            "元数据不完整" in t and ("version" in t or "license" in t)
            for t in titles
        ), f"version/license 应由 package.json 兜底: {titles}"

    def test_package_name_mismatch_is_scoped_to_skill_root(self, tmp_path):
        """父仓库的 package name 不应与嵌套 skill name 强行比较。"""
        (tmp_path / "package.json").write_text(
            '{"name": "superpowers"}', encoding="utf-8"
        )
        skill_dir = tmp_path / "skills" / "brainstorming"
        skill_dir.mkdir(parents=True)
        meta = _full_meta()
        meta["name"] = "brainstorming"
        s = MockScanner(
            files={"SKILL.md": "# brainstorming"},
            _package_metadata=meta,
            target_dir=skill_dir,
        )

        metadata_quality.run(s)

        assert not any(
            "技能名与分发包名不一致" in f["title"]
            for f in s.review_advisories
        )

    def test_package_name_mismatch_is_info_only(self, tmp_path):
        """技能名与真实分发包名不同是可解释元数据差异，不是安全风险。"""
        meta = _full_meta()
        meta["name"] = "pwnhustcollege"
        s = MockScanner(
            files={
                "SKILL.md": "# pwnhustcollege",
                "package.json": '{"name":"pwnhustcollege-skill"}',
            },
            _package_metadata=meta,
            target_dir=tmp_path,
        )

        metadata_quality.run(s)

        mismatch = [
            f for f in s.review_advisories
            if "技能名与分发包名不一致" in f["title"]
        ]
        assert len(mismatch) == 1
        assert mismatch[0]["level"] == "info"

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
        titles = [f["title"] for f in s.review_advisories]
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

    def test_shell_source_is_not_binary_artifact(self, tmp_path):
        """.sh source is analyzed by shell rules, not metadata structure."""
        s = MockScanner(
            files={"SKILL.md": "# hi", "scripts/run.sh": "echo hi\n"},
            _package_metadata=_full_meta(),
            target_dir=tmp_path,
        )
        metadata_quality.run(s)
        assert not any("可疑文件" in f["title"] for f in s.findings)

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
