"""SR-010: Metadata quality + structure check rule unit tests."""

import json

import pytest

from scanners.risk_scanner.dependency_parsers.osv_client import OSVClient
from scanners.risk_scanner.policy import ScanPolicy
from scanners.risk_scanner.rules import metadata_quality
from scanners.risk_scanner.scanner import RiskScanner
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

    @pytest.mark.parametrize("license_value", ["", "NONE", "UNLICENSED"])
    def test_missing_license_low(self, tmp_path, license_value):
        """A missing license remains an advisory even inside the project checkout."""
        meta = _full_meta()
        meta["license"] = license_value
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
        s.repository_root = tmp_path
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

    def test_malformed_metadata_is_a_rule_finding(self, tmp_path):
        """A parse error is visible as an SR-010 finding and report signal."""
        (tmp_path / "SKILL.md").write_text("# hi", encoding="utf-8")
        s = MockScanner(
            files={"manifest.json": '{"name": "demo",', "SKILL.md": "# hi"},
            _package_metadata=_full_meta(),
            target_dir=tmp_path,
        )
        s._metadata_parse_errors = [{"file": "manifest.json", "message": "invalid JSON: Expecting value"}]

        metadata_quality.run(s)

        assert len(s.findings) == 1
        assert s.findings[0]["rule_id"] == "SR-010"
        assert "manifest.json" in s.findings[0]["title"]


class TestSR010LicenseBoundary:
    @pytest.mark.parametrize(
        ("license_location", "explicit_root", "allow_parent", "missing"),
        [
            ("package", False, True, False),
            ("repository", False, True, True),
            ("workspace", False, True, True),
            ("repository", True, True, False),
            ("workspace", True, True, True),
            ("package", True, False, False),
            ("repository", True, False, True),
        ],
    )
    def test_license_scope(self, tmp_path, license_location, explicit_root, allow_parent, missing):
        workspace = tmp_path / "workspace"
        repository = workspace / "acquired"
        # Snapshots need not contain .git, and packages can be deeper than five levels.
        package = repository / "packages" / "group" / "tools" / "nested" / "skills" / "demo"
        package.mkdir(parents=True)
        (workspace / ".git").mkdir()
        license_dir = {
            "workspace": workspace,
            "repository": repository,
            "package": package,
        }[license_location]
        (license_dir / "LiCeNcE.markdown").write_text("MIT License", encoding="utf-8")
        meta = {**_full_meta(), "license": ""}
        (package / "manifest.json").write_text(json.dumps(meta), encoding="utf-8")
        (package / "SKILL.md").write_text("# Demo\n", encoding="utf-8")

        kwargs = {"repository_root": repository} if explicit_root else {}
        report = RiskScanner(
            package,
            source_commit_hash="a" * 40,
            policy=ScanPolicy(allow_parent_license_files=allow_parent),
            osv_client=OSVClient(enabled=False),
            mcp_semantic_model_loader=lambda: None,
            **kwargs,
        ).scan()

        assert report["scan_status"]["state"] == "complete"
        assert any(
            item["code"] == "metadata_incomplete" and "license" in item["description"]
            for item in report["review_advisories"]
        ) is missing

    @pytest.mark.parametrize("explicit_root", [False, True])
    def test_scan_at_repository_root_ignores_parent_license(self, tmp_path, explicit_root):
        (tmp_path / "LICENSE").write_text("MIT License", encoding="utf-8")
        repository = tmp_path / "repository"
        repository.mkdir()
        scanner = MockScanner(
            target_dir=repository,
            _package_metadata={**_full_meta(), "license": ""},
        )
        if explicit_root:
            scanner.repository_root = repository

        metadata_quality.run(scanner)

        assert any(
            item["code"] == "metadata_incomplete" and "license" in item["description"]
            for item in scanner.review_advisories
        )

    def test_repository_root_must_contain_target(self, tmp_path):
        package = tmp_path / "package"
        package.mkdir()
        repository = tmp_path / "repository"
        repository.mkdir()

        with pytest.raises(ValueError, match="repository_root"):
            RiskScanner(package, repository_root=repository)

    @pytest.mark.parametrize("entry_kind", ["directory", "external_symlink"])
    def test_license_entry_must_be_a_regular_file(self, tmp_path, entry_kind):
        package = tmp_path / "package"
        package.mkdir()
        license_path = package / "LICENSE"
        if entry_kind == "directory":
            license_path.mkdir()
        else:
            outside = tmp_path / "external-license"
            outside.write_text("MIT License", encoding="utf-8")
            try:
                license_path.symlink_to(outside)
            except OSError as exc:
                pytest.skip(f"Symlinks unavailable: {exc}")

        assert metadata_quality._find_license_file(package) is None
