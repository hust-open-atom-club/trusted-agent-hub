"""SR-020: installation entry point security checks."""

import json

from packages.schema.extract_skills import extract_single_skill
from scanners.risk_scanner.scanner import RiskScanner
from scanners.risk_scanner.rules import installation_security
from tests.scanner_mock import MockScanner


def test_bin_installer_with_user_path_deletion_requires_confirmation() -> None:
    scanner = MockScanner(
        files={
            "package.json": '{"name":"demo-skill","bin":{"demo":"bin/install.js"}}',
            "bin/install.js": (
                "const targetDir = path.resolve(process.argv[3]);\n"
                "fs.rmSync(targetDir, { recursive: true, force: true });\n"
            ),
        }
    )

    installation_security.run(scanner)

    assert len(scanner.findings) == 1
    assert scanner.findings[0]["rule_id"] == "SR-020"
    assert scanner.findings[0]["severity"] == "medium"
    assert scanner.findings[0]["requires_confirmation"] is True


def test_package_without_installer_is_ignored() -> None:
    scanner = MockScanner(
        files={
            "package.json": '{"name":"demo-skill"}',
            "SKILL.md": "# demo",
        }
    )

    installation_security.run(scanner)

    assert scanner.findings == []


def test_nested_package_lifecycle_is_reported_with_manifest_path() -> None:
    scanner = MockScanner(
        files={
            "packages/demo/package.json": json.dumps(
                {"name": "demo", "scripts": {"postinstall": "echo nested"}}
            ),
        }
    )

    installation_security.run(scanner)

    assert len(scanner.findings) == 1
    finding = scanner.findings[0]
    assert finding["location"]["file"] == "packages/demo/package.json"
    assert "packages/demo/package.json" in finding["title"]
    assert "packages/demo/package.json" in finding["evidence"]


def test_root_and_nested_package_lifecycles_are_both_reported() -> None:
    scanner = MockScanner(
        files={
            "package.json": json.dumps({"scripts": {"postinstall": "echo root"}}),
            "packages/demo/package.json": json.dumps(
                {"scripts": {"postinstall": "echo nested"}}
            ),
        }
    )

    installation_security.run(scanner)

    assert [finding["location"]["file"] for finding in scanner.findings] == [
        "package.json",
        "packages/demo/package.json",
    ]


def test_nested_bin_entrypoint_is_resolved_relative_to_manifest() -> None:
    scanner = MockScanner(
        files={
            "packages/demo/package.json": json.dumps(
                {"bin": {"demo": "./bin/install.js"}}
            ),
            "packages/demo/bin/install.js": (
                "const targetDir = path.resolve(process.argv[3]);\n"
                "fs.rmSync(targetDir, { recursive: true, force: true });\n"
            ),
        }
    )

    installation_security.run(scanner)

    assert len(scanner.findings) == 1
    finding = scanner.findings[0]
    assert finding["location"]["file"] == "packages/demo/bin/install.js"
    assert "packages/demo/package.json" in finding["title"]
    assert "packages/demo/package.json" in finding["evidence"]


def test_malformed_nested_package_manifest_is_reported_as_parse_error(tmp_path) -> None:
    manifest = tmp_path / "packages" / "demo" / "package.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text("{ invalid", encoding="utf-8")

    scanner = RiskScanner(tmp_path)
    report = scanner.scan()

    assert not any(finding["rule_id"] == "SR-020" for finding in report["findings"])
    assert report["structural_analysis"]["parse_errors"] == 1
    assert report["scan_status"]["state"] == "partial"
    assert any(
        error["file"] == "packages/demo/package.json"
        for error in scanner.analysis.parse_errors
    )


def test_extractor_scopes_installer_deletion_separately(tmp_path) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\nname: demo-installer\ndescription: Installer demo\n---\n",
        encoding="utf-8",
    )
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "demo-installer", "bin": {"demo": "bin/install.js"}}),
        encoding="utf-8",
    )
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "install.js").write_text(
        "const targetDir = path.resolve(process.argv[3]);\n"
        "fs.rmSync(targetDir, { recursive: true, force: true });\n",
        encoding="utf-8",
    )

    metadata = extract_single_skill(tmp_path)

    assert metadata["permissions"]["filesystem"]["delete"] is False
    assert any(
        item["capability"] == "installation.filesystem.delete"
        for item in metadata["permission_evidence"]
    )
