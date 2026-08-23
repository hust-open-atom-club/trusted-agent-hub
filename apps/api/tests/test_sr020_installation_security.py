"""SR-020: installation entry point security checks."""

import json

from packages.schema.extract_skills import extract_single_skill
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
