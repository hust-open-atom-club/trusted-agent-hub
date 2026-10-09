"""License inheritance uses only explicit, bounded repository snapshots."""

from pathlib import Path

import pytest

from packages.schema.extract_skills import (
    ScanResult, extract_license, extract_single_skill, scan_directory,
)
from scanners.risk_scanner.inventory import build_inventory, load_text_files
from scanners.risk_scanner.policy import ScanPolicy
from scanners.risk_scanner.rules import metadata_quality
from src.routers import trust


LICENSE_VARIANTS = [
    "LICENSE", "license", "LiCeNsE.MD", "license.txt", "LICENSE.markdown",
    "licence", "LICENCE.md", "licence.txt", "LiCeNcE.markdown",
    "copying", "COPYING.MD", "copying.txt", "CoPyInG.MarkDown",
]


def _write_skill(package: Path) -> None:
    package.mkdir(parents=True)
    (package / "SKILL.md").write_text(
        "---\nname: nested-demo\ndescription: A nested package fixture\n---\n# Demo\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize("license_name", LICENSE_VARIANTS)
def test_parent_license_survives_disk_changes(tmp_path, monkeypatch, license_name):
    package = tmp_path / "repository" / "skills" / "demo"
    _write_skill(package)
    repository = package.parent.parent
    license_file = repository / license_name
    license_file.write_text("MIT License", encoding="utf-8")
    repo_inventory, repo_contents = trust._build_repository_snapshot(repository, "skills/demo")
    parent_licenses = trust._select_parent_license_files("skills/demo", repo_inventory, repo_contents)
    assert parent_licenses == {license_name: "MIT License"}
    inventory = build_inventory(package, ScanPolicy())
    contents = load_text_files(inventory)

    license_file.write_text("Apache License, Version 2.0", encoding="utf-8")
    repo_contents.clear()
    monkeypatch.setattr(
        "packages.schema.extract_skills.build_inventory",
        lambda *_args, **_kwargs: pytest.fail("unexpected second inventory"),
    )
    monkeypatch.setattr(
        "packages.schema.extract_skills.load_text_files",
        lambda *_args, **_kwargs: pytest.fail("unexpected second read"),
    )
    metadata = extract_single_skill(
        package,
        subdirectory="skills/demo",
        inventory=inventory,
        file_contents=contents,
        parent_license_files=parent_licenses,
    )

    assert metadata["license"] == "MIT"


@pytest.mark.parametrize("license_name", LICENSE_VARIANTS)
def test_local_license_snapshot_agrees_with_sr010(tmp_path, license_name):
    (tmp_path / license_name).write_text("MIT License", encoding="utf-8")
    assert metadata_quality._find_license_file(tmp_path).name == license_name
    # Dictionary keys are case-sensitive on every platform, including Windows.
    result = ScanResult(
        directory_name="demo",
        directory_path=tmp_path,
        file_contents={license_name: "MIT License", "package.json": '{"license":"ISC"}'},
    )

    assert extract_license(result) == "MIT"


def test_multiple_license_names_have_stable_precedence(tmp_path):
    result = ScanResult(
        directory_name="demo",
        directory_path=tmp_path,
        file_contents={
            "COPYING": "BSD 2-Clause",
            "LICENSE.txt": "ISC License",
            "license": "Apache License",
            "LICENSE.md": "Apache License",
            "LICENSE": "MIT License",
        },
    )

    assert extract_license(result) == "MIT"


def test_snapshot_candidate_matching_preserves_posix_directory_boundaries():
    assert trust._parent_license_candidates("skills/demo", [
        "license", "skills/CoPyInG.txt", "Skills/LICENSE", "other/LICENSE",
        "skills/demo/LICENSE", "../LICENSE", "skills/LICENSE.bak",
    ]) == ["skills/CoPyInG.txt", "license"]


@pytest.mark.parametrize(
    ("local_files", "expected"),
    [
        ({"LICENSE": "Apache License", "package.json": '{"license":"ISC"}'}, "Apache-2.0"),
        ({"package.json": '{"license":"ISC"}', "pyproject.toml": 'license = "BSD-2-Clause"'}, "ISC"),
        ({"pyproject.toml": 'license = "BSD-2-Clause"'}, "BSD-2-Clause"),
        ({"package.json": '{"license":"UNLICENSED"}'}, "UNLICENSED"),
    ],
)
def test_local_license_precedence_is_preserved(tmp_path, local_files, expected):
    package = tmp_path / "demo"
    _write_skill(package)
    for name, content in local_files.items():
        (package / name).write_text(content, encoding="utf-8")

    metadata = extract_single_skill(package, parent_license_files={"LICENSE": "MIT License"})

    assert metadata["license"] == expected


@pytest.mark.parametrize("nearest_text", ["Apache License", "Unrecognized custom terms"])
def test_nearest_recognized_parent_license_wins(tmp_path, nearest_text):
    package = tmp_path / "packages" / "team" / "demo"
    _write_skill(package)
    (tmp_path / "LICENSE").write_text("MIT License", encoding="utf-8")
    (package.parent / "LICENSE.txt").write_text(nearest_text, encoding="utf-8")
    inventory, contents = trust._build_repository_snapshot(tmp_path, "packages/team/demo")
    licenses = trust._select_parent_license_files("packages/team/demo", inventory, contents)

    metadata = extract_single_skill(package, parent_license_files=licenses)

    assert metadata["license"] == ("Apache-2.0" if nearest_text == "Apache License" else "MIT")


def test_license_outside_repository_or_in_sibling_is_not_inherited(tmp_path):
    (tmp_path / "LICENSE").write_text("MIT License", encoding="utf-8")
    repository = tmp_path / "repository"
    package = repository / "skills" / "demo"
    _write_skill(package)
    sibling = repository / "other"
    sibling.mkdir()
    (sibling / "LICENSE").write_text("MIT License", encoding="utf-8")
    inventory, contents = trust._build_repository_snapshot(repository, "skills/demo")
    # Even extra caller-supplied keys must not become parent evidence.
    contents["../LICENSE"] = "MIT License"
    licenses = trust._select_parent_license_files("skills/demo", inventory, contents)

    assert licenses == {}
    assert extract_single_skill(package, parent_license_files=licenses)["license"] == "UNLICENSED"


@pytest.mark.parametrize(
    ("inventory_allow", "explicit_allow", "expected"),
    [
        (False, None, "UNLICENSED"),
        (True, None, "MIT"),
        (False, False, "UNLICENSED"),
        (True, True, "MIT"),
        (None, False, "UNLICENSED"),
        (None, True, "MIT"),
        (None, None, "MIT"),
    ],
    ids=[
        "inventory-disabled", "inventory-enabled", "explicit-disabled", "explicit-enabled",
        "legacy-explicit-disabled", "legacy-explicit-enabled", "legacy-default",
    ],
)
def test_parent_license_policy_resolution(tmp_path, inventory_allow, explicit_allow, expected):
    package = tmp_path / "demo"
    _write_skill(package)
    policy = ScanPolicy(allow_parent_license_files=inventory_allow is not False)
    inventory = build_inventory(package, policy)
    contents = load_text_files(inventory)
    if inventory_allow is None:
        inventory.policy = None

    explicit_policy = (
        ScanPolicy(allow_parent_license_files=explicit_allow) if explicit_allow is not None else None
    )
    result = scan_directory(
        package, policy=explicit_policy, inventory=inventory, file_contents=contents,
    )
    assert extract_license(result, parent_license_files={"LICENSE": "MIT License"}) == expected

    metadata = extract_single_skill(
        package,
        inventory=inventory,
        file_contents=contents,
        policy=explicit_policy,
        parent_license_files={"LICENSE": "MIT License"},
    )

    assert metadata["license"] == expected


@pytest.mark.parametrize(
    "policy",
    [ScanPolicy(max_file_bytes=16), ScanPolicy(max_total_bytes=12)],
    ids=["oversized", "truncated"],
)
def test_parent_license_respects_snapshot_byte_limits(tmp_path, policy):
    package = tmp_path / "skills" / "demo"
    _write_skill(package)
    (tmp_path / "LICENSE").write_text("MIT License\n" + "x" * 100, encoding="utf-8")
    inventory, contents = trust._build_repository_snapshot(tmp_path, "skills/demo", policy=policy)

    assert trust._select_parent_license_files("skills/demo", inventory, contents) == {}


@pytest.mark.parametrize("license_name", LICENSE_VARIANTS)
def test_parent_license_is_read_before_unrelated_source_files(tmp_path, license_name):
    package = tmp_path / "skills" / "demo"
    _write_skill(package)
    (tmp_path / "a.py").write_text("x" * 100, encoding="utf-8")
    (tmp_path / license_name).write_text("MIT License", encoding="utf-8")
    policy = ScanPolicy(max_files=1, max_file_bytes=100, max_total_bytes=100)
    inventory, contents = trust._build_repository_snapshot(tmp_path, "skills/demo", policy=policy)

    assert trust._select_parent_license_files("skills/demo", inventory, contents) == {
        license_name: "MIT License",
    }


def test_license_changed_during_snapshot_read_is_not_inherited(tmp_path):
    package = tmp_path / "skills" / "demo"
    _write_skill(package)
    license_file = tmp_path / "LICENSE"
    license_file.write_text("MIT License", encoding="utf-8")
    inventory = build_inventory(tmp_path, ScanPolicy())

    license_file.write_text("Apache License, Version 2.0", encoding="utf-8")
    contents = load_text_files(inventory)

    assert contents["LICENSE"] == "Apache License, Version 2.0"
    assert trust._select_parent_license_files("skills/demo", inventory, contents) == {}
