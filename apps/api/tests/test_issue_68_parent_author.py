"""Regression coverage for nearest-parent package.json author inheritance."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from packages.schema.extract_skills import extract_single_skill
from scanners.risk_scanner.inventory import (
    ScanInventory,
    build_inventory,
    load_text_files,
)
from scanners.risk_scanner.policy import ScanPolicy
from src.routers import trust


def _write_package(path: Path, author: str | None) -> None:
    value: dict[str, object] = {"name": path.parent.name}
    if author is not None:
        value["author"] = {"name": author}
    path.write_text(json.dumps(value), encoding="utf-8")


def _write_padded_package(path: Path, author: str) -> None:
    value = {
        "description": "x" * 500,
        "author": {"name": author},
    }
    path.write_text(json.dumps(value), encoding="utf-8")


def _write_skill(path: Path, *, author: str | None = None) -> None:
    author_line = f"author: {author}\n" if author else ""
    path.write_text(
        "---\n"
        "name: issue-68-demo\n"
        "description: Regression fixture for parent author precedence\n"
        f"{author_line}"
        "---\n"
        "# Demo\n",
        encoding="utf-8",
    )


def _target_snapshot(
    skill_dir: Path,
) -> tuple[ScanPolicy, ScanInventory, dict[str, str]]:
    policy = ScanPolicy(max_file_bytes=4096, max_total_bytes=16384)
    inventory = build_inventory(skill_dir, policy)
    contents = load_text_files(inventory, policy=policy)
    return policy, inventory, contents


def test_parent_candidates_are_nearest_first_with_root_last() -> None:
    assert trust._parent_package_json_candidates("packages/team/demo") == [
        "packages/team/package.json",
        "packages/package.json",
        "package.json",
    ]
    assert trust._parent_package_json_candidates("demo") == ["package.json"]
    assert trust._parent_package_json_candidates(".") == []
    assert trust._parent_package_json_candidates(None) == []


def test_parent_selector_prefers_the_nearest_snapshot_author() -> None:
    selected, source = trust._select_parent_package_json(
        "packages/team/demo",
        {
            "package.json": json.dumps({"author": {"name": "ROOT"}}),
            "packages/package.json": json.dumps(
                {"author": {"name": "INTERMEDIATE"}}
            ),
            "packages/team/package.json": json.dumps(
                {"author": {"name": "NEAREST"}}
            ),
        },
    )

    assert source == "packages/team/package.json"
    assert selected == {"author": {"name": "NEAREST"}}


def test_parent_selector_falls_back_to_root_for_unusable_nearer_files() -> None:
    selected, source = trust._select_parent_package_json(
        "packages/team/demo",
        {
            "package.json": json.dumps({"author": "ROOT"}),
            "packages/package.json": "not-json",
            "packages/team/package.json": json.dumps({"name": "team"}),
        },
    )

    assert source == "package.json"
    assert selected == {"author": "ROOT"}


def test_parent_selector_skips_author_objects_without_a_name() -> None:
    selected, source = trust._select_parent_package_json(
        "packages/team/demo",
        {
            "package.json": json.dumps({"author": {"name": "ROOT"}}),
            "packages/team/package.json": json.dumps(
                {"author": {"email": "nearest@example.com"}}
            ),
        },
    )

    assert source == "package.json"
    assert selected == {"author": {"name": "ROOT"}}


def test_parent_selector_skips_placeholder_authors() -> None:
    selected, source = trust._select_parent_package_json(
        "packages/team/demo",
        {
            "package.json": json.dumps({"author": {"name": "ROOT"}}),
            "packages/team/package.json": json.dumps({"author": "UNKNOWN"}),
        },
    )

    assert source == "package.json"
    assert selected == {"author": {"name": "ROOT"}}


def test_parent_selector_skips_json_value_errors() -> None:
    selected, source = trust._select_parent_package_json(
        "packages/team/demo",
        {
            "package.json": json.dumps({"author": "ROOT"}),
            "packages/team/package.json": (
                '{"author": ' + "9" * 5000 + "}"
            ),
        },
    )

    assert source == "package.json"
    assert selected == {"author": "ROOT"}


def test_parent_author_is_immutable_after_repository_snapshot(
    tmp_path: Path,
) -> None:
    nested = tmp_path / "packages" / "team"
    skill_dir = nested / "demo"
    skill_dir.mkdir(parents=True)
    _write_package(tmp_path / "package.json", "ROOT")
    _write_package(nested / "package.json", "NEAREST")
    _write_skill(skill_dir / "SKILL.md")

    repo_policy = ScanPolicy(max_file_bytes=4096, max_total_bytes=16384)
    repo_inventory = build_inventory(tmp_path, repo_policy)
    repo_contents = load_text_files(repo_inventory, policy=repo_policy)
    parent_package, source = trust._select_parent_package_json(
        "packages/team/demo",
        repo_contents,
    )
    policy, inventory, contents = _target_snapshot(skill_dir)

    _write_package(nested / "package.json", "MUTATED_AFTER_SCAN")
    metadata = extract_single_skill(
        skill_dir,
        policy=policy,
        inventory=inventory,
        file_contents=contents,
        parent_package_json=parent_package,
    )

    assert source == "packages/team/package.json"
    assert metadata["author"]["name"] == "NEAREST"


def test_local_package_and_frontmatter_keep_higher_precedence(
    tmp_path: Path,
) -> None:
    skill_dir = tmp_path / "packages" / "demo"
    skill_dir.mkdir(parents=True)
    _write_skill(skill_dir / "SKILL.md")
    _write_package(skill_dir / "package.json", "LOCAL")
    policy, inventory, contents = _target_snapshot(skill_dir)

    local_metadata = extract_single_skill(
        skill_dir,
        policy=policy,
        inventory=inventory,
        file_contents=contents,
        parent_package_json={"author": {"name": "PARENT"}},
    )
    assert local_metadata["author"]["name"] == "LOCAL"

    _write_skill(skill_dir / "SKILL.md", author="FRONTMATTER")
    policy, inventory, contents = _target_snapshot(skill_dir)
    frontmatter_metadata = extract_single_skill(
        skill_dir,
        policy=policy,
        inventory=inventory,
        file_contents=contents,
        parent_package_json={"author": {"name": "PARENT"}},
    )
    assert frontmatter_metadata["author"]["name"] == "FRONTMATTER"


def test_extractor_does_not_read_ambient_parent_metadata(
    tmp_path: Path,
) -> None:
    skill_dir = tmp_path / "packages" / "demo"
    skill_dir.mkdir(parents=True)
    _write_skill(skill_dir / "SKILL.md")
    policy, inventory, contents = _target_snapshot(skill_dir)

    _write_package(tmp_path / "packages" / "package.json", "AMBIENT")
    metadata = extract_single_skill(
        skill_dir,
        policy=policy,
        inventory=inventory,
        file_contents=contents,
        parent_package_json=None,
    )

    assert metadata["author"]["name"] == "UNKNOWN"


def test_invalid_local_package_json_uses_parent_author(tmp_path: Path) -> None:
    skill_dir = tmp_path / "packages" / "demo"
    skill_dir.mkdir(parents=True)
    _write_skill(skill_dir / "SKILL.md")
    (skill_dir / "package.json").write_text(
        '{"value": ' + "9" * 5000 + "}",
        encoding="utf-8",
    )
    policy, inventory, contents = _target_snapshot(skill_dir)

    metadata = extract_single_skill(
        skill_dir,
        policy=policy,
        inventory=inventory,
        file_contents=contents,
        parent_package_json={"author": {"name": "PARENT"}},
    )

    assert metadata["author"]["name"] == "PARENT"


def test_placeholder_authors_use_parent_author(tmp_path: Path) -> None:
    skill_dir = tmp_path / "packages" / "demo"
    skill_dir.mkdir(parents=True)
    _write_skill(skill_dir / "SKILL.md", author="UNKNOWN")
    _write_package(skill_dir / "package.json", "UNKNOWN")
    policy, inventory, contents = _target_snapshot(skill_dir)

    metadata = extract_single_skill(
        skill_dir,
        policy=policy,
        inventory=inventory,
        file_contents=contents,
        parent_package_json={"author": {"name": "PARENT"}},
    )

    assert metadata["author"]["name"] == "PARENT"


def test_priority_parent_metadata_is_not_crowded_out_by_source_bytes(
    tmp_path: Path,
) -> None:
    noisy_dir = tmp_path / "a-noise"
    noisy_dir.mkdir()
    (noisy_dir / "source.py").write_bytes(b"x" * 512)
    parent_path = tmp_path / "packages" / "team" / "package.json"
    parent_path.parent.mkdir(parents=True)
    _write_package(parent_path, "NEAREST")

    policy = ScanPolicy(max_file_bytes=512, max_total_bytes=512)
    inventory = build_inventory(
        tmp_path,
        policy,
        priority_paths={"packages/team/package.json"},
    )
    contents = load_text_files(
        inventory,
        policy=policy,
        priority_paths={"packages/team/package.json"},
    )

    assert "packages/team/package.json" in contents
    assert "a-noise/source.py" not in contents


def test_priority_parent_metadata_is_admitted_before_file_limit(
    tmp_path: Path,
) -> None:
    noisy_dir = tmp_path / "a-noise"
    noisy_dir.mkdir()
    (noisy_dir / "source.py").write_text("value = 1\n", encoding="utf-8")
    parent_path = tmp_path / "packages" / "team" / "package.json"
    parent_path.parent.mkdir(parents=True)
    _write_package(parent_path, "NEAREST")

    policy = ScanPolicy(max_files=1, max_file_bytes=512, max_total_bytes=1024)
    priority_path = "packages/team/package.json"
    inventory = build_inventory(
        tmp_path,
        policy,
        priority_paths={priority_path},
        priority_order=[priority_path],
    )
    contents = load_text_files(inventory, policy=policy)

    assert [record.relative_path for record in inventory.files] == [priority_path]
    assert contents[priority_path]
    assert inventory.discovered_at_least is True
    assert "max_files" in inventory.limit_violations


def test_repository_snapshot_prioritizes_parent_before_file_limit(
    tmp_path: Path,
) -> None:
    noisy_dir = tmp_path / "a-noise"
    noisy_dir.mkdir()
    (noisy_dir / "source.py").write_text("value = 1\n", encoding="utf-8")
    parent_path = tmp_path / "packages" / "team" / "package.json"
    parent_path.parent.mkdir(parents=True)
    _write_package(parent_path, "NEAREST")

    inventory, contents = trust._build_repository_snapshot(
        tmp_path,
        "packages/team/demo",
        policy=ScanPolicy(
            max_files=1,
            max_file_bytes=512,
            max_total_bytes=1024,
        ),
    )

    assert [record.relative_path for record in inventory.files] == [
        "packages/team/package.json"
    ]
    assert json.loads(contents["packages/team/package.json"])["author"] == {
        "name": "NEAREST"
    }


def test_priority_order_preserves_nearest_parent_under_read_budget(
    tmp_path: Path,
) -> None:
    _write_padded_package(tmp_path / "package.json", "ROOT")
    nearest_path = tmp_path / "packages" / "team" / "package.json"
    nearest_path.parent.mkdir(parents=True)
    _write_padded_package(nearest_path, "NEAREST")

    policy = ScanPolicy(max_file_bytes=1024, max_total_bytes=800)
    inventory = build_inventory(tmp_path, policy)
    priority_order = trust._parent_package_json_candidates("packages/team/demo")
    contents = load_text_files(
        inventory,
        policy=policy,
        priority_paths=set(priority_order),
        priority_order=priority_order,
    )

    selected, source = trust._select_parent_package_json(
        "packages/team/demo",
        contents,
    )

    assert source == "packages/team/package.json"
    assert selected == json.loads(contents["packages/team/package.json"])


def test_root_manifest_is_reserved_before_large_source_files(
    tmp_path: Path,
) -> None:
    (tmp_path / "manifest.json").write_text(
        '{"source":{"subdirectory":"packages/team/demo"}}',
        encoding="utf-8",
    )
    noisy_dir = tmp_path / "a-noise"
    noisy_dir.mkdir()
    (noisy_dir / "source.py").write_bytes(b"x" * 512)

    policy = ScanPolicy(max_file_bytes=512, max_total_bytes=512)
    inventory = build_inventory(
        tmp_path,
        policy,
        priority_paths={"manifest.json"},
    )
    contents = load_text_files(
        inventory,
        policy=policy,
        priority_paths={"manifest.json"},
        only_paths={"manifest.json"},
    )

    assert "manifest.json" in contents


def test_root_manifest_reports_excessive_json_nesting() -> None:
    nested_json = (
        '{"source":{},"payload":'
        + "[" * trust._MAX_MANIFEST_JSON_NESTING
        + "0"
        + "]" * trust._MAX_MANIFEST_JSON_NESTING
        + "}"
    )

    with pytest.raises(
        ValueError,
        match="无法扫描：manifest.json 的 JSON 嵌套层级超过支持上限",
    ):
        trust._root_manifest_subdirectory(nested_json)


def test_root_manifest_accepts_supported_json_nesting() -> None:
    nested_json = (
        '{"source":{},"payload":'
        + "[" * (trust._MAX_MANIFEST_JSON_NESTING - 1)
        + "0"
        + "]" * (trust._MAX_MANIFEST_JSON_NESTING - 1)
        + "}"
    )

    assert trust._root_manifest_subdirectory(nested_json) is None


def test_root_manifest_ignores_brackets_inside_strings() -> None:
    manifest = json.dumps(
        {
            "source": {"subdirectory": "packages/team/demo"},
            "description": "[" * 5000,
        }
    )

    assert trust._root_manifest_subdirectory(manifest) == "packages/team/demo"


def test_invalid_priority_paths_are_ignored(tmp_path: Path) -> None:
    (tmp_path / "normal.txt").write_text("ok", encoding="utf-8")

    inventory = build_inventory(
        tmp_path,
        ScanPolicy(max_files=10),
        priority_paths={
            "bad\x00path",
            "C:/outside/package.json",
            "C:outside/package.json",
            "//server/share/package.json",
            r"\\server\share\package.json",
        },
    )

    assert [record.relative_path for record in inventory.files] == ["normal.txt"]


def test_second_metadata_pass_recovers_a_total_budget_skip(
    tmp_path: Path,
) -> None:
    noisy_dir = tmp_path / "a-noise"
    noisy_dir.mkdir()
    (noisy_dir / "source.py").write_bytes(b"x" * 512)
    parent_path = tmp_path / "packages" / "team" / "package.json"
    parent_path.parent.mkdir(parents=True)
    _write_package(parent_path, "NEAREST")

    policy = ScanPolicy(max_file_bytes=512, max_total_bytes=512)
    inventory = build_inventory(tmp_path, policy)
    contents = load_text_files(
        inventory,
        policy=policy,
        priority_paths={"packages/team/package.json"},
    )

    assert "packages/team/package.json" in contents


def test_second_pass_counts_bytes_from_a_decode_failure(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_bytes(b"\xff" * 4)
    (tmp_path / "a.py").write_bytes(b"aaaa")
    (tmp_path / "z.txt").write_bytes(b"zzzz")

    policy = ScanPolicy(max_file_bytes=4, max_total_bytes=8)
    inventory = build_inventory(
        tmp_path,
        policy,
        priority_paths={"manifest.json"},
    )
    first_contents = load_text_files(
        inventory,
        policy=policy,
        priority_paths={"manifest.json"},
        only_paths={"manifest.json"},
    )
    contents = load_text_files(
        inventory,
        policy=policy,
        priority_paths={"z.txt"},
        existing_contents=first_contents,
    )

    assert first_contents == {}
    assert contents == {"z.txt": "zzzz"}
    assert sum(record.bytes_read for record in inventory.files) == 8


@pytest.mark.parametrize(
    "file_contents",
    [
        {"manifest.json": "{}"},
        {
            "SKILL.md": (
                "---\n"
                "name: fallback-demo\n"
                "description: Fallback metadata test\n"
                "---\n"
            )
        },
        {},
    ],
    ids=["manifest", "frontmatter", "stub"],
)
def test_fallback_metadata_inherits_parent_author(
    file_contents: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_extraction(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("forced extractor failure")

    monkeypatch.setitem(
        sys.modules,
        "extract_skills",
        SimpleNamespace(extract_single_skill=fail_extraction),
    )
    metadata = trust._build_package_metadata(
        {"package_name": "fallback-demo", "version": "1.0.0"},
        "unused",
        file_contents=file_contents,
        parent_package_json={
            "author": {"name": "PARENT", "email": "parent@example.com"}
        },
    )

    assert metadata["author"] == {
        "name": "PARENT",
        "email": "parent@example.com",
    }


def test_fallback_metadata_keeps_local_author(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_extraction(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("forced extractor failure")

    monkeypatch.setitem(
        sys.modules,
        "extract_skills",
        SimpleNamespace(extract_single_skill=fail_extraction),
    )
    metadata = trust._build_package_metadata(
        {"package_name": "fallback-demo", "version": "1.0.0"},
        "unused",
        file_contents={"manifest.json": '{"author":{"name":"LOCAL"}}'},
        parent_package_json={"author": {"name": "PARENT"}},
    )

    assert metadata["author"] == {"name": "LOCAL"}


def test_fallback_metadata_prefers_local_package_author(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_extraction(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("forced extractor failure")

    monkeypatch.setitem(
        sys.modules,
        "extract_skills",
        SimpleNamespace(extract_single_skill=fail_extraction),
    )
    metadata = trust._build_package_metadata(
        {"package_name": "fallback-demo", "version": "1.0.0"},
        "unused",
        file_contents={
            "SKILL.md": "---\nname: fallback-demo\n---\n",
            "package.json": '{"author":{"name":"LOCAL"}}',
        },
        parent_package_json={"author": {"name": "PARENT"}},
    )

    assert metadata["author"]["name"] == "LOCAL"


def test_fallback_metadata_ignores_package_json_value_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_extraction(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("forced extractor failure")

    monkeypatch.setitem(
        sys.modules,
        "extract_skills",
        SimpleNamespace(extract_single_skill=fail_extraction),
    )
    metadata = trust._build_package_metadata(
        {"package_name": "fallback-demo", "version": "1.0.0"},
        "unused",
        file_contents={
            "package.json": '{"value": ' + "9" * 5000 + "}",
            "manifest.json": "{}",
        },
        parent_package_json={"author": {"name": "PARENT"}},
    )

    assert metadata["author"]["name"] == "PARENT"


@pytest.mark.parametrize("metadata_path", ["manifest.json", "plugin.json"])
def test_fallback_metadata_ignores_manifest_value_errors(
    metadata_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_extraction(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("forced extractor failure")

    monkeypatch.setitem(
        sys.modules,
        "extract_skills",
        SimpleNamespace(extract_single_skill=fail_extraction),
    )
    metadata = trust._build_package_metadata(
        {"package_name": "fallback-demo", "version": "1.0.0"},
        "unused",
        file_contents={
            metadata_path: '{"value": ' + "9" * 5000 + "}",
            "SKILL.md": "---\nname: fallback-demo\n---\n",
        },
        parent_package_json={"author": {"name": "PARENT"}},
    )

    assert metadata["author"]["name"] == "PARENT"
