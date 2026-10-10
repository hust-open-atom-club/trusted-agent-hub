"""Directory links must remain visible without traversing their targets."""

from contextlib import contextmanager
import os
from pathlib import Path

import pytest

from scanners.risk_scanner.inventory import build_inventory, load_text_files
from scanners.risk_scanner.policy import ScanPolicy
from scanners.risk_scanner.scanner import RiskScanner


@pytest.fixture
def directory_links(monkeypatch):
    """Exercise link handling even on hosts without symlink privileges."""
    links: dict[Path, Path | Exception] = {}
    real_scandir = os.scandir
    real_is_symlink = Path.is_symlink
    real_resolve = Path.resolve
    real_open = Path.open

    class LinkEntry:
        def __init__(self, entry):
            self.name = entry.name
            self.path = entry.path

        def is_symlink(self):
            return True

        def is_dir(self, *, follow_symlinks=True):
            return follow_symlinks

        def is_file(self, *, follow_symlinks=True):
            return False

    @contextmanager
    def scandir(path):
        assert not any(Path(path).is_relative_to(link) for link in links)
        with real_scandir(path) as entries:
            yield (
                LinkEntry(entry) if Path(entry.path) in links else entry
                for entry in entries
            )

    def resolve(path, *args, **kwargs):
        target = links.get(path)
        if isinstance(target, Exception):
            raise target
        return target if target is not None else real_resolve(path, *args, **kwargs)

    def open_file(path, *args, **kwargs):
        assert not any(path.is_relative_to(link) for link in links)
        return real_open(path, *args, **kwargs)

    def create(link: Path, target: Path | Exception):
        link.mkdir(parents=True)
        links[link] = target

    monkeypatch.setattr(os, "scandir", scandir)
    monkeypatch.setattr(Path, "is_symlink", lambda path: path in links or real_is_symlink(path))
    monkeypatch.setattr(Path, "resolve", resolve)
    monkeypatch.setattr(Path, "open", open_file)
    return create


def _write_skill(root: Path):
    root.mkdir()
    (root / "SKILL.md").write_text(
        "---\nname: link-demo\nversion: 1.0.0\ntype: skill\n"
        "description: Directory link fixture\nauthor: tester\nlicense: MIT\n"
        "---\n# Demo\n",
        encoding="utf-8",
    )


def _assert_link_report(root: Path, reason: str):
    scanner = RiskScanner(root, source_commit_hash="a" * 40)
    report = scanner.scan()

    records = {record.relative_path: record for record in scanner.inventory.files}
    assert "linked" in records
    link = records["linked"]
    assert link.is_symlink
    assert link.read_status == "skipped"
    assert link.skip_reason == reason
    assert link.size_bytes == link.bytes_read == 0
    assert not any(path == "linked" or path.startswith("linked/") for path in scanner._file_contents)
    assert not any(path.startswith("linked/") for path in records)
    assert report["scan_limits"]["skipped"]["by_reason"][reason] == 1
    assert "linked" in report["scan_limits"]["skipped"]["samples"]
    assert reason in report["scan_limits"]["exceeded"]
    assert reason in report["scan_status"]["reasons"]
    assert report["scan_status"]["state"] == "partial"
    assert report["scan_status"]["conclusion"] == "inconclusive"
    assert report["scan_status"]["complete"] is False
    assert scanner.acquisition_facts["integrity"]["is_complete"] is False
    assert report["scanner_errors"] == []
    assert "source_changed_during_scan" not in report["scan_status"]["reasons"]

    link_findings = [
        finding for finding in report["findings"]
        if finding["rule_id"] == "SR-009"
        and finding.get("location", {}).get("file") == "linked"
    ]
    if reason == "symlink":
        assert link_findings == []
    else:
        assert any(reason in finding["title"] for finding in link_findings)
        if reason == "symlink_outside_root":
            assert any(finding["severity"] == "high" for finding in link_findings)


@pytest.mark.parametrize("target_kind", ["inside", "outside", "root"])
@pytest.mark.parametrize("backend", ["simulated", "native"])
def test_directory_symlinks_are_reported_without_following(
    tmp_path, request, target_kind, backend,
):
    root = tmp_path / "package"
    _write_skill(root)
    target = {
        "inside": root / "original",
        "outside": tmp_path / "package-sibling",
        "root": root,
    }[target_kind]
    target.mkdir(exist_ok=True)
    (target / "payload.py").write_text("print('target content')\n", encoding="utf-8")
    link = root / "linked"
    if backend == "simulated":
        request.getfixturevalue("directory_links")(link, target)
    else:
        try:
            # A relative target also verifies that resolution is based on the
            # link's parent directory, not the process working directory.
            link.symlink_to(os.path.relpath(target, root), target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            pytest.skip(f"symlink creation is unavailable: {exc}")

    reason = "symlink_outside_root" if target_kind == "outside" else "symlink"
    _assert_link_report(root, reason)


@pytest.mark.parametrize("target_kind", ["inside", "outside", "root"])
def test_relative_scan_root_classifies_directory_links(
    tmp_path, monkeypatch, directory_links, target_kind,
):
    monkeypatch.chdir(tmp_path)
    root = Path("package")
    root.mkdir()
    target = {
        "inside": tmp_path / "package" / "original",
        "outside": tmp_path / "package-sibling",
        "root": tmp_path / "package",
    }[target_kind]
    target.mkdir(exist_ok=True)
    directory_links(root / "linked", target)

    inventory = build_inventory(root, ScanPolicy())

    reason = "symlink_outside_root" if target_kind == "outside" else "symlink"
    assert [record.relative_path for record in inventory.files] == ["linked"]
    assert inventory.files[0].skip_reason == reason
    assert inventory.skipped_by_reason == {reason: 1}
    assert inventory.limit_violations == [reason]
    assert load_text_files(inventory) == {}


@pytest.mark.parametrize("priority_mode", ["exact", "case_insensitive"])
def test_priority_directory_links_are_recorded_once(tmp_path, directory_links, priority_mode):
    root = tmp_path / "package"
    root.mkdir()
    link = root / "LiCeNsE"
    directory_links(link, tmp_path)
    (root / "main.py").write_bytes(b"pass\n")
    options = (
        {"priority_paths": [link.name]}
        if priority_mode == "exact"
        else {"case_insensitive_priority_paths": ["LICENSE"]}
    )

    limited = build_inventory(root, ScanPolicy(max_files=1), **options)
    assert [record.relative_path for record in limited.files] == [link.name]
    assert limited.discovered_at_least
    assert limited.skipped_by_reason == {"symlink_outside_root": 1}
    assert "max_files" in limited.limit_violations
    assert load_text_files(limited) == {}

    full = build_inventory(root, ScanPolicy(), **options)
    assert [record.relative_path for record in full.files] == [link.name, "main.py"]
    assert full.skipped_by_reason == {"symlink_outside_root": 1}
    assert load_text_files(full) == {"main.py": "pass\n"}


def test_directory_link_at_depth_limit_is_recorded(tmp_path, directory_links):
    directory_links(tmp_path / "nested" / "linked", tmp_path.parent)

    inventory = build_inventory(tmp_path, ScanPolicy(max_depth=1))

    assert [record.relative_path for record in inventory.files] == ["nested/linked"]
    assert inventory.skipped_samples == ["nested/linked"]
    assert inventory.limit_violations == ["symlink_outside_root"]


@pytest.mark.parametrize("max_files", [0, 2])
def test_directory_links_respect_file_and_sample_limits(tmp_path, directory_links, max_files):
    for index in range(4):
        directory_links(tmp_path / f"linked-{index}", tmp_path.parent)

    inventory = build_inventory(tmp_path, ScanPolicy(max_files=max_files, max_skipped_samples=1))

    assert len(inventory.files) == inventory.discovered_count == max_files
    assert inventory.discovered_at_least
    assert "max_files" in inventory.limit_violations
    assert sum(inventory.skipped_by_reason.values()) == max_files
    assert len(inventory.skipped_samples) == min(max_files, 1)
    assert inventory.discovered_bytes == 0
    assert load_text_files(inventory) == {}


@pytest.mark.parametrize("error_type", [OSError, RuntimeError])
def test_unresolvable_directory_links_are_partial_without_crashing(
    tmp_path, directory_links, error_type,
):
    root = tmp_path / "package"
    _write_skill(root)
    directory_links(root / "linked", error_type("cannot resolve directory link"))

    _assert_link_report(root, "symlink_unreadable")
