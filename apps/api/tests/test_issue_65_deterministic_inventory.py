"""Inventory selection must not depend on filesystem enumeration order."""

from contextlib import contextmanager
import os
from pathlib import Path
import tracemalloc
from types import SimpleNamespace

import pytest

from scanners.risk_scanner.analyzers.source_integrity import (
    capture_source_state,
    verify_source_state,
)
from scanners.risk_scanner.inventory import build_inventory, load_text_files
from scanners.risk_scanner.policy import ScanPolicy
from scanners.risk_scanner.scanner import RiskScanner


@pytest.fixture
def scandir_order(monkeypatch):
    real_scandir = os.scandir
    order = "forward"
    calls = 0

    @contextmanager
    def scandir(path):
        nonlocal calls
        with real_scandir(path) as entries:
            ordered = sorted(entries, key=lambda entry: entry.name)
        calls += 1
        if order == "reverse" or (order == "alternating" and calls % 2):
            ordered.reverse()
        yield iter(ordered)

    def set_order(value):
        nonlocal order, calls
        order, calls = value, 0

    monkeypatch.setattr(os, "scandir", scandir)
    return set_order


def _write(root: Path, relative_path: str, content: bytes = b"pass\n"):
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_file_limit_selects_the_same_paths_in_each_enumeration_order(tmp_path, scandir_order):
    for name in (
        "z.py", "manifest.json", "config.json", "b.py", "README.md", "a.py", "SKILL.md",
    ):
        _write(tmp_path, name)

    inventories = []
    for order in ("forward", "reverse", "alternating"):
        scandir_order(order)
        inventory = build_inventory(tmp_path, ScanPolicy(max_files=4))
        assert [record.relative_path for record in inventory.files] == [
            "SKILL.md", "a.py", "b.py", "manifest.json",
        ]
        assert inventory.discovered_count == inventory.discovered_files == 4
        assert inventory.discovered_at_least
        assert inventory.limit_violations == ["max_files"]
        inventories.append(inventory)
    assert inventories[0] == inventories[1] == inventories[2]


def test_priorities_apply_across_directories_before_truncation(tmp_path, scandir_order):
    for name in (
        "root.py", "README.md", "config.json", "z/manifest.json",
        "z/a.py", "a/SKILL.md", "a/b.py",
    ):
        _write(tmp_path, name)

    for order in ("reverse", "forward", "alternating"):
        scandir_order(order)
        inventory = build_inventory(tmp_path, ScanPolicy(max_files=4))
        assert [record.relative_path for record in inventory.files] == [
            "a/SKILL.md", "a/b.py", "root.py", "z/manifest.json",
        ]


def test_explicit_metadata_order_reserves_slots_before_global_selection(tmp_path, scandir_order):
    for name in ("manifest.json", "a.py", "b.py", "parent/package.json", "LICENSE"):
        _write(tmp_path, name)

    for order in ("forward", "reverse", "alternating"):
        scandir_order(order)
        inventory = build_inventory(
            tmp_path,
            ScanPolicy(max_files=3),
            priority_paths=["LICENSE", "parent/package.json"],
            priority_order=["parent/package.json", "LICENSE"],
        )
        assert [record.relative_path for record in inventory.files] == [
            "LICENSE", "manifest.json", "parent/package.json",
        ]
        assert inventory.discovered_at_least
        single = build_inventory(
            tmp_path,
            ScanPolicy(max_files=1),
            priority_paths=["LICENSE", "parent/package.json"],
            priority_order=["parent/package.json", "LICENSE"],
        )
        assert [record.relative_path for record in single.files] == ["parent/package.json"]


def test_byte_budget_and_skipped_samples_are_stable(tmp_path, scandir_order):
    for name in ("c.py", "a.py", "b.py", "z/child/deep.py", "a/child/deep.py"):
        _write(tmp_path, name, b"pass")

    inventories = []
    for order in ("reverse", "forward", "alternating"):
        scandir_order(order)
        inventory = build_inventory(
            tmp_path,
            ScanPolicy(max_depth=0, max_total_bytes=4, max_skipped_samples=2),
        )
        assert load_text_files(inventory) == {"a.py": "pass"}
        assert inventory.skipped_by_reason == {
            "max_depth_exceeded": 2, "total_budget_exceeded": 2,
        }
        assert inventory.skipped_samples == ["a", "b.py"]
        inventories.append(inventory)
    assert inventories[0] == inventories[1] == inventories[2]


def test_enumeration_changes_do_not_look_like_source_mutation(tmp_path, scandir_order):
    for name in ("a.py", "b.py", "c.py", "d.py"):
        _write(tmp_path, name)
    scandir_order("reverse")
    inventory = build_inventory(tmp_path, ScanPolicy(max_files=2))
    snapshot = capture_source_state(tmp_path, inventory)

    scandir_order("forward")
    assert verify_source_state(tmp_path, snapshot) == [
        {"kind": "source_state_check_limited", "file": "<scan tree>"},
    ]


def test_scan_coverage_metadata_and_hash_are_repeatable(tmp_path, scandir_order):
    _write(
        tmp_path, "SKILL.md",
        b"---\nname: stable\nversion: 1.0.0\ndescription: Stable inventory fixture\n"
        b"author: tester\nlicense: MIT\n---\n# Stable\n",
    )
    for name in ("a.py", "b.py", "c.py", "d.py"):
        _write(tmp_path, name, f"value = {name!r}\n".encode())

    results = []
    for order in ("reverse", "forward", "alternating"):
        scandir_order(order)
        scanner = RiskScanner(tmp_path, policy=ScanPolicy(max_files=3))
        report = scanner.scan()
        assert report["scanner_errors"] == []
        assert "source_added_during_scan" not in report["scan_status"]["reasons"]
        assert report["scan_status"]["state"] == "partial"
        results.append((
            report["scan_status"], report["scan_limits"], report["metadata_validation"],
            scanner.acquisition_facts["integrity"],
        ))
    assert results[0] == results[1] == results[2]


@pytest.mark.parametrize("max_files, count", [(0, 0), (0, 1), (3, 3), (3, 4)])
def test_exact_and_zero_file_limits(tmp_path, scandir_order, max_files, count):
    for index in range(count):
        _write(tmp_path, f"{index}.py")
    for order in ("forward", "reverse"):
        scandir_order(order)
        inventory = build_inventory(tmp_path, ScanPolicy(max_files=max_files))
        assert len(inventory.files) == min(max_files, count)
        assert inventory.discovered_at_least is (count > max_files)
        assert ("max_files" in inventory.limit_violations) is (count > max_files)


def test_large_directory_uses_bounded_memory_and_stats_only_selected_files(tmp_path, monkeypatch):
    count, max_files = 20_000, 5
    for index in range(max_files):
        _write(tmp_path, f"{index:05d}.py")

    @contextmanager
    def scandir(path):
        assert Path(path) == tmp_path
        yield (
            SimpleNamespace(
                name=f"{index:05d}.py", path=str(tmp_path / f"{index:05d}.py"),
                is_symlink=lambda: False, is_dir=lambda **_: False,
            )
            for index in reversed(range(count))
        )

    real_lstat = Path.lstat
    statted = []

    def lstat(path, *args, **kwargs):
        if path.parent == tmp_path:
            statted.append(path.name)
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(os, "scandir", scandir)
    monkeypatch.setattr(Path, "lstat", lstat)
    tracemalloc.start()
    try:
        inventory = build_inventory(tmp_path, ScanPolicy(max_files=max_files))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    expected = [f"{index:05d}.py" for index in range(max_files)]
    assert [record.relative_path for record in inventory.files] == expected
    assert set(statted) == set(expected)
    assert len(statted) <= 3 * max_files
    assert inventory.discovered_at_least
    # Allow for Python's process-wide path-component intern table resizing.
    # Materializing and sorting all 20,000 candidate paths exceeds this bound.
    assert peak < 8 * 1024 * 1024
