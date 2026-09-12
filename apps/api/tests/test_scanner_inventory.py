from pathlib import Path

from scanners.risk_scanner.policy import ScanPolicy
from scanners.risk_scanner.inventory import build_inventory, load_text_files
from scanners.risk_scanner.scanner import RiskScanner


def _write(root: Path, name: str, data: str | bytes) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data, encoding="utf-8")


def test_binary_is_in_inventory_and_structure_finding(tmp_path):
    _write(tmp_path, "SKILL.md", "---\nname: demo\n---\n")
    _write(tmp_path, "payload.exe", b"MZ\x00\x01")
    _write(tmp_path, "payload.pyd", b"native extension payload")
    scanner = RiskScanner(tmp_path)
    report = scanner.scan()
    assert "payload.exe" in report["scan_limits"]["skipped"]["samples"]
    assert "payload.pyd" in report["scan_limits"]["skipped"]["samples"]
    assert any(f.get("location", {}).get("file") == "payload.exe" for f in report["findings"])
    assert any(f.get("location", {}).get("file") == "payload.pyd" for f in report["findings"])


def test_untrusted_python_artifacts_remain_in_inventory_and_hash(tmp_path):
    clean_root = tmp_path / "clean"
    cache_root = tmp_path / "cache"
    untrusted_root = tmp_path / "untrusted"
    for root in (clean_root, cache_root, untrusted_root):
        _write(root, "SKILL.md", "---\nname: demo\nversion: 1.0.0\ndescription: clean fixture\nauthor: tester\nlicense: MIT\n---\n")
        _write(root, "module.py", "value = 1\n")
    _write(cache_root, "__pycache__/module.cpython-311.pyc", b"\x00\x01compiled")
    _write(untrusted_root, "__pycache__/module.cpython-311.pyc", b"\x00\x01compiled")
    _write(untrusted_root, "__pycache__/orphan.pyc", b"\x00\x02compiled")
    _write(untrusted_root, "stray.pyc", b"\x00\x03compiled")
    _write(untrusted_root, "legacy.pyo", b"\x00\x04compiled")

    inventory = build_inventory(untrusted_root, ScanPolicy())
    paths = {record.relative_path for record in inventory.files}
    assert paths == {
        "SKILL.md",
        "module.py",
        "__pycache__/module.cpython-311.pyc",
        "__pycache__/orphan.pyc",
        "stray.pyc",
        "legacy.pyo",
    }

    clean_scanner = RiskScanner(clean_root)
    cache_scanner = RiskScanner(cache_root)
    untrusted_scanner = RiskScanner(untrusted_root)
    assert cache_scanner._content_tree_sha256() != clean_scanner._content_tree_sha256()
    assert untrusted_scanner._content_tree_sha256() != clean_scanner._content_tree_sha256()
    cache_report = cache_scanner.scan()
    assert any(
        finding.get("location", {}).get("file") == "__pycache__/module.cpython-311.pyc"
        for finding in cache_report["findings"]
    )
    report = untrusted_scanner.scan()
    assert report["scan_status"]["state"] == "complete"
    assert any(
        finding.get("location", {}).get("file") == "__pycache__/module.cpython-311.pyc"
        for finding in report["findings"]
    )
    assert any(
        finding.get("location", {}).get("file") == "__pycache__/orphan.pyc"
        for finding in report["findings"]
    )
    assert any(finding.get("location", {}).get("file") == "stray.pyc" for finding in report["findings"])
    assert any(finding.get("location", {}).get("file") == "legacy.pyo" for finding in report["findings"])


def test_limits_make_scan_partial_and_inconclusive(tmp_path):
    _write(tmp_path, "SKILL.md", "---\nname: demo\nversion: 1\ndescription: enough description\nauthor: me\nlicense: MIT\n---\n")
    _write(tmp_path, "README.md", "x" * 100)
    report = RiskScanner(tmp_path, policy=ScanPolicy(max_file_bytes=10)).scan()
    assert report["scan_status"]["state"] == "partial"
    assert report["scan_status"]["conclusion"] == "inconclusive"
    assert "max_file_bytes" in report["scan_limits"]["exceeded"]


def test_cache_miss_does_not_read_from_disk(tmp_path):
    _write(tmp_path, "SKILL.md", "# skill")
    scanner = RiskScanner(tmp_path)
    scanner._inventory = scanner.inventory
    scanner._file_contents = {}
    assert scanner._read_file_content("SKILL.md") == ""


def test_inventory_order_and_manifest_priority(tmp_path):
    _write(tmp_path, "README.md", "readme")
    _write(tmp_path, "manifest.json", '{"name":"manifest"}')
    _write(tmp_path, "z.py", "pass")
    _write(tmp_path, "a.py", "pass")
    scanner = RiskScanner(tmp_path)
    scanner.scan()
    assert scanner.discovered_files == sorted(scanner.discovered_files)
    assert scanner._package_metadata["name"] == "manifest"


def test_max_files_equal_to_limit_is_complete(tmp_path):
    for index in range(3):
        _write(tmp_path, f"file-{index}.py", "value = 1\n")

    inventory = build_inventory(tmp_path, ScanPolicy(max_files=3))

    assert len(inventory.files) == 3
    assert inventory.discovered_count == 3
    assert inventory.discovered_at_least is False
    assert "max_files" not in inventory.limit_violations

    report = RiskScanner(tmp_path, policy=ScanPolicy(max_files=3)).scan()
    assert report["scan_status"]["state"] == "complete"


def test_max_files_stops_discovery_and_reports_lower_bound(tmp_path):
    for index in range(4):
        _write(tmp_path, f"file-{index}.py", "value = 1\n")

    inventory = build_inventory(tmp_path, ScanPolicy(max_files=3))

    assert len(inventory.files) == 3
    assert inventory.discovered_count == 3
    assert inventory.discovered_at_least is True
    assert "max_files" in inventory.limit_violations


def test_max_depth_prunes_directories_before_walk_descends(tmp_path):
    _write(tmp_path, "a/b/c/deep.py", "value = 1\n")

    inventory = build_inventory(tmp_path, ScanPolicy(max_depth=2))

    assert inventory.files == []
    assert "max_depth" in inventory.limit_violations
    assert "a/b/c" in (inventory.skipped_samples or [])


def test_text_loading_is_bounded_when_file_grows_after_inventory(tmp_path):
    path = tmp_path / "growing.py"
    _write(tmp_path, "growing.py", "12345")
    policy = ScanPolicy(max_file_bytes=10, max_total_bytes=10)
    inventory = build_inventory(tmp_path, policy)
    path.write_text("123456789012345", encoding="utf-8")

    contents = load_text_files(inventory, policy=policy)
    record = inventory.files[0]

    assert contents["growing.py"] == "1234567890"
    assert record.bytes_read == 10
    assert record.changed_during_scan is True
    assert record.content_truncated is True
    assert {"source_changed_during_scan", "content_truncated"} <= set(
        inventory.skipped_by_reason or {}
    )


def test_text_loading_records_decode_failures_and_budget_exhaustion(tmp_path):
    decode_root = tmp_path / "decode"
    _write(decode_root, "bad.py", b"valid\xff")
    decode_policy = ScanPolicy(max_file_bytes=10, max_total_bytes=10)
    decode_inventory = build_inventory(decode_root, decode_policy)
    load_text_files(decode_inventory, policy=decode_policy)

    budget_root = tmp_path / "budget"
    _write(budget_root, "a.py", b"1")
    _write(budget_root, "b.py", b"")
    budget_policy = ScanPolicy(max_file_bytes=10, max_total_bytes=1)
    budget_inventory = build_inventory(budget_root, budget_policy)
    load_text_files(budget_inventory, policy=budget_policy)

    assert (decode_inventory.skipped_by_reason or {}).get("decode_error") == 1
    assert (budget_inventory.skipped_by_reason or {}).get("read_budget_exhausted") == 1
