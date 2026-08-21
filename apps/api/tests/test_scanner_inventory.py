from pathlib import Path

from scanners.risk_scanner.policy import ScanPolicy
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
    scanner = RiskScanner(tmp_path)
    report = scanner.scan()
    assert "payload.exe" in report["scan_limits"]["skipped"]["samples"]
    assert any(f.get("location", {}).get("file") == "payload.exe" for f in report["findings"])


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
