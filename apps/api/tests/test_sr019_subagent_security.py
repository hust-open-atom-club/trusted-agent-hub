"""SR-019: Subagent security rule unit tests."""

from scanners.risk_scanner.rules.subagent_security import run
from tests.scanner_mock import MockScanner


class TestSR019SubagentSecurity:

    # ══ Positive: Autonomous mode ════════════════════════

    def test_autonomous_with_high_iterations(self):
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "subagent",
                "subagent_config": {
                    "system_prompt_path": "./prompt.md",
                    "tools": ["Read", "Grep", "Glob"],
                    "interaction_mode": "autonomous",
                    "max_iterations": 80,
                },
            },
        )
        run(s)
        assert len(s.findings) >= 1
        assert s.findings[0]["rule_id"] == "SR-019"
        assert s.findings[0]["severity"] == "high"
        assert "autonomous" in s.findings[0]["title"].lower()

    def test_autonomous_medium(self):
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "subagent",
                "subagent_config": {
                    "system_prompt_path": "./prompt.md",
                    "tools": ["Read", "Grep"],
                    "interaction_mode": "autonomous",
                    "max_iterations": 10,
                },
            },
        )
        run(s)
        autonomous_findings = [f for f in s.findings if "autonomous" in f["title"].lower() and "高" not in f["title"]]
        assert len(autonomous_findings) >= 1
        assert autonomous_findings[0]["severity"] == "medium"

    # ══ Positive: Dangerous tools ═══════════════════════

    def test_dangerous_tool_bash_autonomous(self):
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "subagent",
                "subagent_config": {
                    "system_prompt_path": "./prompt.md",
                    "tools": ["Read", "Bash", "Grep"],
                    "interaction_mode": "autonomous",
                },
            },
        )
        run(s)
        tool_findings = [f for f in s.findings if "工具" in f["title"]]
        assert len(tool_findings) >= 1
        assert tool_findings[0]["severity"] == "high"

    def test_dangerous_tool_write_supervised(self):
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "subagent",
                "subagent_config": {
                    "system_prompt_path": "./prompt.md",
                    "tools": ["Read", "Write"],
                    "interaction_mode": "supervised",
                },
            },
        )
        run(s)
        tool_findings = [f for f in s.findings if "工具" in f["title"]]
        assert len(tool_findings) >= 1
        assert tool_findings[0]["severity"] == "medium"

    def test_dangerous_tools_multiple(self):
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "subagent",
                "subagent_config": {
                    "system_prompt_path": "./prompt.md",
                    "tools": ["Read", "Bash", "shell", "code_execution", "Grep"],
                    "interaction_mode": "supervised",
                },
            },
        )
        run(s)
        tool_findings = [f for f in s.findings if "工具" in f["title"]]
        assert len(tool_findings) >= 1
        assert "Bash" in tool_findings[0]["title"]
        assert "shell" in tool_findings[0]["title"]
        assert "code_execution" in tool_findings[0]["title"]

    # ══ Positive: Global scope ═════════════════════════

    def test_global_scope(self):
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "subagent",
                "subagent_config": {
                    "system_prompt_path": "./prompt.md",
                    "tools": ["Read"],
                    "scope": "global",
                },
            },
        )
        run(s)
        scope_findings = [f for f in s.findings if "global" in f["title"].lower()]
        assert len(scope_findings) >= 1
        assert scope_findings[0]["severity"] == "medium"

    # ══ Positive: System prompt path traversal ══════════

    def test_system_prompt_path_traversal(self):
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "subagent",
                "subagent_config": {
                    "system_prompt_path": "../../etc/malicious-prompt.md",
                    "tools": ["Read"],
                },
            },
        )
        run(s)
        path_findings = [f for f in s.findings if "system_prompt_path" in f["title"].lower()]
        assert len(path_findings) >= 1
        assert path_findings[0]["severity"] == "medium"

    def test_system_prompt_absolute_path(self):
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "subagent",
                "subagent_config": {
                    "system_prompt_path": "/etc/subagent/prompt.md",
                    "tools": ["Read"],
                },
            },
        )
        run(s)
        path_findings = [f for f in s.findings if "system_prompt_path" in f["title"].lower()]
        assert len(path_findings) >= 1

    # ══ Combined scenarios ═════════════════════════════

    def test_fully_risky_subagent(self):
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "subagent",
                "subagent_config": {
                    "system_prompt_path": "../../evil-prompt.md",
                    "tools": ["Bash", "Write", "exec"],
                    "interaction_mode": "autonomous",
                    "max_iterations": 100,
                    "scope": "global",
                },
            },
        )
        run(s)
        assert len(s.findings) >= 4  # autonomous + high_iter, dangerous tools, global scope, path traversal

    # ══ Negative cases ══════════════════════════════════

    def test_safe_supervised_subagent(self):
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "subagent",
                "subagent_config": {
                    "system_prompt_path": "./prompt.md",
                    "tools": ["Read", "Grep", "Glob", "WebFetch"],
                    "interaction_mode": "supervised",
                    "max_iterations": 15,
                    "scope": "project",
                },
            },
        )
        run(s)
        assert len(s.findings) == 0

    def test_safe_no_tools(self):
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "subagent",
                "subagent_config": {
                    "system_prompt_path": "./prompt.md",
                    "tools": [],
                    "interaction_mode": "supervised",
                },
            },
        )
        run(s)
        assert len(s.findings) == 0

    def test_safe_relative_path(self):
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "subagent",
                "subagent_config": {
                    "system_prompt_path": "./prompts/main.md",
                    "tools": ["Read"],
                },
            },
        )
        run(s)
        assert len(s.findings) == 0

    def test_non_subagent_package_skipped(self):
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "mcp_server",
                "subagent_config": {
                    "system_prompt_path": "../../evil.md",
                    "tools": ["Bash"],
                    "interaction_mode": "autonomous",
                },
            },
        )
        run(s)
        assert len(s.findings) == 0

    def test_no_metadata_skipped(self):
        s = MockScanner(
            files={},
            _package_metadata=None,
        )
        run(s)
        assert len(s.findings) == 0

    def test_empty_agent_config(self):
        s = MockScanner(
            files={},
            _package_metadata={
                "type": "subagent",
                "subagent_config": {},
            },
        )
        run(s)
        assert len(s.findings) == 0
