"""SR-015: Agent snooping rule unit tests."""

import pytest

from scanners.risk_scanner.rules import agent_snooping
from tests.scanner_mock import MockScanner


class TestSR015AgentSnooping:

    def test_read_claude_config(self):
        """Reading .claude directory → high findings (may hit multiple patterns)."""
        s = MockScanner(files={
            "main.py": 'os.listdir("/home/user/.claude")\n',
        })
        agent_snooping.run(s)
        assert len(s.findings) >= 1
        f = s.findings[0]
        assert f["rule_id"] == "SR-015"
        assert f["severity"] == "high"
        assert f["category"] == "agent_snooping"

    def test_read_mcp_config(self):
        """open('mcp.json') → high finding."""
        s = MockScanner(files={
            "main.py": 'cfg = open("mcp.json")\n',
        })
        agent_snooping.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "high"

    def test_conversation_history_read(self):
        """Reading conversation history → high findings (may hit multiple patterns)."""
        s = MockScanner(files={
            "main.py": 'data = read("conversation history")\n',
        })
        agent_snooping.run(s)
        assert len(s.findings) >= 1
        assert s.findings[0]["severity"] == "high"

    def test_html_css_files_skipped(self):
        """HTML/CSS files are excluded from this rule."""
        s = MockScanner(files={"style.css": "body { content: '.claude'; }"})
        agent_snooping.run(s)
        assert s.findings == []

    def test_benign_code_no_finding(self):
        """Ordinary filesystem access inside own directory → no findings."""
        s = MockScanner(files={
            "main.py": 'data = open("notes.md")\nprint(data)\n',
        })
        agent_snooping.run(s)
        assert s.findings == []

    def test_conversation_reference_prose_no_finding(self):
        """"earlier in this conversation"（引用当前对话）→ 不报。"""
        s = MockScanner(files={
            "SKILL.md": "A study diagnosis was emitted earlier in this "
                        "conversation and the user is asking to build from it.\n",
        })
        agent_snooping.run(s)
        assert s.findings == []
