"""SR-016: Tool misuse rule unit tests."""

import pytest

from scanners.risk_scanner.rules import tool_misuse
from tests.scanner_mock import MockScanner


class TestSR016ToolMisuse:

    def test_tool_name_impersonation(self):
        """tool_name: 'Bash' (YAML/declaration form) → high finding."""
        s = MockScanner(files={
            "config.yaml": 'tool_name: "Bash"\ndescription: "run commands"\n',
        })
        tool_misuse.run(s)
        assert len(s.findings) == 1
        f = s.findings[0]
        assert f["rule_id"] == "SR-016"
        assert f["severity"] == "high"
        assert f["category"] == "tool_misuse"

    def test_zero_width_character(self):
        """Zero-width character → high finding."""
        s = MockScanner(files={"main.py": "hidden = 'a\u200bb'\n"})
        tool_misuse.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "high"

    def test_unicode_escape(self):
        """\\u0061 escape → medium finding."""
        s = MockScanner(files={"main.py": "x = '\\u0061bc'\n"})
        tool_misuse.run(s)
        assert len(s.findings) >= 1
        assert any(f["severity"] == "medium" for f in s.findings)

    def test_tls_verification_disabled(self):
        """verify=False → medium finding."""
        s = MockScanner(files={"main.py": "requests.get(url, verify=False)\n"})
        tool_misuse.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "medium"

    def test_privileged_k8s_workload(self):
        """privileged: true → high finding."""
        s = MockScanner(files={"deploy.yaml": "securityContext:\n  privileged: true\n"})
        tool_misuse.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "high"

    def test_benign_code_no_finding(self):
        """Ordinary code → no findings."""
        s = MockScanner(files={"main.py": "print('hello')\n"})
        tool_misuse.run(s)
        assert s.findings == []

    def test_prose_run_reads_no_finding(self):
        """"run reads it. The user read"（小写动词散文）→ 不再误报。"""
        s = MockScanner(files={
            "SKILL.md": "The run reads it. The user read the output carefully.\n",
        })
        tool_misuse.run(s)
        assert s.findings == []
