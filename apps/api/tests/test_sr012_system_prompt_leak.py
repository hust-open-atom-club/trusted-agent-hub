"""SR-012: System prompt leakage rule unit tests."""

import pytest

from scanners.risk_scanner.rules import system_prompt_leak
from tests.scanner_mock import MockScanner


class TestSR012SystemPromptLeak:

    def test_read_system_prompt(self):
        """Reading 'system prompt' → high findings (may hit multiple patterns)."""
        s = MockScanner(files={
            "main.py": 'content = read("system prompt.txt")\n',
        })
        system_prompt_leak.run(s)
        assert len(s.findings) >= 1
        f = s.findings[0]
        assert f["rule_id"] == "SR-012"
        assert f["severity"] == "high"
        assert f["category"] == "system_prompt_leakage"

    def test_open_file_as_prompt_critical(self):
        """prompt = open(...) → critical finding."""
        s = MockScanner(files={
            "main.py": 'prompt = open("/etc/sysprompt")\n',
        })
        system_prompt_leak.run(s)
        assert len(s.findings) >= 1
        criticals = [f for f in s.findings if f["severity"] == "critical"]
        assert criticals

    def test_send_system_prompt_over_network(self):
        """requests.post(... system prompt ...) → critical finding."""
        s = MockScanner(files={
            "main.py": 'requests.post(url, data="system prompt is secret")\n',
        })
        system_prompt_leak.run(s)
        assert len(s.findings) >= 1
        criticals = [f for f in s.findings if f["severity"] == "critical"]
        assert criticals

    def test_rephrase_instruction(self):
        """rephrase system instruction → high finding."""
        s = MockScanner(files={
            "main.py": 'out = rephrase("system instruction")\n',
        })
        system_prompt_leak.run(s)
        assert len(s.findings) >= 1

    def test_html_css_files_skipped(self):
        """HTML/CSS files are excluded from this rule."""
        s = MockScanner(files={
            "style.css": "body { content: 'system prompt'; }",
        })
        system_prompt_leak.run(s)
        assert s.findings == []

    def test_benign_code_no_finding(self):
        """Ordinary code mentioning prompts without sensitive patterns → no findings."""
        s = MockScanner(files={"main.py": "print('Hello')\n"})
        system_prompt_leak.run(s)
        assert s.findings == []
