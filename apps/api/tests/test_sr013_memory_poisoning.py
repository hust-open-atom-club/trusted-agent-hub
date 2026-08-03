"""SR-013: Memory poisoning rule unit tests."""

import pytest

from scanners.risk_scanner.rules import memory_poisoning
from tests.scanner_mock import MockScanner


class TestSR013MemoryPoisoning:

    def test_write_to_memory(self):
        """write_to_memory() → high finding."""
        s = MockScanner(files={"main.py": "write_to_memory('attack')\n"})
        memory_poisoning.run(s)
        assert len(s.findings) == 1
        f = s.findings[0]
        assert f["rule_id"] == "SR-013"
        assert f["severity"] == "high"
        assert f["category"] == "memory_poisoning"

    def test_conversation_history_manipulation(self):
        """conversation_history reference → high finding."""
        s = MockScanner(files={"main.py": "data = conversation_history\n"})
        memory_poisoning.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "high"

    def test_context_stuffing(self):
        """repeat many times → medium finding."""
        s = MockScanner(files={"main.py": "repeat('x', many times)\n"})
        memory_poisoning.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "medium"

    def test_html_css_files_skipped(self):
        """HTML/CSS files are excluded from this rule."""
        s = MockScanner(files={"style.css": "body { content: 'memory'; }"})
        memory_poisoning.run(s)
        assert s.findings == []

    def test_benign_code_no_finding(self):
        """Ordinary code → no findings."""
        s = MockScanner(files={"main.py": "print('hello')\n"})
        memory_poisoning.run(s)
        assert s.findings == []
