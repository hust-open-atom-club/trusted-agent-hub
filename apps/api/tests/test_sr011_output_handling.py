"""SR-011: Output handling risk rule unit tests."""

import pytest

from scanners.risk_scanner.rules import output_handling
from tests.scanner_mock import MockScanner


class TestSR011OutputHandling:

    def test_print_sensitive_variable(self):
        """print(token) → high finding."""
        s = MockScanner(files={"main.py": "print(token)\n"})
        output_handling.run(s)
        assert len(s.findings) == 1
        f = s.findings[0]
        assert f["rule_id"] == "SR-011"
        assert f["severity"] == "high"
        assert f["category"] == "output_handling"

    def test_user_input_in_shell_command(self):
        """os.system("cmd " + user_input) → medium finding."""
        s = MockScanner(files={
            "main.py": 'import os\nos.system("ls " + user_input)\n',
        })
        output_handling.run(s)
        assert len(s.findings) >= 1
        assert s.findings[0]["severity"] == "medium"

    def test_unbounded_output_loop(self):
        """while True: print(...) → low finding."""
        s = MockScanner(files={"main.py": "while True: print(x)\n"})
        output_handling.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "low"

    def test_benign_code_no_finding(self):
        """Ordinary print/output → no findings."""
        s = MockScanner(files={"main.py": "print('hello world')\nresult = add(a, b)\n"})
        output_handling.run(s)
        assert s.findings == []

    def test_code_example_downgrade(self):
        """Sensitive print inside a code example → downgraded severity."""
        s = MockScanner(
            files={"README.md": "Example: ```python\nprint(token)\n```\n"},
            code_example_predicate=lambda f, ln: True,
        )
        output_handling.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["severity"] == "medium"

    def test_prose_save_above_no_finding(self):
        """"save themes for reuse" + 隔句 above（散文）→ 不再误报。"""
        s = MockScanner(files={
            "SKILL.md": "Use this to save themes for reuse. "
                        "The skill does not write above the fold.\n",
        })
        output_handling.run(s)
        assert s.findings == []
