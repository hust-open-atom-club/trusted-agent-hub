"""SR-005b: Behavioral AST analysis rule unit tests."""

import pytest

from scanners.risk_scanner.rules import behavioral_ast
from tests.scanner_mock import MockScanner


class TestSR005bBehavioralAST:

    def test_import_alias_evasion(self):
        """import os as o; o.system() → finding (high)."""
        s = MockScanner(files={
            "main.py": 'import os as o\no.system("ls -la")\n',
        })
        behavioral_ast.run(s)
        assert len(s.findings) == 1
        f = s.findings[0]
        assert f["rule_id"] == "SR-005"
        assert f["severity"] == "high"
        assert f["category"] == "remote_code_execution"
        assert "别名" in f["title"]

    def test_variable_indirection(self):
        """import os; cmd = os; cmd.system() → finding (variable alias)."""
        s = MockScanner(files={
            "main.py": "import os\ncmd = os\ncmd.system('whoami')\n",
        })
        behavioral_ast.run(s)
        assert len(s.findings) == 1
        assert s.findings[0]["rule_id"] == "SR-005"
        assert "cmd.system" in s.findings[0]["title"]

    def test_reflective_getattr_call(self):
        """getattr(os, 'system')() → finding (reflective call)."""
        s = MockScanner(files={
            "main.py": 'import os\nf = getattr(os, "system")("whoami")\n',
        })
        behavioral_ast.run(s)
        assert len(s.findings) == 1
        assert "反射调用" in s.findings[0]["title"]

    def test_dynamic_import_module(self):
        """importlib.import_module() → finding (dynamic import chain)."""
        s = MockScanner(files={
            "main.py": "import importlib\nm = importlib.import_module('os')\n",
        })
        behavioral_ast.run(s)
        assert len(s.findings) == 1
        assert "动态导入" in s.findings[0]["title"]

    def test_benign_code_no_finding(self):
        """Ordinary code with no dangerous calls → no findings."""
        s = MockScanner(files={
            "main.py": 'import json\nimport math\ndata = json.dumps({"a": 1})\nx = math.sqrt(4)\nprint(data, x)\n',
        })
        behavioral_ast.run(s)
        assert s.findings == []

    def test_syntax_error_file_skipped(self):
        """Files with syntax errors are skipped, not crashed."""
        s = MockScanner(files={
            "bad.py": "def broken(:\n    pass\n",
        })
        behavioral_ast.run(s)
        assert s.findings == []
