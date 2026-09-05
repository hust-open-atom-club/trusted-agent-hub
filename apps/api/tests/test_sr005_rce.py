"""SR-005: Remote Code Execution rule unit tests (regex + AST layers)."""

from types import SimpleNamespace

from scanners.risk_scanner.analyzers.javascript_ast import analyze_javascript
from scanners.risk_scanner.rules.rce import run as run_rce
from scanners.risk_scanner.rules.behavioral_ast import run as run_ast
from tests.scanner_mock import MockScanner


class TestSR005RCE:

    # ── Positive cases (regex layer) ──────────────────────

    def test_eval(self):
        """eval() with user input should be detected."""
        s = MockScanner(files={
            "danger.py": 'eval(request.args.get("cmd"))',
        })
        run_rce(s)
        assert len(s.findings) >= 1
        assert s.findings[0]["rule_id"] == "SR-005"
        assert s.findings[0]["category"] == "remote_code_execution"

    def test_exec(self):
        """exec() should be detected."""
        s = MockScanner(files={
            "run.py": 'exec(user_input)',
        })
        run_rce(s)
        assert len(s.findings) >= 1

    def test_os_system(self):
        """os.system() should be detected."""
        s = MockScanner(files={
            "syscall.py": 'os.system("rm -rf " + path)',
        })
        run_rce(s)
        assert len(s.findings) >= 1

    def test_subprocess_shell_true(self):
        """subprocess with shell=True should be detected."""
        s = MockScanner(files={
            "proc.py": 'subprocess.run(cmd, shell=True)',
        })
        run_rce(s)
        assert len(s.findings) >= 1

    def test_child_process_exec_uses_matching_structured_call(self):
        content = "cp.exec('fixed'); cp.exec(userInput);\n"
        s = MockScanner(files={"script.js": content})
        s.analysis = SimpleNamespace(
            javascript_ast={"script.js": analyze_javascript("script.js", content)}
        )

        run_rce(s)

        assert [finding["severity"] for finding in s.findings] == ["critical"]
        assert s.findings[0]["kind"] == "vulnerability"
        assert s.findings[0]["disposition"] == "confirmed_vulnerability"
        assert s.findings[0]["source_control"] == "remote_attacker"

    def test_operator_environment_exec_requires_context(self):
        content = (
            'const childProcess = require("child_process");\n'
            "childProcess.exec(process.env.OPERATOR_COMMAND);\n"
        )
        s = MockScanner(files={"hook.js": content})
        s.analysis = SimpleNamespace(
            javascript_ast={"hook.js": analyze_javascript("hook.js", content)}
        )

        run_rce(s)

        assert len(s.findings) == 1
        finding = s.findings[0]
        assert finding["severity"] == "medium"
        assert finding["kind"] == "context_dependent"
        assert finding["disposition"] == "needs_context"
        assert finding["source_control"] == "operator"
        assert finding["requires_manual_review"] is True

    def test_exec_file_with_fixed_binary_is_capability_only(self):
        content = (
            'const childProcess = require("child_process");\n'
            'childProcess.execFile("xdg-open", [url], { shell: false });\n'
        )
        s = MockScanner(files={"launcher.js": content})
        s.analysis = SimpleNamespace(
            javascript_ast={"launcher.js": analyze_javascript("launcher.js", content)}
        )

        run_rce(s)

        assert s.findings == []

    def test_getattr_reflection(self):
        """Dynamic attribute access to dangerous modules (AST layer)."""
        s = MockScanner(files={
            "reflect.py": (
                'import os\n'
                'getattr(os, "system")("echo hello")'
            ),
        })
        run_ast(s)
        assert len(s.findings) >= 1
        assert s.findings[0]["rule_id"] == "SR-005"

    # ── Negative cases (regex layer) ──────────────────────

    def test_literal_eval(self):
        """ast.literal_eval() is safe and should NOT be detected."""
        s = MockScanner(files={
            "safe.py": 'ast.literal_eval(\'{"key": "value"}\')',
        })
        run_rce(s)
        assert len(s.findings) == 0

    def test_subprocess_without_shell(self):
        """subprocess.run() without shell=True should NOT be detected."""
        s = MockScanner(files={
            "safe_proc.py": 'subprocess.run(["ls", "-la"])',
        })
        run_rce(s)
        assert len(s.findings) == 0

    def test_dsl_eval_mention(self):
        """Mentioning eval in a DSL context should NOT be detected."""
        s = MockScanner(files={
            "example.json": '{"name": "expression-eval", "type": "dsl"}',
        })
        run_rce(s)
        assert len(s.findings) == 0

    def test_regex_exec_method_is_not_dynamic_execution(self):
        """RegExp.exec() 是普通正则 API，不应命中 Python exec 内建函数规则。"""
        s = MockScanner(files={"render-graphs.js": "regex.exec(markdown)\n"})
        run_rce(s)
        assert s.findings == []

    # ── AST should not process non-Python ─────────────────

    def test_ast_skips_non_python(self):
        """AST rule should skip non-Python files."""
        s = MockScanner(files={
            "script.js": 'eval("console.log(1)")',
            "template.txt": 'os.system("ls")',
        })
        run_ast(s)
        assert len(s.findings) == 0
