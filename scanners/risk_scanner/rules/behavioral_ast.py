"""SR-005b: Behavioral AST analysis for RCE detection.

Detects code execution patterns that regex cannot catch:
  - import alias evasion (import os as o; o.system())
  - reflective calls (getattr(os, 'system'))
  - dynamic import chains (importlib.import_module(x).system())
  - eval/exec/subprocess through variable indirection
"""

from __future__ import annotations

import ast
import re
from typing import Any

from scanners.risk_scanner.analyzers.python_ast import analyze_python


_DANGEROUS_CALLS: set[str] = {
    "os.system", "os.popen",
    "os.execl", "os.execle", "os.execlp", "os.execlpe",
    "os.execv", "os.execve", "os.execvp", "os.execvpe",
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "subprocess.check_call", "subprocess.check_output",
    "eval", "exec", "compile",
}

_DANGEROUS_MODULES: set[str] = {
    "os", "subprocess", "builtins", "importlib", "pty",
}


def _resolve_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _resolve_name(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    return None


def run(scanner: Any) -> None:
    rule_id = "SR-005"

    # Production scans consume the shared analyzer facts.  The fallback keeps
    # this rule usable with the lightweight MockScanner used by unit tests and
    # downstream integrations.
    analysis = getattr(getattr(scanner, "analysis", None), "python_ast", None)
    if analysis is not None:
        for fname, result in sorted(analysis.items()):
            _report_analysis(scanner, fname, result)
        return

    findings_map: dict[tuple, bool] = {}

    for fname in scanner.scanned_files:
        if not fname.endswith(".py"):
            continue
        content = scanner._read_file_content(fname)
        if not content:
            continue
        try:
            tree = ast.parse(content, filename=fname)
        except SyntaxError:
            continue

        analyser = _ASTAnalyser(rule_id, scanner, fname, content, findings_map)
        analyser.visit(tree)


def _report_analysis(scanner: Any, fname: str, result: Any) -> None:
    """Turn analyzer facts into findings without reparsing source."""
    content = scanner._read_file_content(fname)
    lines = content.split("\n") if content else []
    seen: set[tuple[str, int, str]] = set()
    safe_spawn_lines = _safe_fixed_spawn_lines(content)
    for event in result.calls:
        key = (event.kind, event.line, event.calling)
        if key in seen:
            continue
        seen.add(key)
        snippet = "\n".join(lines[max(0, event.line - 1):event.line])[:200]
        if scanner._is_code_example(fname, event.line):
            continue
        resolved = event.resolved or event.calling
        if resolved.startswith("subprocess.") and event.line in safe_spawn_lines:
            # Fixed argv with shell disabled is a process capability, not RCE.
            continue
        if event.kind == "dynamic_import":
            title = f"动态导入: {event.calling}()"
            description = f"在 {fname} 中发现 importlib.import_module() 动态加载模块"
            evidence = f"Dynamic import: {event.calling}"
        elif event.kind == "reflective":
            title = f"反射调用: {event.calling}() 访问危险模块 {event.resolved or ''}".rstrip()
            description = f"在 {fname} 中发现反射调用 {event.calling}() 可能用于动态访问危险模块"
            evidence = f"Reflective call: {event.calling}"
        else:
            title = f"AST 代码执行检测: {event.calling} 通过别名引用到危险函数 {resolved}"
            description = f"在 {fname} 中发现通过别名/变量间接调用危险函数：{event.calling} -> {resolved}"
            evidence = f"Resolved call: {event.calling}"
        source_semantics = _execution_source_semantics(snippet)
        severity = (
            "high" if source_semantics["kind"] == "vulnerability" else "medium"
        )
        scanner._add_finding(
            rule_id="SR-005",
            severity=severity,
            category="remote_code_execution",
            title=title,
            description=description,
            location={"file": fname, "line": event.line, "snippet": snippet},
            evidence=evidence,
            remediation="避免使用 import 别名隐藏危险调用。显式使用危险函数并使用参数校验和命令白名单。",
            cwe_id="CWE-94",
            **source_semantics,
        )


def _safe_fixed_spawn_lines(content: str) -> set[int]:
    """Return subprocess call lines using constant argv and no shell."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return set()
    safe: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        called = _resolve_name(node.func) or ""
        if called.rsplit(".", 1)[-1] not in {
            "call", "run", "Popen", "check_call", "check_output",
        }:
            continue
        shell_value = next(
            (keyword.value for keyword in node.keywords if keyword.arg == "shell"),
            None,
        )
        if isinstance(shell_value, ast.Constant) and shell_value.value is True:
            continue
        if not node.args:
            continue
        argv = node.args[0]
        if isinstance(argv, (ast.List, ast.Tuple)) and all(
            isinstance(item, ast.Constant) and isinstance(item.value, (str, bytes))
            for item in argv.elts
        ):
            safe.add(int(getattr(node, "lineno", 1)))
    return safe


def _execution_source_semantics(snippet: str) -> dict[str, Any]:
    if re.search(
        r"\b(?:request|req)\s*\.|\buser[_-]?input\b",
        snippet,
        re.IGNORECASE,
    ):
        return {
            "kind": "vulnerability",
            "disposition": "confirmed_vulnerability",
            "sink_kind": "shell_exec",
            "source_kind": "request",
            "source_control": "remote_attacker",
            "reachability": "request_reachable",
            "activation": "direct",
            "trust_boundary_crossed": True,
        }
    return {
        "kind": "context_dependent",
        "disposition": "needs_context",
        "sink_kind": "shell_exec",
        "source_kind": "unknown",
        "source_control": "unknown",
        "reachability": "unknown",
        "activation": "conditional",
        "requires_manual_review": True,
    }


class _ASTAnalyser(ast.NodeVisitor):

    def __init__(self, rule_id: str, scanner: Any, fname: str,
                 content: str, findings_map: dict[tuple, bool]) -> None:
        self.rule_id = rule_id
        self.scanner = scanner
        self.fname = fname
        self.lines = content.split("\n")
        self.findings_map = findings_map
        self._import_alias: dict[str, str] = {}
        self._var_alias: dict[str, str] = {}

    # ── import tracking ──────────────────────────────────────────

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name in _DANGEROUS_MODULES:
                key = alias.asname or alias.name
                self._import_alias[key] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module in _DANGEROUS_MODULES:
            for alias in node.names:
                key = alias.asname or alias.name
                self._import_alias[key] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    # ── variable assignment tracking (simple) ────────────────────

    def visit_Assign(self, node: ast.Assign) -> None:
        rhs_name = _resolve_name(node.value)
        if rhs_name and rhs_name in self._import_alias:
            for target in node.targets:
                tgt_name = _resolve_name(target)
                if tgt_name:
                    self._var_alias[tgt_name] = self._import_alias[rhs_name]
        self.generic_visit(node)

    # ── call detection ───────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:
        called = _resolve_name(node.func)
        resolved = self._resolve_full(called) if called else None
        lineno = getattr(node, "lineno", 1)

        if resolved and self._is_dangerous(resolved):
            self._report(lineno, called or resolved,
                         f"{called} 通过别名引用到危险函数 {resolved}",
                         f"在 {self.fname} 中发现通过别名/变量间接调用危险函数：{called} -> {resolved}")

        if called and (called.endswith(".import_module") or called == "import_module"):
            self._report(lineno, called,
                         f"动态导入: {called}()",
                         f"在 {self.fname} 中发现 importlib.import_module() 动态加载模块")

        if isinstance(node.func, ast.Call):
            inner = _resolve_name(node.func.func)
            if inner in ("getattr", "hasattr"):
                args = node.func.args
                if args:
                    mod_name = _resolve_name(args[0])
                    if mod_name in _DANGEROUS_MODULES:
                        self._report(lineno, inner,
                                     f"反射调用: {inner}() 访问危险模块 {mod_name}",
                                     f"在 {self.fname} 中发现反射调用 getattr() 可能用于动态访问危险模块")
            if inner == "globals":
                self._report(lineno, "globals",
                             "反射调用: globals() 可能用于动态访问危险函数",
                             f"在 {self.fname} 中发现 globals() 反射调用")

        self.generic_visit(node)

    # ── helpers ──────────────────────────────────────────────────

    def _resolve_full(self, name: str) -> str | None:
        if name in self._import_alias:
            return self._import_alias[name]
        parts = name.rsplit(".", 1)
        if len(parts) == 2:
            base, attr = parts
            if base in self._import_alias:
                return f"{self._import_alias[base]}.{attr}"
            if base in self._var_alias:
                return f"{self._var_alias[base]}.{attr}"
        return name if "." in name else None

    def _is_dangerous(self, resolved: str) -> bool:
        if resolved in _DANGEROUS_CALLS:
            return True
        for dc in _DANGEROUS_CALLS:
            func_name = dc.rsplit(".", 1)[-1]
            if resolved.endswith(f".{func_name}"):
                module = dc.rsplit(".", 1)[0]
                if resolved.startswith(module + "."):
                    return True
        return False

    def _report(self, lineno: int, calling: str, title_detail: str, desc: str) -> None:
        key = (self.rule_id, self.fname, calling, lineno)
        if key in self.findings_map:
            return
        self.findings_map[key] = True
        snippet = "\n".join(self.lines[max(0, lineno - 1):lineno])[:200]
        self.scanner._add_finding(
            rule_id=self.rule_id,
            severity="high",
            category="remote_code_execution",
            title=f"AST 代码执行检测: {title_detail}",
            description=desc,
            location={"file": self.fname, "line": lineno, "snippet": snippet},
            evidence=f"Resolved call: {calling}",
            remediation="避免使用 import 别名隐藏危险调用。显式使用危险函数并使用参数校验和命令白名单。",
            cwe_id="CWE-94",
        )
