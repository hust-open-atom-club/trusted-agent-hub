"""Python AST facts for rules and capability analysis."""

from __future__ import annotations

import ast

from .models import PythonAstAnalysis, PythonCallEvent


_DANGEROUS_CALLS = {
    "os.system", "os.popen", "os.execl", "os.execle", "os.execlp", "os.execlpe",
    "os.execv", "os.execve", "os.execvp", "os.execvpe", "subprocess.call",
    "subprocess.run", "subprocess.Popen", "subprocess.check_call",
    "subprocess.check_output", "eval", "exec", "compile",
}
_DANGEROUS_MODULES = {"os", "subprocess", "builtins", "importlib", "pty"}


def _resolve_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _resolve_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _is_dangerous(resolved: str) -> bool:
    if resolved in _DANGEROUS_CALLS:
        return True
    for dangerous in _DANGEROUS_CALLS:
        function = dangerous.rsplit(".", 1)[-1]
        module = dangerous.rsplit(".", 1)[0]
        if resolved.endswith(f".{function}") and resolved.startswith(module + "."):
            return True
    return False


class _Visitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.imports: list[str] = []
        self.events: list[PythonCallEvent] = []
        self.import_alias: dict[str, str] = {}
        self.var_alias: dict[str, str] = {}

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(alias.name)
            if alias.name in _DANGEROUS_MODULES:
                self.import_alias[alias.asname or alias.name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        self.imports.append(module)
        if module in _DANGEROUS_MODULES:
            for alias in node.names:
                self.import_alias[alias.asname or alias.name] = f"{module}.{alias.name}"
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        rhs = _resolve_name(node.value)
        if rhs and rhs in self.import_alias:
            for target in node.targets:
                name = _resolve_name(target)
                if name:
                    self.var_alias[name] = self.import_alias[rhs]
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        called = _resolve_name(node.func)
        resolved = self._resolve_full(called) if called else None
        line = int(getattr(node, "lineno", 1))
        if resolved and _is_dangerous(resolved):
            self.events.append(PythonCallEvent(line, called or resolved, resolved, "dangerous"))
        if called and (called.endswith(".import_module") or called == "import_module"):
            self.events.append(PythonCallEvent(line, called, called, "dynamic_import"))
        if isinstance(node.func, ast.Call):
            inner = _resolve_name(node.func.func)
            if inner in {"getattr", "hasattr"} and node.func.args:
                module = _resolve_name(node.func.args[0])
                if module in _DANGEROUS_MODULES:
                    self.events.append(PythonCallEvent(line, inner, module, "reflective"))
            if inner == "globals":
                self.events.append(PythonCallEvent(line, "globals", "globals", "reflective"))
        self.generic_visit(node)

    def _resolve_full(self, name: str) -> str | None:
        if name in self.import_alias:
            return self.import_alias[name]
        parts = name.rsplit(".", 1) if name else []
        if len(parts) == 2:
            base, attr = parts
            if base in self.import_alias:
                return f"{self.import_alias[base]}.{attr}"
            if base in self.var_alias:
                return f"{self.var_alias[base]}.{attr}"
        return name if name and "." in name else None


def analyze_python(path: str, content: str) -> PythonAstAnalysis:
    result = PythonAstAnalysis(path=path)
    try:
        tree = ast.parse(content, filename=path)
    except SyntaxError as exc:
        result.error = f"syntax error at line {getattr(exc, 'lineno', 0) or 0}"
        return result
    visitor = _Visitor()
    visitor.visit(tree)
    result.imports = visitor.imports
    result.calls = list(dict.fromkeys(visitor.events))
    return result
