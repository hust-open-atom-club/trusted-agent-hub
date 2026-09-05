"""Deterministic scope analysis for permission-sensitive code operations."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import PurePosixPath


@dataclass(frozen=True)
class DeleteOperation:
    file: str
    line: int
    sink: str
    target: str
    recursive: bool
    scope: str
    source_control: str


_PYTHON_DELETE_CALLS = {
    "shutil.rmtree": True,
    "os.remove": False,
    "os.unlink": False,
    "os.rmdir": False,
}
_JAVASCRIPT_DELETE = re.compile(
    r"\bfs\.(rm|rmSync|rmdir|rmdirSync|unlink|unlinkSync)\s*\(\s*([^,\n)]+)",
    re.IGNORECASE,
)
_SHELL_DELETE = re.compile(
    r"\brm\s+(-[A-Za-z]*[rf][A-Za-z]*)\s+([^;&|\n]+)",
    re.IGNORECASE,
)
_REQUEST_SOURCE = re.compile(
    r"\b(?:request|req)\s*(?:\.|\[)|\b(?:query|body|params?)\s*(?:\.|\[)",
    re.IGNORECASE,
)
_OPERATOR_SOURCE = re.compile(
    r"\b(?:process\.argv|sys\.argv|input\s*\(|argparse|commander\.|yargs\.)",
    re.IGNORECASE,
)
_OWN_STATE_SOURCE = re.compile(
    r"(?:\b__file__\b|\b__dirname\b|import\.meta\.url|"
    r"\.session-state\b|(?:^|[/\\])\.cache(?:[/\\]|$)|"
    r"(?:^|[/\\])\.tmp(?:[/\\]|$))",
    re.IGNORECASE,
)


def _python_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _python_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _contains_name(node: ast.AST, name: str) -> bool:
    return any(isinstance(item, ast.Name) and item.id == name for item in ast.walk(node))


def _python_target(
    node: ast.AST,
    assignments: dict[str, ast.AST],
    *,
    seen: frozenset[str] = frozenset(),
) -> tuple[str, str, str]:
    """Return target text, scope, and source controller for a Python value."""
    try:
        text = ast.unparse(node)
    except (AttributeError, ValueError):
        text = ""
    if _REQUEST_SOURCE.search(text):
        return text, "unbounded", "remote_attacker"
    if _OPERATOR_SOURCE.search(text):
        return text, "unbounded", "operator"
    if _OWN_STATE_SOURCE.search(text):
        return text, "package_owned", "package"
    if isinstance(node, ast.Name) and node.id in assignments and node.id not in seen:
        return _python_target(
            assignments[node.id], assignments, seen=seen | {node.id}
        )
    for name, value in assignments.items():
        if name not in seen and _contains_name(node, name):
            target, scope, controller = _python_target(
                value, assignments, seen=seen | {name}
            )
            if scope != "unknown":
                return target or text, scope, controller
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        value = node.value.replace("\\", "/")
        path = PurePosixPath(value)
        if not path.is_absolute() and ".." not in path.parts:
            return text, "package_owned", "package"
        return text, "external_fixed", "package"
    return text, "unknown", "unknown"


def _python_delete_operations(path: str, content: str) -> list[DeleteOperation]:
    try:
        tree = ast.parse(content, filename=path)
    except SyntaxError:
        return []
    assignments: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = value

    operations: list[DeleteOperation] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        called = _python_name(node.func)
        recursive = _PYTHON_DELETE_CALLS.get(called)
        target_node: ast.AST | None = node.args[0] if node.args else None
        if recursive is None and isinstance(node.func, ast.Attribute):
            if node.func.attr not in {"unlink", "rmdir"}:
                continue
            recursive = False
            target_node = node.func.value
            called = node.func.attr
        if recursive is None or target_node is None:
            continue
        target, scope, controller = _python_target(target_node, assignments)
        operations.append(DeleteOperation(
            path,
            int(getattr(node, "lineno", 1)),
            called,
            target,
            recursive,
            scope,
            controller,
        ))
    return operations


def _text_target(value: str) -> tuple[str, str]:
    if _REQUEST_SOURCE.search(value):
        return "unbounded", "remote_attacker"
    if _OPERATOR_SOURCE.search(value) or re.search(r"\$(?:\d+\b|[@*])", value):
        return "unbounded", "operator"
    if _OWN_STATE_SOURCE.search(value):
        return "package_owned", "package"
    literal = re.match(r"[\"']([^\"']+)[\"']", value.strip())
    if literal:
        path = PurePosixPath(literal.group(1).replace("\\", "/"))
        if not path.is_absolute() and ".." not in path.parts:
            return "package_owned", "package"
        return "external_fixed", "package"
    return "unknown", "unknown"


def _text_delete_operations(path: str, content: str) -> list[DeleteOperation]:
    operations: list[DeleteOperation] = []
    assignments = {
        match.group(1): match.group(2).strip()
        for match in re.finditer(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)",
            content,
        )
    }

    def classify(target: str) -> tuple[str, str]:
        scope, controller = _text_target(target)
        name = target.strip()
        if scope == "unknown" and name in assignments:
            return _text_target(assignments[name])
        return scope, controller

    for match in _JAVASCRIPT_DELETE.finditer(content):
        target = match.group(2).strip()
        line_text = content.splitlines()[content.count("\n", 0, match.start())]
        scope, controller = classify(target)
        operations.append(DeleteOperation(
            path,
            content.count("\n", 0, match.start()) + 1,
            f"fs.{match.group(1)}",
            target,
            bool(re.search(r"recursive\s*:\s*true", line_text, re.I)),
            scope,
            controller,
        ))
    for match in _SHELL_DELETE.finditer(content):
        target = match.group(2).strip()
        scope, controller = classify(target)
        operations.append(DeleteOperation(
            path,
            content.count("\n", 0, match.start()) + 1,
            "rm",
            target,
            "r" in match.group(1).lower(),
            scope,
            controller,
        ))
    return operations


def analyze_delete_operations(path: str, content: str) -> list[DeleteOperation]:
    """Return scoped delete operations found in one source file."""
    suffix = PurePosixPath(path.replace("\\", "/")).suffix.lower()
    if suffix == ".py":
        return _python_delete_operations(path, content)
    if suffix in {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}:
        return _text_delete_operations(path, content)
    if suffix in {".sh", ".bash", ".zsh"}:
        return _text_delete_operations(path, content)
    return []
