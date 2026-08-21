"""Dependency-free JavaScript/TypeScript structural token analysis.

This is intentionally a conservative parser for the scanner's baseline. It
tracks imports and call expressions while ignoring comments and string bodies;
projects can later replace it with a full parser without changing rule APIs.
"""

from __future__ import annotations

import re

from .models import JavaScriptAstAnalysis, JavaScriptCallEvent


_CALL_NAMES = {
    "eval": "dynamic_code",
    "Function": "dynamic_code",
    "exec": "process",
    "execFile": "process",
    "spawn": "process",
    "fork": "process",
    "fetch": "network",
    "axios": "network",
}
_CHAIN_CALLS = {
    "child_process.exec": "process",
    "child_process.execFile": "process",
    "child_process.spawn": "process",
    "fs.readFile": "filesystem",
    "fs.writeFile": "filesystem",
    "fs.rm": "filesystem",
}


def _tokens(content: str) -> list[tuple[str, int]]:
    pattern = re.compile(
        r"(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)|"
        r"(?P<string>`(?:\\.|[^`])*`|'(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\")|"
        r"(?P<identifier>[A-Za-z_$][\w$]*)|(?P<punct>[().,])"
    )
    result: list[tuple[str, int]] = []
    for match in pattern.finditer(content):
        if match.lastgroup in {"comment", "string"}:
            continue
        line = content.count("\n", 0, match.start()) + 1
        result.append((match.group(), line))
    return result


def analyze_javascript(path: str, content: str) -> JavaScriptAstAnalysis:
    result = JavaScriptAstAnalysis(path=path)
    try:
        tokens = _tokens(content)
        for index, (token, line) in enumerate(tokens):
            if token in {"import", "require", "from"} and index + 1 < len(tokens):
                result.imports.append(tokens[index + 1][0])
            if index + 1 >= len(tokens) or tokens[index + 1][0] != "(":
                continue
            kind = _CALL_NAMES.get(token)
            calling = token
            if index >= 2 and tokens[index - 1][0] == ".":
                calling = f"{tokens[index - 2][0]}.{token}"
                kind = _CHAIN_CALLS.get(calling, kind)
            if kind:
                result.calls.append(JavaScriptCallEvent(line, calling, kind))
        result.calls = list(dict.fromkeys(result.calls))
    except (ValueError, TypeError):
        result.error = "javascript tokenization failed"
    return result
