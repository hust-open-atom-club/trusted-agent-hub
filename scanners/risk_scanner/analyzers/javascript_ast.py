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


def _tokens(content: str) -> list[tuple[str, int, int, int]]:
    pattern = re.compile(
        r"(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)|"
        r"(?P<string>`(?:\\.|[^`])*`|'(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\")|"
        r"(?P<identifier>[A-Za-z_$][\w$]*)|(?P<punct>[().,])"
    )
    result: list[tuple[str, int, int, int]] = []
    for match in pattern.finditer(content):
        if match.lastgroup in {"comment", "string"}:
            continue
        line = content.count("\n", 0, match.start()) + 1
        result.append((match.group(), line, match.start(), match.end()))
    return result


def _closing_paren_start(
    tokens: list[tuple[str, int, int, int]],
    open_paren_index: int,
    content_length: int,
) -> int:
    depth = 0
    for token, _line, start, _end in tokens[open_paren_index:]:
        if token == "(":
            depth += 1
        elif token == ")":
            depth -= 1
            if depth == 0:
                return start
    return content_length


def analyze_javascript(path: str, content: str) -> JavaScriptAstAnalysis:
    result = JavaScriptAstAnalysis(path=path)
    try:
        tokens = _tokens(content)
        for index, (token, line, token_start, _token_end) in enumerate(tokens):
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
                open_paren_end = tokens[index + 1][3]
                close_paren = _closing_paren_start(
                    tokens,
                    index + 1,
                    len(content),
                )
                argument = content[open_paren_end:close_paren]
                argument_text = argument.strip()
                shell_capable = token == "exec" or calling.endswith(".exec")
                has_argument = bool(argument_text)
                literal_argument = argument_text.startswith(("'", '"', "`"))
                dynamic = has_argument and not literal_argument
                dynamic = dynamic or bool(re.search(
                    r"(?:process\.env|os\.environ|\+|\$\{)",
                    argument,
                ))
                if re.search(r"\b(?:process\.env|os\.environ)\b", argument):
                    input_source = "environment"
                elif re.search(r"\b(?:req\.|request\.|argv|user[_-]?input|input)\b", argument, re.I):
                    input_source = "user_input"
                elif literal_argument:
                    input_source = "literal"
                else:
                    input_source = "variable"
                line_start = content.rfind("\n", 0, token_start) + 1
                result.calls.append(JavaScriptCallEvent(
                    line,
                    calling,
                    kind,
                    dynamic=dynamic,
                    input_source=input_source,
                    shell_capable=shell_capable,
                    column=token_start - line_start,
                ))
        result.calls = list(dict.fromkeys(result.calls))
    except (ValueError, TypeError):
        result.error = "javascript tokenization failed"
    return result
