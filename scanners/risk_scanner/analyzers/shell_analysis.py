"""Shell command decomposition used by risk and capability analysis."""

from __future__ import annotations

import re
import shlex

from .models import ShellAnalysis, ShellCommand


def analyze_shell(path: str, content: str) -> ShellAnalysis:
    result = ShellAnalysis(path=path)
    for line_number, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            argv = tuple(shlex.split(stripped, comments=True, posix=True))
        except ValueError:
            result.errors.append(f"invalid shell syntax at line {line_number}")
            continue
        if not argv:
            continue
        result.commands.append(ShellCommand(
            line=line_number,
            argv=argv,
            pipeline="|" in stripped,
            redirections=tuple(re.findall(r"(?:>>?|<<?)\s*[^\s]+", stripped)),
        ))
    return result
