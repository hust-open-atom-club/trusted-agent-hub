from __future__ import annotations

import re

from .models import DependencyRecord


def parse_cargo_lock(content: str, source_file: str) -> list[DependencyRecord]:
    result: list[DependencyRecord] = []
    current: dict[str, str] = {}
    for line in content.splitlines() + [""]:
        match = re.match(r"^(name|version)\s*=\s*\"([^\"]+)\"", line.strip())
        if match:
            current[match.group(1)] = match.group(2)
        elif not line.strip() and current.get("name"):
            result.append(DependencyRecord(current["name"], current.get("version"), "crates.io", True, source_file))
            current = {}
    return result
