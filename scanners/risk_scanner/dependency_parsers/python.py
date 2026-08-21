from __future__ import annotations

import json
import re

from .models import DependencyRecord


def parse_requirements(content: str, source_file: str) -> list[DependencyRecord]:
    result: list[DependencyRecord] = []
    for line in content.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http:")):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:(==|===|>=|<=|~=|>|<)\s*([^;\s]+))?", line)
        if match:
            result.append(DependencyRecord(match.group(1), match.group(3), "PyPI", True, source_file))
    return result


def _parse_toml_packages(content: str, source_file: str) -> list[DependencyRecord]:
    result: list[DependencyRecord] = []
    current: dict[str, str] = {}
    for line in content.splitlines() + [""]:
        match = re.match(r"^\s*(name|version)\s*=\s*[\"']([^\"']+)", line)
        if match:
            current[match.group(1)] = match.group(2)
        elif not line.strip() and current.get("name"):
            result.append(DependencyRecord(current["name"], current.get("version"), "PyPI", True, source_file))
            current = {}
    return result


def parse_poetry_lock(content: str, source_file: str) -> list[DependencyRecord]:
    return _parse_toml_packages(content, source_file)


def parse_pipfile_lock(content: str, source_file: str) -> list[DependencyRecord]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    result: list[DependencyRecord] = []
    for section, direct in (("default", True), ("develop", False)):
        values = data.get(section, {})
        if isinstance(values, dict):
            for name, info in values.items():
                version = info.get("version") if isinstance(info, dict) else info
                integrity = None
                if isinstance(info, dict):
                    hashes = info.get("hashes")
                    integrity = hashes[0] if isinstance(hashes, list) and hashes else None
                result.append(DependencyRecord(name, str(version).lstrip("=") if version else None,
                                                "PyPI", direct, source_file, integrity=integrity))
    return result
