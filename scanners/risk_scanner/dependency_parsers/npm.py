from __future__ import annotations

import json
import re
from typing import Any

from .models import DependencyRecord


def _version(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def parse_package_json(content: str, source_file: str) -> list[DependencyRecord]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    records: list[DependencyRecord] = []
    for field, direct in (("dependencies", True), ("devDependencies", False), ("optionalDependencies", True)):
        values = data.get(field, {})
        if isinstance(values, dict):
            records.extend(DependencyRecord(name, _version(version), "npm", direct, source_file)
                           for name, version in values.items())
    return records


def parse_package_lock(content: str, source_file: str) -> list[DependencyRecord]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    records: list[DependencyRecord] = []
    packages = data.get("packages", {})
    if isinstance(packages, dict):
        for path, info in packages.items():
            if not path or not isinstance(info, dict) or path == "":
                continue
            name = path.rsplit("node_modules/", 1)[-1]
            if name.startswith("@") and "/" in name:
                name = "@" + name[1:].replace("/node_modules/", "/", 1)
            records.append(DependencyRecord(name, _version(info.get("version")), "npm",
                                             "/node_modules/" not in path or path.count("node_modules/") == 1,
                                             source_file, info.get("resolved"), info.get("integrity")))
    deps = data.get("dependencies", {})
    if not records and isinstance(deps, dict):
        def visit(values: dict[str, Any], direct: bool) -> None:
            for name, info in values.items():
                if not isinstance(info, dict):
                    continue
                records.append(DependencyRecord(name, _version(info.get("version")), "npm", direct,
                                                 source_file, info.get("resolved"), info.get("integrity")))
                nested = info.get("dependencies")
                if isinstance(nested, dict):
                    visit(nested, False)
        visit(deps, True)
    return records


def parse_pnpm_lock(content: str, source_file: str) -> list[DependencyRecord]:
    records: list[DependencyRecord] = []
    section = ""
    current: str | None = None
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.endswith(":") and not stripped.startswith("/"):
            section = stripped[:-1]
            current = None
        match = re.match(r"^\s{2,}(?:/)?(@?[^:]+):(?:\s*\{?([^,}\s]+))?", line)
        if match and section in {"dependencies", "devDependencies", "packages", "snapshots"}:
            current = match.group(1)
            version = _version(match.group(2))
            if current and version and not current.startswith(("@", "/")):
                records.append(DependencyRecord(current, version.lstrip("^~"), "npm", section == "dependencies", source_file))
        if current and stripped.startswith("version:"):
            version = stripped.split(":", 1)[1].strip().strip("'\"")
            if not any(r.name == current and r.source_file == source_file for r in records):
                records.append(DependencyRecord(current, version, "npm", section == "dependencies", source_file))
    return records


def parse_yarn_lock(content: str, source_file: str) -> list[DependencyRecord]:
    records: list[DependencyRecord] = []
    current_names: list[str] = []
    for line in content.splitlines():
        if line and not line.startswith((" ", "#")) and line.endswith(":"):
            current_names = [part.strip().strip('"\'') for part in line[:-1].split(",")]
        match = re.match(r"^\s+version\s+\"([^\"]+)\"", line)
        if match:
            for selector in current_names:
                name = selector.rsplit("@", 1)[0] if not selector.startswith("@") else selector.rsplit("@", 1)[0]
                if name:
                    records.append(DependencyRecord(name, match.group(1), "npm", True, source_file))
    return records
