"""Dependency lockfile parsers with a common normalized output."""

from __future__ import annotations

from scanners.risk_scanner.dependency_parsers.models import DependencyRecord
from scanners.risk_scanner.dependency_parsers.npm import parse_package_json, parse_package_lock, parse_pnpm_lock, parse_yarn_lock
from scanners.risk_scanner.dependency_parsers.python import parse_pipfile_lock, parse_poetry_lock, parse_requirements
from scanners.risk_scanner.dependency_parsers.rust import parse_cargo_lock


def parse_dependencies(files: dict[str, str]) -> list[DependencyRecord]:
    records: list[DependencyRecord] = []
    for path, content in sorted(files.items()):
        name = path.rsplit("/", 1)[-1].lower()
        if name == "package.json":
            records.extend(parse_package_json(content, path))
        elif name == "package-lock.json":
            records.extend(parse_package_lock(content, path))
        elif name == "pnpm-lock.yaml":
            records.extend(parse_pnpm_lock(content, path))
        elif name == "yarn.lock":
            records.extend(parse_yarn_lock(content, path))
        elif name == "requirements.txt":
            records.extend(parse_requirements(content, path))
        elif name == "poetry.lock":
            records.extend(parse_poetry_lock(content, path))
        elif name == "pipfile.lock":
            records.extend(parse_pipfile_lock(content, path))
        elif name == "cargo.lock":
            records.extend(parse_cargo_lock(content, path))
    # A lockfile and manifest can describe the same direct dependency.
    unique: dict[tuple[str, str, str | None, str], DependencyRecord] = {}
    for record in records:
        key = (record.ecosystem, record.name.lower(), record.version, record.source_file)
        unique[key] = record
    return list(unique.values())


__all__ = ["DependencyRecord", "parse_dependencies"]
