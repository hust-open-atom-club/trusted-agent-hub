from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

from .models import DependencyRecord, DependencyScope


def _version(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _direct_dependency_source(version: str | None) -> str | None:
    value = (version or "").strip()
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", value, re.IGNORECASE):
        return value

    shorthand = re.match(
        r"^(?:(?P<provider>github|gitlab|bitbucket):)?"
        r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)"
        r"(?P<ref>#[^\s]+)?$",
        value,
        re.IGNORECASE,
    )
    if shorthand:
        provider = (shorthand.group("provider") or "github").casefold()
        host = {
            "github": "github.com",
            "gitlab": "gitlab.com",
            "bitbucket": "bitbucket.org",
        }[provider]
        ref = shorthand.group("ref") or ""
        return (
            f"git+https://{host}/{shorthand.group('owner')}/"
            f"{shorthand.group('repo')}.git{ref}"
        )
    return None


def _resolved_source(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _integrity(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _lock_scope(info: dict[str, Any]) -> DependencyScope:
    if info.get("devOptional") is True:
        return "mixed"
    if info.get("dev") is True:
        return "dev"
    if info.get("optional") is True:
        return "optional"
    return "runtime"


def _yarn_resolved_source(value: str) -> tuple[str, str | None]:
    """Separate an HTTP tarball URL from Yarn Classic's hash fragment."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value, None
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.fragment:
        return value, None
    return parsed._replace(fragment="").geturl(), parsed.fragment


def parse_package_json(content: str, source_file: str) -> list[DependencyRecord]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    records: list[DependencyRecord] = []
    for field, direct, scope in (
        ("dependencies", True, "runtime"),
        ("devDependencies", False, "dev"),
        ("optionalDependencies", True, "optional"),
    ):
        values = data.get(field, {})
        if isinstance(values, dict):
            for name, version in values.items():
                normalized_version = _version(version)
                source = _direct_dependency_source(normalized_version)
                records.append(
                    DependencyRecord(
                        name,
                        normalized_version,
                        "npm",
                        direct,
                        source_file,
                        registry=source,
                        registry_usage="resolved_download" if source else None,
                        scope=scope,
                        source_ref=f"#/{field}/{_pointer_token(name)}",
                    )
                )
    return records


def parse_package_lock(content: str, source_file: str) -> list[DependencyRecord]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
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
            resolved = _resolved_source(info.get("resolved"))
            records.append(
                DependencyRecord(
                    name,
                    _version(info.get("version")),
                    "npm",
                    "/node_modules/" not in path or path.count("node_modules/") == 1,
                    source_file,
                    registry=resolved,
                    integrity=_integrity(info.get("integrity")),
                    registry_usage="resolved_download" if resolved else None,
                    scope=_lock_scope(info),
                    source_ref=f"#/packages/{_pointer_token(path)}",
                )
            )
    deps = data.get("dependencies", {})
    if not records and isinstance(deps, dict):
        def visit(values: dict[str, Any], direct: bool, pointer: str) -> None:
            for name, info in values.items():
                if not isinstance(info, dict):
                    continue
                resolved = _resolved_source(info.get("resolved"))
                records.append(
                    DependencyRecord(
                        name,
                        _version(info.get("version")),
                        "npm",
                        direct,
                        source_file,
                        registry=resolved,
                        integrity=_integrity(info.get("integrity")),
                        registry_usage="resolved_download" if resolved else None,
                        scope=_lock_scope(info),
                        source_ref=f"{pointer}/{_pointer_token(name)}",
                    )
                )
                nested = info.get("dependencies")
                if isinstance(nested, dict):
                    visit(nested, False, f"{pointer}/{_pointer_token(name)}/dependencies")
        visit(deps, True, "#/dependencies")
    return records


def parse_pnpm_lock(content: str, source_file: str) -> list[DependencyRecord]:
    records: list[DependencyRecord] = []
    section = ""
    current: str | None = None
    for line_no, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.endswith(":") and not stripped.startswith("/"):
            section = stripped[:-1]
            current = None
        match = re.match(r"^\s{2,}(?:/)?(@?[^:]+):(?:\s*\{?([^,}\s]+))?", line)
        if match and section in {"dependencies", "devDependencies", "packages", "snapshots"}:
            current = match.group(1)
            version = _version(match.group(2))
            if current and version and not current.startswith(("@", "/")):
                records.append(DependencyRecord(
                    current, version.lstrip("^~"), "npm",
                    section == "dependencies", source_file,
                    scope="runtime" if section == "dependencies" else "dev" if section == "devDependencies" else "unknown",
                    source_ref=f"L{line_no}", line=line_no,
                ))
        if current and stripped.startswith("version:"):
            version = stripped.split(":", 1)[1].strip().strip("'\"")
            if not any(r.name == current and r.source_file == source_file for r in records):
                records.append(DependencyRecord(
                    current, version, "npm", section == "dependencies", source_file,
                    scope="runtime" if section == "dependencies" else "dev" if section == "devDependencies" else "unknown",
                    source_ref=f"L{line_no}", line=line_no,
                ))
    return records


def parse_yarn_lock(content: str, source_file: str) -> list[DependencyRecord]:
    records: list[DependencyRecord] = []
    current_names: list[str] = []
    current_version: str | None = None
    current_resolved: str | None = None
    current_integrity: str | None = None
    current_line: int | None = None

    def flush() -> None:
        nonlocal current_names, current_version, current_resolved, current_integrity, current_line
        if current_version:
            for selector in current_names:
                name = selector.rsplit("@", 1)[0]
                if name:
                    records.append(
                        DependencyRecord(
                            name,
                            current_version,
                            "npm",
                            True,
                            source_file,
                            registry=current_resolved,
                            integrity=current_integrity,
                            registry_usage="resolved_download" if current_resolved else None,
                            source_ref=f"L{current_line}" if current_line else None,
                            line=current_line,
                        )
                    )
        current_names = []
        current_version = None
        current_resolved = None
        current_integrity = None
        current_line = None

    for line_no, line in enumerate(content.splitlines() + [""], 1):
        if line and not line.startswith((" ", "#")) and line.endswith(":"):
            flush()
            current_names = [part.strip().strip('"\'') for part in line[:-1].split(",")]
            current_line = line_no
        match = re.match(r"^\s+version\s+\"([^\"]+)\"", line)
        if match:
            current_version = match.group(1)
        resolved = re.match(r"^\s+resolved\s+\"([^\"]+)\"", line)
        if resolved:
            current_resolved, fragment_integrity = _yarn_resolved_source(
                resolved.group(1)
            )
            if fragment_integrity and current_integrity is None:
                current_integrity = fragment_integrity
        integrity = re.match(r"^\s+integrity\s+(.+)$", line)
        if integrity:
            current_integrity = integrity.group(1).strip().strip('"\'')
        if not line.strip() and current_names:
            flush()
    return records
