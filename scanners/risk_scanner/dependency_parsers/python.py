from __future__ import annotations

import json
import re
import tomllib

from scanners.risk_scanner.logical_lines import iter_logical_lines

from .models import DependencyRecord


_DIRECT_REFERENCE = re.compile(
    r"^(?P<name>[A-Za-z0-9_.-]+)"
    r"(?:\[[A-Za-z0-9_.-]+(?:\s*,\s*[A-Za-z0-9_.-]+)*\])?"
    r"\s*@\s*(?P<url>\S+)",
    re.IGNORECASE,
)
_EDITABLE_REFERENCE = re.compile(
    r"^(?:-e|--editable)(?:\s+|=)(?P<url>\S+)",
    re.IGNORECASE,
)
_VCS_REFERENCE = re.compile(
    r"^(?:git|hg|svn|bzr)\+[^\s]+://[^\s]+",
    re.IGNORECASE,
)
_HTTP_REFERENCE = re.compile(
    r"^(?P<url>https?://\S+)",
    re.IGNORECASE,
)
_EGG_NAME = re.compile(r"(?:^|[&])egg=([^&]+)", re.IGNORECASE)
_SOURCE_OPTION = re.compile(
    r"(?:^|\s)(?P<option>--(?:extra-)?index-url|--find-links|-i|-f)"
    r"(?:\s+|=)(?P<url>\"[^\"]+\"|'[^']+'|\S+)",
    re.IGNORECASE,
)
_INCOMPLETE_SOURCE_OPTION_PREFIX = re.compile(
    r"^(?:--(?:extra-)?index-url|--find-links|-i|-f)=\s+(?=https?://)",
    re.IGNORECASE,
)


def _requirement_source(line: str) -> tuple[str | None, str] | None:
    direct = _DIRECT_REFERENCE.match(line)
    if direct:
        return direct.group("name"), direct.group("url")

    editable = _EDITABLE_REFERENCE.match(line)
    candidate = editable.group("url") if editable else line
    if _VCS_REFERENCE.match(candidate):
        egg = _EGG_NAME.search(candidate.partition("#")[2])
        return (egg.group(1) if egg else None), candidate

    # Bare URLs keep fragments; only an explicit egg supplies a package name.
    remote = _HTTP_REFERENCE.match(candidate)
    if remote:
        url = remote.group("url")
        egg = _EGG_NAME.search(url.partition("#")[2])
        return (egg.group(1) if egg else None), url
    return None


def parse_requirement_sources(
    content: str,
) -> list[tuple[str | None, str]]:
    """Return remote direct, VCS, and bare HTTP(S) requirement URLs."""
    sources: list[tuple[str | None, str]] = []
    for logical_line in iter_logical_lines(content, requirement_comments=True):
        line = logical_line.text.strip()
        if not line:
            continue
        # Retain trailing URLs in incomplete source declarations for review,
        # even when pip ignores them. This only adds a download observation;
        # it must not grant registry usage or create a dependency record.
        line = _INCOMPLETE_SOURCE_OPTION_PREFIX.sub("", line, count=1)
        source = _requirement_source(line)
        if source:
            sources.append(source)
    return sources


def parse_requirement_options(content: str) -> list[tuple[str, str]]:
    """Return source option/value pairs from complete logical requirements."""
    return [
        (match.group("option").casefold(), match.group("url").strip("\"'"))
        for line in iter_logical_lines(content, requirement_comments=True)
        for match in _SOURCE_OPTION.finditer(line.text)
    ]


def parse_requirements(content: str, source_file: str) -> list[DependencyRecord]:
    result: list[DependencyRecord] = []
    index_url: str | None = None
    for logical_line in iter_logical_lines(content, requirement_comments=True):
        line = logical_line.text.strip()
        if not line:
            continue
        for option in _SOURCE_OPTION.finditer(line):
            if option.group("option").casefold() in {"--index-url", "-i"}:
                index_url = option.group("url").strip("\"'")
        source = _requirement_source(line)
        if source:
            dependency_name, source_url = source
            if not dependency_name:
                continue
            result.append(
                DependencyRecord(
                    dependency_name,
                    None,
                    "PyPI",
                    True,
                    source_file,
                    registry=source_url,
                    registry_usage="resolved_download",
                )
            )
            continue
        if line.startswith("-"):
            continue
        if line.startswith(("git+", "http:", "https:")):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:(==|===|>=|<=|~=|>|<)\s*([^;\s]+))?", line)
        if match:
            version = match.group(3)
            if version:
                version = version.split("#", 1)[0]
            result.append(
                DependencyRecord(
                    match.group(1),
                    version,
                    "PyPI",
                    True,
                    source_file,
                    registry=index_url,
                    registry_usage="registry_api" if index_url else None,
                )
            )
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
    try:
        data = tomllib.loads(content)
    except (tomllib.TOMLDecodeError, ValueError):
        return _parse_toml_packages(content, source_file)
    packages = data.get("package", [])
    if not isinstance(packages, list):
        return _parse_toml_packages(content, source_file)
    result: list[DependencyRecord] = []
    for package in packages:
        if not isinstance(package, dict) or not package.get("name"):
            continue
        source = package.get("source")
        registry = source.get("url") if isinstance(source, dict) else None
        source_type = (
            str(source.get("type", "")).casefold()
            if isinstance(source, dict)
            else ""
        )
        registry_usage = (
            "registry_api"
            if registry and source_type in {"legacy", "repository"}
            else "resolved_download"
            if registry
            else None
        )
        result.append(
            DependencyRecord(
                str(package["name"]),
                str(package["version"]) if package.get("version") else None,
                "PyPI",
                True,
                source_file,
                registry=str(registry) if registry else None,
                registry_usage=registry_usage,
            )
        )
    return result


def parse_pipfile_lock(content: str, source_file: str) -> list[DependencyRecord]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    result: list[DependencyRecord] = []
    source_urls: dict[str, str] = {}
    metadata = data.get("_meta", {})
    sources = metadata.get("sources", []) if isinstance(metadata, dict) else []
    if isinstance(sources, list):
        for source in sources:
            if isinstance(source, dict) and source.get("name") and source.get("url"):
                source_urls[str(source["name"])] = str(source["url"])
    default_registry = next(iter(source_urls.values()), None)
    for section, direct in (("default", True), ("develop", False)):
        values = data.get(section, {})
        if isinstance(values, dict):
            for name, info in values.items():
                version = info.get("version") if isinstance(info, dict) else info
                integrity = None
                registry = default_registry
                if isinstance(info, dict):
                    hashes = info.get("hashes")
                    integrity = hashes[0] if isinstance(hashes, list) and hashes else None
                    index_name = info.get("index")
                    if index_name:
                        registry = source_urls.get(str(index_name))
                result.append(
                    DependencyRecord(
                        name,
                        str(version).lstrip("=") if version else None,
                        "PyPI",
                        direct,
                        source_file,
                        registry=registry,
                        integrity=integrity,
                        registry_usage="registry_api" if registry else None,
                    )
                )
    return result
