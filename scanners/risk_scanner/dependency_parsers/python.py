from __future__ import annotations

import json
import re
import shlex
import tomllib
from collections.abc import Iterator
from pathlib import PurePosixPath

from scanners.risk_scanner.logical_lines import iter_logical_lines

from .models import DependencyRecord, DependencyScope


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
_SOURCE_OPTIONS = frozenset({
    "--index-url", "--extra-index-url", "--find-links", "-i", "-f",
})
_VALUE_OPTIONS = _SOURCE_OPTIONS | {
    "--trusted-host", "--no-binary", "--only-binary", "--use-feature",
}
_FLAG_OPTIONS = frozenset({
    "--no-index", "--prefer-binary", "--require-hashes", "--pre",
})
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


def iter_requirement_sources(
    content: str,
) -> Iterator[tuple[str | None, str, int]]:
    """Yield requirement URLs with their original physical source lines."""
    for logical in iter_logical_lines(content, requirement_comments=True):
        line = logical.text.strip()
        if not line:
            continue
        # Keep trailing URLs in incomplete source declarations for static
        # review, without granting registry usage or creating dependencies.
        line = _INCOMPLETE_SOURCE_OPTION_PREFIX.sub("", line, count=1)
        source = _requirement_source(line)
        if source:
            name, url = source
            offset = logical.text.find(url)
            yield name, url, logical.source_line(max(0, offset))


def _requirement_option_tokens(line: str) -> list[tuple[str, int, int]]:
    """Split quoted arguments while retaining each token's source offset."""
    lexer = shlex.shlex(line, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    tokens: list[tuple[str, int, int]] = []
    while True:
        offset = lexer.instream.tell()
        token = lexer.get_token()
        if token is None:
            return tokens
        while offset < len(line) and line[offset].isspace():
            offset += 1
        tokens.append((token, offset, lexer.instream.tell()))


def _source_options_for_line(line: str) -> list[tuple[str, str, int]]:
    """Read leading options, never option-looking text inside a payload."""
    try:
        tokens = iter(_requirement_option_tokens(line))
    except ValueError:
        return []
    sources: list[tuple[str, str, int]] = []
    for token, offset, end in tokens:
        option, has_equals, value = token.partition("=")
        option = option.casefold()
        # Preserve preceding explicit sources as static evidence. Do not
        # interpret the editable/include payload as more source declarations.
        if option in {"-e", "--editable", "-r", "--requirement", "-c", "--constraint"}:
            break
        if option in _VALUE_OPTIONS:
            # An explicit empty value must not consume the following token.
            if not has_equals:
                value, offset, end = next(tokens, ("", offset, end))
            if option in _SOURCE_OPTIONS and "://" in value:
                # Dequoting may change the raw spelling. Never search a later
                # argument with the same URL when locating this occurrence.
                value_offset = line.find(value, offset, end)
                sources.append((option, value, max(offset, value_offset)))
        elif option not in _FLAG_OPTIONS or has_equals:
            break
    return sources


def iter_requirement_options(content: str) -> Iterator[tuple[str, str, int]]:
    """Yield option/value pairs with the URL's original physical line."""
    for logical in iter_logical_lines(content, requirement_comments=True):
        for option, url, offset in _source_options_for_line(logical.text):
            yield option, url, logical.source_line(offset)


def requirement_scope(source_file: str) -> DependencyScope:
    """Infer a requirements file's dependency scope from filename tokens."""
    basename = PurePosixPath(source_file.replace("\\", "/")).stem.casefold()
    tokens = set(re.split(r"[-_.]", basename))
    return (
        "test" if tokens & {"test", "tests", "spec", "specs"}
        else "dev" if tokens & {"dev", "development"}
        else "runtime"
    )


def parse_requirements(content: str, source_file: str) -> list[DependencyRecord]:
    result: list[DependencyRecord] = []
    index_url: str | None = None
    scope = requirement_scope(source_file)
    for logical in iter_logical_lines(content, requirement_comments=True):
        line_no = logical.start_line
        line = logical.text.strip()
        if not line:
            continue
        for option, source_url, _ in _source_options_for_line(line):
            if option in {"--index-url", "-i"}:
                index_url = source_url
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
                    scope=scope,
                    source_ref=f"L{line_no}",
                    line=line_no,
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
                    scope=scope,
                    source_ref=f"L{line_no}",
                    line=line_no,
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
    for package_index, package in enumerate(packages):
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
        groups = package.get("groups")
        if not isinstance(groups, list):
            groups = []
        group_names = {group.casefold() for group in groups if isinstance(group, str)}
        if "main" in group_names:
            scope = "mixed" if len(group_names) > 1 else "runtime"
        elif group_names and group_names <= {"dev", "test"}:
            scope = "test" if "test" in group_names else "dev"
        elif group_names:
            scope = "unknown"
        else:
            category = package.get("category")
            scope = (
                {"main": "runtime", "dev": "dev", "test": "test"}.get(
                    category, "unknown"
                )
                if isinstance(category, str)
                else "unknown"
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
                scope=scope,
                source_ref=f"package[{package_index}]",
            )
        )
    return result


def parse_pipfile_lock(content: str, source_file: str) -> list[DependencyRecord]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
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
                    integrity = hashes[0] if isinstance(hashes, list) and hashes and isinstance(hashes[0], str) else None
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
                        scope="runtime" if section == "default" else "dev",
                        source_ref=f"#/{section}/{name.replace('~', '~0').replace('/', '~1')}",
                    )
                )
    return result
