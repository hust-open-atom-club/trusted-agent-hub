"""Dependency lockfile parsers with a common normalized output."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import PurePosixPath

from scanners.risk_scanner.evidence import source_reference

from scanners.risk_scanner.dependency_parsers.models import (
    DEPENDENCY_SCOPE_VALUES,
    DependencyRecord,
    DependencyScope,
    DependencySourceObservation,
    DependencySourceUsage,
    is_local_npm_reference,
)
from scanners.risk_scanner.dependency_parsers.npm import parse_package_json, parse_package_lock, parse_pnpm_lock, parse_yarn_lock
from scanners.risk_scanner.dependency_parsers.python import (
    iter_requirement_options,
    iter_requirement_sources,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_requirements,
    requirement_scope,
)
from scanners.risk_scanner.dependency_parsers.rust import parse_cargo_lock
from scanners.risk_scanner.dependency_parsers.validation import validate_structure_depth


def _parser_name(path: str) -> str | None:
    name = path.rsplit("/", 1)[-1].lower()
    if name == "package.json":
        return "npm_package_json"
    if name in {"package-lock.json", "npm-shrinkwrap.json"}:
        return "npm_lockfile"
    if name == "pnpm-lock.yaml":
        return "pnpm_lockfile"
    if name == "yarn.lock":
        return "yarn_lockfile"
    if name.startswith("requirements") and name.endswith(".txt"):
        return "requirements"
    if name == "poetry.lock":
        return "poetry_lockfile"
    if name == "pipfile.lock":
        return "pipfile_lockfile"
    if name == "cargo.lock":
        return "cargo_lockfile"
    return None


def _structured_parse_error(
    path: str,
    content: str,
    parser: str,
) -> dict[str, str] | None:
    """Return a durable parse-gap record for strict structured formats."""
    if parser in {"npm_package_json", "npm_lockfile", "pipfile_lockfile"}:
        try:
            value = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            return {"file": path, "parser": parser, "reason": "dependency_parse_error"}
        if not isinstance(value, dict):
            return {"file": path, "parser": parser, "reason": "dependency_parse_error"}
        validate_structure_depth(value)
        if parser == "pipfile_lockfile":
            for section in ("default", "develop"):
                entries = value.get(section, {})
                if not isinstance(entries, dict) or any(
                    not name or not isinstance(info, (dict, str))
                    or (isinstance(info, dict) and "version" in info and not isinstance(info["version"], str))
                    for name, info in entries.items()
                ):
                    return {"file": path, "parser": parser, "reason": "dependency_parse_error"}
    elif parser in {"poetry_lockfile", "cargo_lockfile"}:
        try:
            value = tomllib.loads(content)
        except (tomllib.TOMLDecodeError, TypeError, ValueError):
            return {"file": path, "parser": parser, "reason": "dependency_parse_error"}
        if not isinstance(value, dict):
            return {"file": path, "parser": parser, "reason": "dependency_parse_error"}
        validate_structure_depth(value)
        entries = value.get("package", [])
        if not isinstance(entries, list) or any(
            not isinstance(entry, dict)
            or not isinstance(entry.get("name"), str) or not entry["name"].strip()
            or not isinstance(entry.get("version"), str) or not entry["version"].strip()
            for entry in entries
        ):
            return {"file": path, "parser": parser, "reason": "dependency_parse_error"}
    return None


def _parse_dependency_records(
    files: dict[str, str], problems: list[str] | None = None,
    *, manifests: list[DependencyRecord] | tuple[DependencyRecord, ...] = (),
) -> list[DependencyRecord]:
    records: list[DependencyRecord] = []
    for path, content in sorted(files.items()):
        parser = _parser_name(path)
        if parser == "npm_package_json":
            records.extend(parse_package_json(content, path, problems=problems))
        elif parser == "npm_lockfile":
            records.extend(parse_package_lock(content, path, problems=problems))
        elif parser == "pnpm_lockfile":
            records.extend(parse_pnpm_lock(content, path, problems=problems))
        elif parser == "yarn_lockfile":
            records.extend(parse_yarn_lock(content, path, manifests=manifests, problems=problems))
        elif parser == "requirements":
            records.extend(parse_requirements(content, path))
        elif parser == "poetry_lockfile":
            records.extend(parse_poetry_lock(content, path))
        elif parser == "pipfile_lockfile":
            records.extend(parse_pipfile_lock(content, path))
        elif parser == "cargo_lockfile":
            records.extend(parse_cargo_lock(content, path))
    return records


def _deduplicate_records(records: list[DependencyRecord]) -> list[DependencyRecord]:
    # Distinct lockfile entries may share a tarball URL while having different
    # scopes or integrity claims. Preserve each addressable occurrence.
    unique: dict[tuple[object, ...], DependencyRecord] = {}
    for record in records:
        key = (
            record.ecosystem,
            record.name.lower(),
            record.version,
            record.source_file,
            record.registry,
            record.integrity,
            record.scope,
            record.source_ref,
            record.line,
            record.reachability or (("direct",) if record.direct else ("transitive",)),
            record.direct,
            record.local_reference,
        )
        unique[key] = record
    return list(unique.values())


def parse_dependencies_with_errors(
    files: dict[str, str],
) -> tuple[list[DependencyRecord], list[dict[str, str]]]:
    """Parse dependencies while retaining explicit structured parse gaps."""
    errors: list[dict[str, str]] = []
    records: list[DependencyRecord] = []
    # Yarn scopes are derived from all manifests, regardless of file ordering.
    ordered_files = sorted(files.items(), key=lambda item: (_parser_name(item[0]) != "npm_package_json", item[0]))
    yarn_directories = {
        PurePosixPath(path.replace("\\", "/")).parent
        for path in files if _parser_name(path) == "yarn_lockfile"
    }
    for path, content in ordered_files:
        parser = _parser_name(path)
        if parser is None:
            continue
        try:
            error = _structured_parse_error(path, content, parser)
            if error:
                errors.append(error)
                continue
            problems: list[str] = []
            manifests = records
            if parser == "yarn_lockfile":
                directory = PurePosixPath(path.replace("\\", "/")).parent
                manifests = [
                    record for record in records
                    if PurePosixPath(record.source_file.replace("\\", "/")).name == "package.json"
                    and max(
                        (parent for parent in yarn_directories if PurePosixPath(record.source_file.replace("\\", "/")).parent.is_relative_to(parent)),
                        key=lambda parent: len(parent.parts), default=None,
                    ) == directory
                ]
            records.extend(_parse_dependency_records({path: content}, problems, manifests=manifests))
            for source_ref in dict.fromkeys(problems):
                error = {"file": path, "parser": parser, "reason": "dependency_parse_error"}
                safe_ref = source_reference(source_ref).get("source_ref")
                if safe_ref:
                    error["source_ref"] = safe_ref
                errors.append(error)
        except (ValueError, RecursionError):
            # Lockfile parsers validate syntax and supported structure before
            # returning records, including valid-but-unrecognized lock formats.
            errors.append({"file": path, "parser": parser, "reason": "dependency_parse_error"})
    return _deduplicate_records(records), errors


def parse_dependencies(files: dict[str, str]) -> list[DependencyRecord]:
    """Parse dependency files, preserving the historic records-only API."""
    records, _errors = parse_dependencies_with_errors(files)
    return records


def _source_observation(
    ecosystem: str,
    url: object,
    usage: DependencySourceUsage,
    source_file: str,
    dependency_name: str | None = None,
    dependency_version: str | None = None,
    integrity: str | None = None,
    scope: DependencyScope = "unknown",
    source_ref: str | None = None,
    line: int | None = None,
    reachability: tuple[str, ...] = (),
    direct: bool | None = None,
) -> DependencySourceObservation | None:
    value = str(url or "").strip().strip('"\'')
    if not value:
        return None
    return DependencySourceObservation(
        ecosystem=ecosystem,
        url=value,
        usage=usage,
        source_file=source_file,
        dependency_name=dependency_name,
        dependency_version=dependency_version,
        integrity=integrity,
        scope=scope,
        source_ref=source_ref,
        line=line,
        reachability=reachability,
        direct=direct,
    )


def _toml_data(content: str) -> dict[str, object]:
    try:
        value = tomllib.loads(content)
        validate_structure_depth(value)
    except (tomllib.TOMLDecodeError, ValueError, RecursionError):
        return {}
    return value if isinstance(value, dict) else {}


def parse_dependency_sources(
    files: dict[str, str],
    records: list[DependencyRecord] | None = None,
) -> list[DependencySourceObservation]:
    """Collect dependency-source URLs from records and source configuration.

    Lockfile entries retain the dependency name so one policy advisory can
    report both observations and the number of affected dependencies. Source
    declarations without a package (for example ``.npmrc``) are retained as
    policy-relevant observations without inventing an affected dependency.
    """

    observations: list[DependencySourceObservation] = []
    source_records = records if records is not None else parse_dependencies(files)
    for record in source_records:
        if not record.registry:
            continue
        observation = _source_observation(
            record.ecosystem,
            record.registry,
            record.registry_usage or "registry_api",
            record.source_file,
            record.name,
            record.version,
            record.integrity,
            record.scope,
            record.source_ref,
            record.line,
            record.reachability or (("direct",) if record.direct else ("transitive",)),
            record.direct,
        )
        if observation:
            observations.append(observation)

    for path, content in sorted(files.items()):
        normalized_path = path.replace("\\", "/").casefold()
        name = normalized_path.rsplit("/", 1)[-1]

        if name.startswith("requirements") and name.endswith(".txt"):
            scope = requirement_scope(path)
            for option, source_url, line_no in iter_requirement_options(content):
                if option not in {"--find-links", "-f"} and any(
                    record.source_file == path and record.registry == source_url
                    for record in source_records
                ):
                    continue
                observation = _source_observation(
                    "pypi",
                    source_url,
                    (
                        "resolved_download"
                        if option in {"--find-links", "-f"}
                        else "registry_api"
                    ),
                    path,
                    scope=scope,
                    source_ref=f"L{line_no}",
                    line=line_no,
                )
                if observation:
                    observations.append(observation)
            record_sources = {
                (record.name, record.registry)
                for record in source_records
                if record.source_file == path
            }
            for dependency_name, source_url, line_no in iter_requirement_sources(content):
                if dependency_name and (dependency_name, source_url) in record_sources:
                    continue
                observation = _source_observation(
                    "pypi",
                    source_url,
                    "resolved_download",
                    path,
                    dependency_name,
                    scope=scope,
                    source_ref=f"L{line_no}",
                    line=line_no,
                )
                if observation:
                    observations.append(observation)

        elif name == "pipfile.lock":
            try:
                data = json.loads(content)
                validate_structure_depth(data)
            except (ValueError, RecursionError):
                data = {}
            metadata = data.get("_meta", {}) if isinstance(data, dict) else {}
            sources = metadata.get("sources", []) if isinstance(metadata, dict) else []
            if isinstance(sources, list):
                for source in sources:
                    if not isinstance(source, dict):
                        continue
                    observation = _source_observation(
                        "pypi", source.get("url"), "registry_api", path
                    )
                    if observation:
                        observations.append(observation)

        elif name == "pyproject.toml":
            data = _toml_data(content)
            tool = data.get("tool", {})
            poetry = tool.get("poetry", {}) if isinstance(tool, dict) else {}
            sources = poetry.get("source", []) if isinstance(poetry, dict) else []
            if isinstance(sources, list):
                for source in sources:
                    if not isinstance(source, dict):
                        continue
                    observation = _source_observation(
                        "pypi", source.get("url"), "registry_api", path
                    )
                    if observation:
                        observations.append(observation)

        elif normalized_path in {".cargo/config", ".cargo/config.toml"} or (
            normalized_path.endswith(("/.cargo/config", "/.cargo/config.toml"))
        ):
            data = _toml_data(content)
            for section_name in ("registries", "source"):
                section = data.get(section_name, {})
                if not isinstance(section, dict):
                    continue
                for config in section.values():
                    if not isinstance(config, dict):
                        continue
                    observation = _source_observation(
                        "cargo", config.get("index") or config.get("registry"),
                        "registry_api", path
                    )
                    if observation:
                        observations.append(observation)

        elif name == ".npmrc":
            for match in re.finditer(
                r"(?im)^\s*((?:@[^:\s]+:)?registry)\s*=\s*([^\s;#]+)",
                content,
            ):
                observation = _source_observation(
                    "npm", match.group(2), "registry_api", path,
                    source_ref=match.group(1),
                    line=content.count("\n", 0, match.start(1)) + 1,
                )
                if observation:
                    observations.append(observation)

        elif name == "pnpm-lock.yaml":
            for line_no, line in enumerate(content.splitlines(), 1):
                match = re.match(r"^\s*tarball:\s*[\"']?([^\s\"']+)", line, re.IGNORECASE)
                if match is None:
                    continue
                if is_local_npm_reference(match.group(1)):
                    continue
                observation = _source_observation(
                    "npm", match.group(1), "resolved_download", path,
                    source_ref=f"L{line_no}", line=line_no,
                )
                if observation:
                    observations.append(observation)

    unique: dict[tuple[object, ...], DependencySourceObservation] = {}
    for observation in observations:
        key = (
            observation.ecosystem.casefold(),
            observation.url,
            observation.usage,
            observation.source_file,
            observation.dependency_name,
            observation.dependency_version,
            observation.integrity,
            observation.scope,
            observation.source_ref,
            observation.line,
            observation.reachability,
            observation.direct,
        )
        unique[key] = observation
    return list(unique.values())


__all__ = [
    "DependencyRecord",
    "DEPENDENCY_SCOPE_VALUES",
    "DependencySourceObservation",
    "parse_dependencies",
    "parse_dependencies_with_errors",
    "parse_dependency_sources",
]
