"""Dependency lockfile parsers with a common normalized output."""

from __future__ import annotations

import json
import re
import tomllib

from scanners.risk_scanner.dependency_parsers.models import (
    DependencyRecord,
    DependencySourceObservation,
    DependencySourceUsage,
)
from scanners.risk_scanner.dependency_parsers.npm import parse_package_json, parse_package_lock, parse_pnpm_lock, parse_yarn_lock
from scanners.risk_scanner.dependency_parsers.python import (
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_requirement_sources,
    parse_requirements,
)
from scanners.risk_scanner.dependency_parsers.rust import parse_cargo_lock


def parse_dependencies(files: dict[str, str]) -> list[DependencyRecord]:
    records: list[DependencyRecord] = []
    for path, content in sorted(files.items()):
        name = path.rsplit("/", 1)[-1].lower()
        if name == "package.json":
            records.extend(parse_package_json(content, path))
        elif name in {"package-lock.json", "npm-shrinkwrap.json"}:
            records.extend(parse_package_lock(content, path))
        elif name == "pnpm-lock.yaml":
            records.extend(parse_pnpm_lock(content, path))
        elif name == "yarn.lock":
            records.extend(parse_yarn_lock(content, path))
        elif name.startswith("requirements") and name.endswith(".txt"):
            records.extend(parse_requirements(content, path))
        elif name == "poetry.lock":
            records.extend(parse_poetry_lock(content, path))
        elif name == "pipfile.lock":
            records.extend(parse_pipfile_lock(content, path))
        elif name == "cargo.lock":
            records.extend(parse_cargo_lock(content, path))
    # Registry is intentionally part of record identity: collapsing the same
    # package/version from two registries would erase policy-relevant source
    # evidence. The OSV client independently caches lookups by package/version.
    unique: dict[tuple[str, str, str | None, str, str | None], DependencyRecord] = {}
    for record in records:
        key = (
            record.ecosystem,
            record.name.lower(),
            record.version,
            record.source_file,
            record.registry,
        )
        unique[key] = record
    return list(unique.values())


def _source_observation(
    ecosystem: str,
    url: object,
    usage: DependencySourceUsage,
    source_file: str,
    dependency_name: str | None = None,
) -> DependencySourceObservation | None:
    value = str(url or "").strip().strip('"\'')
    if not value or "://" not in value:
        return None
    return DependencySourceObservation(
        ecosystem=ecosystem,
        url=value,
        usage=usage,
        source_file=source_file,
        dependency_name=dependency_name,
    )


def _toml_data(content: str) -> dict[str, object]:
    try:
        value = tomllib.loads(content)
    except (tomllib.TOMLDecodeError, ValueError):
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
    for record in records if records is not None else parse_dependencies(files):
        if not record.registry:
            continue
        observation = _source_observation(
            record.ecosystem,
            record.registry,
            record.registry_usage or "registry_api",
            record.source_file,
            record.name,
        )
        if observation:
            observations.append(observation)

    for path, content in sorted(files.items()):
        normalized_path = path.replace("\\", "/").casefold()
        name = normalized_path.rsplit("/", 1)[-1]

        if name.startswith("requirements") and name.endswith(".txt"):
            for match in re.finditer(
                r"(?im)^\s*(?P<option>--(?:extra-)?index-url|--find-links|-i)"
                r"(?:\s+|=)(?P<url>\S+)",
                content,
            ):
                option = match.group("option").casefold()
                observation = _source_observation(
                    "pypi",
                    match.group("url"),
                    (
                        "resolved_download"
                        if option == "--find-links"
                        else "registry_api"
                    ),
                    path,
                )
                if observation:
                    observations.append(observation)
            for dependency_name, source_url in parse_requirement_sources(content):
                observation = _source_observation(
                    "pypi",
                    source_url,
                    "resolved_download",
                    path,
                    dependency_name,
                )
                if observation:
                    observations.append(observation)

        elif name == "pipfile.lock":
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
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
                r"(?im)^\s*(?:@[^:\s]+:)?registry\s*=\s*([^\s;#]+)",
                content,
            ):
                observation = _source_observation(
                    "npm", match.group(1), "registry_api", path
                )
                if observation:
                    observations.append(observation)

        elif name == "pnpm-lock.yaml":
            for match in re.finditer(
                r"(?im)^\s*tarball:\s*[\"']?([^\s\"']+)", content
            ):
                observation = _source_observation(
                    "npm", match.group(1), "resolved_download", path
                )
                if observation:
                    observations.append(observation)

    unique: dict[
        tuple[str, str, DependencySourceUsage, str],
        DependencySourceObservation,
    ] = {}
    for observation in observations:
        key = (
            observation.ecosystem.casefold(),
            observation.url,
            observation.usage,
            observation.source_file,
        )
        existing = unique.get(key)
        if existing is None or (
            existing.dependency_name is None
            and observation.dependency_name is not None
        ):
            unique[key] = observation
    return list(unique.values())


__all__ = [
    "DependencyRecord",
    "DependencySourceObservation",
    "parse_dependencies",
    "parse_dependency_sources",
]
