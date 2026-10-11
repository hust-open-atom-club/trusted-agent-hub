from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import replace
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from .models import DependencyRecord, DependencyScope, is_local_npm_reference
from .validation import validate_structure_depth


def _problem(problems: list[str] | None, source_ref: str) -> None:
    if problems is None:
        raise ValueError(f"Invalid dependency entry at {source_ref}")
    problems.append(source_ref)


def _version(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _direct_dependency_source(version: str | None) -> str | None:
    value = (version or "").strip()
    if is_local_npm_reference(value):
        return None
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


def _scope_from_root_sections(root: dict[str, Any]) -> dict[str, DependencyScope]:
    """Build direct dependency scopes from npm lockfile root metadata."""
    observed: dict[str, set[str]] = {}
    for section, scope in (
        ("dependencies", "runtime"),
        ("devDependencies", "dev"),
        ("optionalDependencies", "optional"),
        ("peerDependencies", "peer"),
        ("bundledDependencies", "bundled"),
        ("bundleDependencies", "bundled"),
    ):
        values = root.get(section, {})
        if isinstance(values, dict):
            names = values.keys()
        elif isinstance(values, list) and scope == "bundled":
            names = values
        else:
            continue
        for name in names:
            if isinstance(name, str) and name:
                observed.setdefault(name, set()).add(scope)

    result: dict[str, DependencyScope] = {}
    for name, scopes in observed.items():
        result[name] = _scope_from_values(scopes)
    return result


def _scope_from_values(scopes: set[str]) -> DependencyScope:
    normalized = {scope for scope in scopes if scope}
    if not normalized:
        return "unknown"
    if len(normalized) > 1:
        return "mixed"
    value = next(iter(normalized))
    return value if value in {
        "runtime", "dev", "test", "optional", "peer", "bundled", "unknown"
    } else "unknown"


def _lock_scope(
    info: dict[str, Any],
    declared_scope: DependencyScope | None = None,
) -> DependencyScope:
    """Interpret npm's install flags without losing peer/bundled context."""
    if info.get("devOptional") is True:
        return "mixed"

    explicit: set[str] = set()
    if info.get("dev") is True:
        explicit.add("dev")
    if info.get("optional") is True:
        explicit.add("optional")
    if info.get("peer") is True:
        explicit.add("peer")
    if info.get("inBundle") is True or info.get("bundled") is True:
        explicit.add("bundled")
        if declared_scope is not None:
            explicit.add(declared_scope)
    if explicit:
        # Preserve npm's existing dev+optional interpretation while marking
        # genuinely different install paths as mixed.
        if explicit == {"dev", "optional"}:
            return "dev"
        return _scope_from_values(explicit)
    if declared_scope is not None:
        return declared_scope
    return "runtime"


def _package_name(path: str) -> str:
    name = path.rsplit("node_modules/", 1)[-1].strip("/")
    return name


def _lock_reachability(path: str) -> tuple[str, ...]:
    parts = [part.strip("/") for part in path.split("node_modules/")]
    if len(parts) <= 2:
        return ("direct",)
    parent = parts[-2] or "unknown"
    return (f"transitive:{parent}",)


def _yarn_resolved_source(value: str) -> tuple[str, str | None]:
    """Separate an HTTP tarball URL from Yarn Classic's hash fragment."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value, None
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.fragment:
        return value, None
    return parsed._replace(fragment="").geturl(), parsed.fragment


def parse_package_json(content: str, source_file: str, *, problems: list[str] | None = None) -> list[DependencyRecord]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    records: list[DependencyRecord] = []
    bundled_names: list[tuple[str, str]] = []
    for field in ("bundledDependencies", "bundleDependencies"):
        values = data.get(field, [])
        if not isinstance(values, (list, bool)):
            _problem(problems, f"#/{field}")
        if isinstance(values, list):
            if any(not isinstance(name, str) or not name for name in values):
                _problem(problems, f"#/{field}")
            bundled_names.extend(
                (str(name), f"#/{field}/{index}")
                for index, name in enumerate(values)
                if isinstance(name, str) and name
            )
    bundled_name_set = {item[0] for item in bundled_names}
    for field, direct, scope in (
        ("dependencies", True, "runtime"),
        ("devDependencies", True, "dev"),
        ("optionalDependencies", True, "optional"),
        ("peerDependencies", True, "peer"),
    ):
        values = data.get(field, {})
        if not isinstance(values, dict):
            _problem(problems, f"#/{field}")
        if isinstance(values, dict):
            for name, version in values.items():
                if not name or not isinstance(version, str) or not version.strip():
                    _problem(problems, f"#/{field}/{_pointer_token(name)}")
                    continue
                normalized_version = _version(version)
                source = _direct_dependency_source(normalized_version)
                local_reference = normalized_version if is_local_npm_reference(normalized_version) else None
                records.append(
                    DependencyRecord(
                        name,
                        normalized_version,
                        "npm",
                        direct,
                        source_file,
                        registry=source,
                        registry_usage="resolved_download" if source else None,
                        scope=_scope_from_values({scope, "bundled"}) if name in bundled_name_set else scope,
                        source_ref=f"#/{field}/{_pointer_token(name)}",
                        reachability=("direct",),
                        local_reference=local_reference,
                    )
                )
    # Some npm manifests list bundled package names without repeating their
    # versions in dependencies. Keep that inventory explicit as unknown-version
    # bundled occurrences instead of silently dropping it.
    represented_bundled = {
        record.name for record in records if record.name in bundled_name_set
    }
    for name, source_ref in bundled_names:
        if name in represented_bundled:
            continue
        records.append(
            DependencyRecord(
                name,
                None,
                "npm",
                True,
                source_file,
                scope="bundled",
                source_ref=source_ref,
                reachability=("direct",),
            )
        )
    return records


def parse_package_lock(content: str, source_file: str, *, problems: list[str] | None = None) -> list[DependencyRecord]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    if "lockfileVersion" in data:
        version = data["lockfileVersion"]
        # bool is an int subclass; JSON strings/floats/null are not versions.
        if type(version) is not int or version not in {1, 2, 3}:
            raise ValueError("Unsupported npm lockfile version")
        if version in {2, 3} and "packages" not in data:
            raise ValueError("Modern npm lockfile has no packages mapping")
        if version == 1 and "packages" in data:
            raise ValueError("npm v1 lockfile uses the legacy dependencies tree")
        if version == 1 and "dependencies" not in data:
            raise ValueError("npm v1 lockfile has no dependencies mapping")
    # Unversioned historic input remains compatible with the recognized
    # dependency layouts; explicit unsupported versions never use this path.
    elif not any(field in data for field in ("dependencies", "packages")):
        raise ValueError("Unrecognized unversioned npm lockfile")
    records: list[DependencyRecord] = []
    packages = data.get("packages", {})
    if not isinstance(packages, dict):
        _problem(problems, "#/packages")
    if isinstance(packages, dict):
        root = packages.get("")
        root_scopes = _scope_from_root_sections(root) if isinstance(root, dict) else {}
        for path, info in packages.items():
            if not isinstance(info, dict):
                _problem(problems, f"#/packages/{_pointer_token(path)}")
                continue
            if not path:
                continue
            if "version" in info and not isinstance(info["version"], str):
                _problem(problems, f"#/packages/{_pointer_token(path)}/version")
                continue
            name = _package_name(path)
            direct = "/node_modules/" not in path or path.count("node_modules/") == 1
            resolved = _resolved_source(info.get("resolved"))
            local_reference = next((value for value in (info.get("version"), resolved) if is_local_npm_reference(value)), None)
            if "link" in info and not isinstance(info["link"], bool):
                _problem(problems, f"#/packages/{_pointer_token(path)}/link")
            if info.get("link") is True:
                if not resolved or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", resolved) and not resolved.casefold().startswith("file:"):
                    _problem(problems, f"#/packages/{_pointer_token(path)}/resolved")
                local_reference = local_reference or f"file:{resolved or path}"
            elif "node_modules" not in path.replace("\\", "/").split("/"):
                # Workspace/link targets live outside node_modules and may
                # have their own exact version. That is not a registry version.
                local_reference = local_reference or f"file:{path}"
                name = info.get("name") if isinstance(info.get("name"), str) and info["name"] else PurePosixPath(path).name
            records.append(
                DependencyRecord(
                    name,
                    _version(info.get("version")),
                    "npm",
                    direct,
                    source_file,
                    registry=None if local_reference else resolved,
                    integrity=_integrity(info.get("integrity")),
                    registry_usage="resolved_download" if resolved and not local_reference else None,
                    scope=_lock_scope(
                        info,
                        root_scopes.get(name) if direct else None,
                    ),
                    source_ref=f"#/packages/{_pointer_token(path)}",
                    reachability=_lock_reachability(path),
                    local_reference=local_reference,
                )
            )
    deps = data.get("dependencies", {})
    if not isinstance(deps, dict):
        _problem(problems, "#/dependencies")
    if not records and isinstance(deps, dict):
        def visit(
            values: dict[str, Any],
            direct: bool,
            pointer: str,
            parent: str | None = None,
        ) -> None:
            for name, info in values.items():
                if not isinstance(info, dict):
                    _problem(problems, f"{pointer}/{_pointer_token(name)}")
                    continue
                if "version" in info and not isinstance(info["version"], str):
                    _problem(problems, f"{pointer}/{_pointer_token(name)}/version")
                    continue
                resolved = _resolved_source(info.get("resolved"))
                local_reference = next((value for value in (info.get("version"), resolved) if is_local_npm_reference(value)), None)
                records.append(
                    DependencyRecord(
                        name,
                        _version(info.get("version")),
                        "npm",
                        direct,
                        source_file,
                        registry=None if local_reference else resolved,
                        integrity=_integrity(info.get("integrity")),
                        registry_usage="resolved_download" if resolved and not local_reference else None,
                        scope=_lock_scope(info),
                        source_ref=f"{pointer}/{_pointer_token(name)}",
                        reachability=(
                            ("direct",)
                            if direct
                            else (f"transitive:{parent or 'unknown'}",)
                        ),
                        local_reference=local_reference,
                    )
                )
                nested = info.get("dependencies")
                if "dependencies" in info and not isinstance(nested, dict):
                    _problem(problems, f"{pointer}/{_pointer_token(name)}/dependencies")
                if isinstance(nested, dict):
                    visit(
                        nested,
                        False,
                        f"{pointer}/{_pointer_token(name)}/dependencies",
                        name,
                    )
        visit(deps, True, "#/dependencies")
    return records


def _yaml_lock_mapping(content: str) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:
        raise ValueError("YAML parser unavailable") from exc
    try:
        value = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ValueError("Invalid lockfile YAML") from exc
    if not isinstance(value, dict):
        raise ValueError("Lockfile root must be a mapping")
    validate_structure_depth(value)
    return value


def _propagate_scopes(
    seeds: list[tuple[str, str]],
    edges: dict[str, list[tuple[str, bool]]],
) -> dict[str, set[str]]:
    """Propagate each install scope once per node, including cycles/shared paths."""
    scopes: dict[str, set[str]] = {}
    pending = deque(seeds)
    unknown_seeded = False
    while pending or not unknown_seeded:
        if not pending:
            # Unrooted subgraphs can still reach a known dev dependency. Their
            # unknown context must not silently receive a development discount.
            pending.extend((parent, "unknown") for parent in edges if parent not in scopes)
            unknown_seeded = True
            if not pending:
                break
        node, scope = pending.popleft()
        seen = scopes.setdefault(node, set())
        if scope in seen:
            continue
        seen.add(scope)
        for child, optional in edges.get(node, ()):
            pending.append((child, "optional" if optional and scope == "runtime" else scope))
    return scopes


def parse_pnpm_lock(content: str, source_file: str, *, problems: list[str] | None = None) -> list[DependencyRecord]:
    """Keep valid coordinates on entry errors; reject unsupported file structure."""
    data = _yaml_lock_mapping(content)
    lock_major = str(data.get("lockfileVersion", "")).split(".")[0]
    if lock_major not in {"5", "6", "9"}:
        raise ValueError("Unrecognized pnpm lockfile version")
    records: list[DependencyRecord] = []

    def mapping(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("Invalid pnpm dependency mapping")
        return value

    importers = mapping(data.get("importers", {".": data}))
    packages = mapping(data.get("packages", {}))
    snapshots = mapping(data.get("snapshots", {}))
    package_keys = {str(key).split("(", 1)[0] for key in packages}
    for key in snapshots:
        if not isinstance(key, str) or key.split("(", 1)[0] not in package_keys:
            raise ValueError("pnpm snapshot has no package entry")

    graph = snapshots if lock_major == "9" else packages
    seeds: list[tuple[str, str]] = []
    edges: dict[str, list[tuple[str, bool]]] = {}

    def target(name: str, reference: str) -> str | None:
        for candidate in (f"{name}@{reference}", f"/{name}@{reference}", f"/{name}/{reference}", reference.removeprefix("npm:")):
            if candidate in graph:
                return candidate
        return None

    for importer, info in importers.items():
        prefix = f"#/importers/{_pointer_token(str(importer))}" if "importers" in data else "#"
        if not isinstance(info, dict):
            _problem(problems, prefix)
            continue
        for section, scope in (("dependencies", "runtime"), ("devDependencies", "dev"), ("optionalDependencies", "optional")):
            values = info.get(section, {})
            if not isinstance(values, dict):
                _problem(problems, f"{prefix}/{section}")
                continue
            for name, reference in values.items():
                source_ref = f"{prefix}/{section}/{_pointer_token(str(name))}"
                if isinstance(reference, dict) and "specifier" in reference and not isinstance(reference["specifier"], str):
                    _problem(problems, f"{source_ref}/specifier")
                version = reference.get("version") if isinstance(reference, dict) else reference
                if version is None and isinstance(reference, dict) and is_local_npm_reference(reference.get("specifier")):
                    version = reference["specifier"]
                if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
                    _problem(problems, source_ref)
                    continue
                node = target(name, version)
                if node is not None:
                    seeds.append((node, scope))
                elif not is_local_npm_reference(version):
                    _problem(problems, f"{source_ref}/version")
                # Older scoped aliases use /name/version references. Preserve
                # unknown protocols instead of inventing an exact version.
                records.append(DependencyRecord(
                    name, version.split("(", 1)[0], "npm", True, source_file, scope=scope,
                    source_ref=source_ref,
                    reachability=("direct",),
                    local_reference=version if is_local_npm_reference(version) else None,
                ))

    graph_section = "snapshots" if lock_major == "9" else "packages"
    for key, info in graph.items():
        prefix = f"#/{graph_section}/{_pointer_token(str(key))}"
        if not isinstance(key, str) or not isinstance(info, dict):
            _problem(problems, prefix)
            continue
        # Older lockfiles (and some producers) include explicit install flags.
        if any(flag in info for flag in ("dev", "optional", "devOptional")):
            seeds.append((key, _lock_scope(info)))
        for section in ("dependencies", "optionalDependencies"):
            values = info.get(section, {})
            if not isinstance(values, dict):
                _problem(problems, f"{prefix}/{section}")
                continue
            for name, version in values.items():
                if not isinstance(name, str) or not isinstance(version, str):
                    _problem(problems, f"{prefix}/{section}/{_pointer_token(str(name))}")
                    continue
                child = target(name, version)
                if child is not None:
                    edges.setdefault(key, []).append((child, section == "optionalDependencies"))
                elif not is_local_npm_reference(version):
                    _problem(problems, f"{prefix}/{section}/{_pointer_token(name)}")

    graph_scopes = _propagate_scopes(seeds, edges)
    package_scopes: dict[str, set[str]] = {}
    for node, scopes in graph_scopes.items():
        package_scopes.setdefault(node.split("(", 1)[0], set()).update(scopes)

    for key, info in packages.items():
        prefix = f"#/packages/{_pointer_token(str(key))}"
        if not isinstance(info, dict):
            _problem(problems, prefix)
            continue
        if not isinstance(key, str):
            _problem(problems, prefix)
            continue
        coordinate = key.lstrip("/").split("(", 1)[0]
        match = re.fullmatch(r"(@[^/]+/[^/@]+|[^/@]+)(?:@|/)(.+)", coordinate)
        name = info.get("name") or (match.group(1) if match else None)
        version = info.get("version") or (match.group(2).split("_", 1)[0] if match else None)
        if not isinstance(name, str) or not isinstance(version, str) or not version:
            _problem(problems, prefix)
            continue
        resolution = info.get("resolution", {})
        if not isinstance(resolution, dict):
            _problem(problems, f"{prefix}/resolution")
            resolution = {}
        registry = _resolved_source(resolution.get("tarball"))
        local_reference = next((value for value in (key, match.group(2) if match else None, version, registry) if is_local_npm_reference(value)), None)
        scopes = set(package_scopes.get(key.split("(", 1)[0], ()))
        if any(flag in info for flag in ("dev", "optional", "devOptional")):
            scopes.add(_lock_scope(info))
        scope = _scope_from_values(scopes)
        records.append(DependencyRecord(
            name, version, "npm", False, source_file,
            registry=None if local_reference else registry, integrity=_integrity(resolution.get("integrity")),
            registry_usage="resolved_download" if registry and not local_reference else None,
            scope=scope, source_ref=f"#/packages/{_pointer_token(key)}",
            reachability=("transitive",),
            local_reference=local_reference,
        ))
    return records


def _validate_yarn_classic(content: str) -> None:
    """Validate every Classic entry; a matched version alone is not coverage."""
    atom = r'(?:"(?:[^"\\]|\\.)*"|[^\s"\']+)'
    header = re.compile(rf"{atom}(?:\s*,\s*{atom})*:")
    scalar = re.compile(rf"({atom})\s+({atom})(?:\s+#.*)?")
    has_entry = False
    has_version = False
    nested = False
    for raw in content.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if "\t" in raw:
            raise ValueError("Invalid Yarn indentation")
        indent = len(raw) - len(raw.lstrip(" "))
        text = raw.strip()
        if indent == 0:
            if has_entry and not has_version:
                raise ValueError("Yarn entry missing version")
            if not header.fullmatch(text):
                raise ValueError("Unrecognized Yarn lockfile entry")
            selectors = re.findall(r'"(?:[^"\\]|\\.)*"|[^\s,]+', text[:-1])
            if any("@" not in selector.strip('"')[1:] for selector in selectors):
                raise ValueError("Invalid Yarn selector")
            has_entry, has_version, nested = True, False, False
        elif indent == 2 and has_entry:
            if text in {"dependencies:", "optionalDependencies:"}:
                nested = True
                continue
            nested = False
            match = scalar.fullmatch(text)
            if not match:
                raise ValueError("Invalid Yarn entry field")
            if match.group(1) == "version":
                if has_version or not re.fullmatch(r'version "[^"\\]+"', text):
                    raise ValueError("Invalid Yarn version")
                has_version = True
        elif indent == 4 and has_entry and nested and scalar.fullmatch(text):
            continue
        else:
            raise ValueError("Unrecognized Yarn lockfile line")
    if has_entry and not has_version:
        raise ValueError("Yarn entry missing version")
    if not has_entry and "# yarn lockfile v1" not in content:
        raise ValueError("Unrecognized empty Yarn lockfile")


def parse_yarn_lock(
    content: str,
    source_file: str,
    *,
    manifests: list[DependencyRecord] | tuple[DependencyRecord, ...] = (),
    problems: list[str] | None = None,
) -> list[DependencyRecord]:
    _validate_yarn_classic(content)
    records: list[DependencyRecord] = []
    current_names: list[str] = []
    current_version: str | None = None
    current_resolved: str | None = None
    current_integrity: str | None = None
    current_line: int | None = None
    current_section: str | None = None
    selectors: dict[str, str] = {}
    entry_records: dict[str, list[int]] = {}
    references: dict[str, list[tuple[str, bool]]] = {}

    def flush() -> None:
        nonlocal current_names, current_version, current_resolved, current_integrity, current_line
        if current_version:
            node = str(current_line)
            entry_records[node] = []
            for selector in current_names:
                selectors[selector] = node
                name = selector[:selector.find("@", 1)]
                reference = selector[selector.find("@", 1) + 1:]
                local_reference = next((value for value in (reference, current_resolved) if is_local_npm_reference(value)), None)
                if name:
                    entry_records[node].append(len(records))
                    records.append(
                        DependencyRecord(
                            name,
                            current_version,
                            "npm",
                            False,
                            source_file,
                            registry=None if local_reference else current_resolved,
                            integrity=current_integrity,
                            registry_usage="resolved_download" if current_resolved and not local_reference else None,
                            source_ref=f"L{current_line}" if current_line else None,
                            line=current_line,
                            local_reference=local_reference,
                        )
                    )
        current_names = []
        current_version = None
        current_resolved = None
        current_integrity = None
        current_line = None

    for line_no, raw_line in enumerate(content.splitlines(), 1):
        # Match the validator's handling of trailing whitespace. Otherwise a
        # valid header can be ignored and its dependencies silently disappear.
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line and not line.startswith((" ", "#")) and line.endswith(":"):
            flush()
            current_names = [part.strip('"') for part in re.findall(r'"(?:[^"\\]|\\.)*"|[^\s,]+', line[:-1])]
            current_line = line_no
            current_section = None
        if line.startswith("  ") and not line.startswith("   "):
            current_section = line.strip() if line.strip() in {"dependencies:", "optionalDependencies:"} else None
        if line.startswith("    ") and current_section and current_line:
            atoms = re.findall(r'"(?:[^"\\]|\\.)*"|[^\s]+', line.strip())
            name, reference = [json.loads(atom) if atom.startswith('"') else atom for atom in atoms[:2]]
            references.setdefault(str(current_line), []).append((f"{name}@{reference}", current_section == "optionalDependencies:"))
        match = re.match(r"^  version\s+\"([^\"]+)\"", line)
        if match:
            current_version = match.group(1)
        resolved = re.match(r"^  resolved\s+\"([^\"]+)\"", line)
        if resolved:
            current_resolved, fragment_integrity = _yarn_resolved_source(
                resolved.group(1)
            )
            if fragment_integrity and current_integrity is None:
                current_integrity = fragment_integrity
        integrity = re.match(r"^  integrity\s+(.+)$", line)
        if integrity:
            current_integrity = integrity.group(1).strip().strip('"\'')
    flush()
    edges: dict[str, list[tuple[str, bool]]] = {}
    for node, children in references.items():
        for selector, optional in children:
            if selector in selectors:
                edges.setdefault(node, []).append((selectors[selector], optional))
            elif not is_local_npm_reference(selector[selector.find("@", 1) + 1:]):
                _problem(problems, f"L{node}")
    seeds: list[tuple[str, str]] = []
    direct_nodes: set[str] = set()
    directory = PurePosixPath(source_file.replace("\\", "/")).parent
    for record in manifests:
        path = PurePosixPath(record.source_file.replace("\\", "/"))
        if path.name != "package.json" or not path.parent.is_relative_to(directory):
            continue
        node = selectors.get(f"{record.name}@{record.version}")
        if node is not None:
            seeds.append((node, record.scope))
            direct_nodes.add(node)
    scopes = _propagate_scopes(seeds, edges)
    for node, indices in entry_records.items():
        for index in indices:
            records[index] = replace(
                records[index], scope=_scope_from_values(scopes.get(node, set())),
                direct=node in direct_nodes,
                reachability=("direct",) if node in direct_nodes else ("transitive",),
            )
    return records
