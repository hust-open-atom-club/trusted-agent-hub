"""Semantic validation and local/graph-aware npm-family dependency inventory."""

import json

import jsonschema
import pytest
import yaml

from scanners.risk_scanner.dependency_parsers import parse_dependencies_with_errors
from tests.test_dependency_scope_regressions import SCHEMA, scan_dependencies


@pytest.mark.parametrize("lock", [
    {"packages": []},
    {"packages": {"node_modules/x": []}},
    {"dependencies": {"x": []}},
])
def test_semantically_invalid_npm_lock_is_not_clean(lock):
    files = {"package-lock.json": json.dumps(lock)}
    _, errors = parse_dependencies_with_errors(files)
    assert errors
    scan = scan_dependencies(files).dependency_scan
    assert scan["status"] == "partial"
    assert scan["known_vulnerabilities"] is None


@pytest.mark.parametrize("filename,content", [
    ("package.json", '{"dependencies":[]}'),
    ("package.json", '{"devDependencies":{"x":[]}}'),
    ("package.json", '{"bundledDependencies":[false]}'),
    ("package-lock.json", '{"packages":{"node_modules/x":{"version":[]}}}'),
    ("Pipfile.lock", '{"default":[]}'),
    ("Pipfile.lock", '{"develop":{"x":[]}}'),
    ("poetry.lock", 'package = {}'),
    ("poetry.lock", '[[package]]\nname=[]\nversion="1.0.0"'),
    ("Cargo.lock", 'package = {}'),
    ("Cargo.lock", '[[package]]\nname="x"\nversion=[]'),
])
def test_semantic_shape_errors_are_reported(filename, content):
    files = {filename: content}
    _, errors = parse_dependencies_with_errors(files)
    assert errors
    scan = scan_dependencies(files).dependency_scan
    assert scan["status"] == "partial"
    assert scan["vulnerability_status"] == "not_assessed"
    jsonschema.validate(scan, {"$defs": SCHEMA["$defs"], **SCHEMA["properties"]["dependency_scan"]})


def test_bad_npm_entry_preserves_valid_sibling_and_error_pointer():
    files = {"package-lock.json": json.dumps({"packages": {
        "node_modules/bad": [], "node_modules/good": {"version": "1.0.0"},
    }})}
    scanner = scan_dependencies(files, ["CVE-2099-1234"])
    assert scanner.osv_client.calls == [("good", "1.0.0")]
    assert scanner.dependency_scan["parse_errors"][0]["source_ref"] == "#/packages/node_modules~1bad"
    assert scanner.dependency_scan["status"] == "partial"


def test_pnpm_workspace_links_are_inventory_not_unlocked_versions():
    files = {
        "package.json": json.dumps({"dependencies": {"ui": "workspace:*"}}),
        "pnpm-lock.yaml": yaml.safe_dump({
            "lockfileVersion": "9.0",
            "importers": {".": {"dependencies": {"ui": {
                "specifier": "workspace:*", "version": "link:../packages/ui",
            }}}},
        }),
    }
    scanner = scan_dependencies(files)
    assert not any("版本未锁定" in f["title"] for f in scanner.findings)
    assert scanner.dependency_scan["status"] == "complete"
    assert scanner.dependency_scan["unsupported"] == 0
    assert scanner.dependency_scan["inventory_only"] > 0
    assert scanner.osv_client.calls == []


@pytest.mark.parametrize("broken_section", ["importers", "packages", "snapshots"])
def test_pnpm_bad_entry_preserves_other_queries(broken_section):
    lock = {
        "lockfileVersion": "9.0",
        "importers": {".": {"dependencies": {"good": {"specifier": "^1.0.0", "version": "1.0.0"}}}},
        "packages": {"good@1.0.0": {}},
        "snapshots": {"good@1.0.0": {}},
    }
    if broken_section == "importers":
        lock["importers"]["."]["dependencies"]["bad"] = {"specifier": "^2.0.0"}
    elif broken_section == "packages":
        lock["packages"]["bad@2.0.0"] = []
    else:
        lock["snapshots"]["good@1.0.0"] = []
    files = {"pnpm-lock.yaml": yaml.safe_dump(lock)}
    records, errors = parse_dependencies_with_errors(files)
    assert any(r.name == "good" and r.version == "1.0.0" for r in records)
    assert errors
    scanner = scan_dependencies(files, ["CVE-2099-1234"])
    assert ("good", "1.0.0") in scanner.osv_client.calls
    assert scanner.dependency_scan["status"] == "partial"
    assert any("CVE-2099-1234" in f["title"] for f in scanner.findings)
    assert scanner.dependency_scan["parse_errors"][0]["source_ref"]


def test_pnpm_workspace_specifier_without_version_does_not_drop_remote_packages():
    files = {"pnpm-lock.yaml": yaml.safe_dump({
        "lockfileVersion": "9.0",
        "importers": {".": {"dependencies": {"ui": {"specifier": "workspace:*"}}}},
        "packages": {"remote@1.0.0": {}},
        "snapshots": {"remote@1.0.0": {}},
    })}
    records, errors = parse_dependencies_with_errors(files)
    assert any(r.name == "remote" for r in records)
    assert errors == []
    scanner = scan_dependencies(files)
    assert scanner.dependency_scan["status"] == "complete"
    assert scanner.osv_client.calls == [("remote", "1.0.0")]


def test_pnpm_v9_scope_propagates_from_importers_through_snapshots():
    files = {"pnpm-lock.yaml": yaml.safe_dump({
        "lockfileVersion": "9.0",
        "importers": {".": {"devDependencies": {"build": {"specifier": "1.0.0", "version": "1.0.0"}}}},
        "packages": {"build@1.0.0": {}, "helper@2.0.0": {}},
        "snapshots": {"build@1.0.0": {"dependencies": {"helper": "2.0.0"}}, "helper@2.0.0": {}},
    })}
    records, errors = parse_dependencies_with_errors(files)
    assert errors == []
    assert {r.scope for r in records} == {"dev"}


def test_pnpm_v9_snapshot_flags_are_retained_without_importers():
    records, errors = parse_dependencies_with_errors({"pnpm-lock.yaml": yaml.safe_dump({
        "lockfileVersion": "9.0",
        "packages": {"helper@1.0.0": {}},
        "snapshots": {"helper@1.0.0": {"dev": True}},
    })})
    assert errors == []
    assert {r.scope for r in records} == {"dev"}


def test_yarn_dev_scope_propagates_from_manifest_through_lock_graph():
    records, errors = parse_dependencies_with_errors({
        "package.json": '{"devDependencies":{"build":"^1.0.0"}}',
        "yarn.lock": 'build@^1.0.0:\n  version "1.0.0"\n  dependencies:\n    helper "^2.0.0"\nhelper@^2.0.0:\n  version "2.0.0"\n',
    })
    assert errors == []
    assert {r.scope for r in records} == {"dev"}


@pytest.mark.parametrize("manager", ["pnpm", "yarn"])
def test_graph_handles_cycles_optional_shared_and_orphan_nodes(manager):
    if manager == "pnpm":
        files = {"pnpm-lock.yaml": yaml.safe_dump({
            "lockfileVersion": "9.0",
            "importers": {".": {
                "dependencies": {"prod": {"version": "1.0.0"}},
                "devDependencies": {"build": {"version": "1.0.0"}},
            }},
            "packages": {f"{name}@1.0.0": {} for name in ("prod", "build", "shared", "optional", "orphan")},
            "snapshots": {
                "prod@1.0.0": {"dependencies": {"shared": "1.0.0"}, "optionalDependencies": {"optional": "1.0.0"}},
                "build@1.0.0": {"dependencies": {"shared": "1.0.0"}},
                "shared@1.0.0": {"dependencies": {"build": "1.0.0"}},
                "optional@1.0.0": {}, "orphan@1.0.0": {},
            },
        })}
    else:
        files = {
            "package.json": '{"dependencies":{"prod":"1.0.0"},"devDependencies":{"build":"1.0.0"}}',
            "yarn.lock": 'prod@1.0.0:\n  version "1.0.0"\n  dependencies:\n    shared "1.0.0"\n  optionalDependencies:\n    optional "1.0.0"\nbuild@1.0.0:\n  version "1.0.0"\n  dependencies:\n    shared "1.0.0"\nshared@1.0.0:\n  version "1.0.0"\n  dependencies:\n    build "1.0.0"\noptional@1.0.0:\n  version "1.0.0"\norphan@1.0.0:\n  version "1.0.0"\n',
        }
    records, errors = parse_dependencies_with_errors(files)
    assert errors == []
    scopes = {r.name: r.scope for r in records if not r.source_file.endswith("package.json") and not (r.source_ref or "").startswith("#/importers")}
    assert scopes == {"prod": "runtime", "build": "mixed", "shared": "mixed", "optional": "optional", "orphan": "unknown"}


@pytest.mark.parametrize("lock", [
    {"lockfileVersion": "99.0"},
    {"lockfileVersion": "9.0", "importers": []},
    {"lockfileVersion": "9.0", "packages": {"good@1.0.0": {}}, "snapshots": {"missing@1.0.0": {}}},
])
def test_pnpm_file_level_errors_remain_fail_closed(lock):
    records, errors = parse_dependencies_with_errors({"pnpm-lock.yaml": yaml.safe_dump(lock)})
    assert records == []
    assert errors


def test_pnpm_peer_variants_keep_distinct_graph_contexts():
    records, errors = parse_dependencies_with_errors({"pnpm-lock.yaml": yaml.safe_dump({
        "lockfileVersion": "9.0",
        "importers": {".": {
            "dependencies": {"shared": {"version": "1.0.0(peer@1.0.0)"}},
            "devDependencies": {"shared": {"version": "1.0.0(peer@2.0.0)"}},
        }},
        "packages": {"shared@1.0.0": {}, "prod-leaf@1.0.0": {}, "dev-leaf@1.0.0": {}},
        "snapshots": {
            "shared@1.0.0(peer@1.0.0)": {"dependencies": {"prod-leaf": "1.0.0"}},
            "shared@1.0.0(peer@2.0.0)": {"dependencies": {"dev-leaf": "1.0.0"}},
            "prod-leaf@1.0.0": {}, "dev-leaf@1.0.0": {},
        },
    })})
    assert errors == []
    scopes = {r.name: r.scope for r in records if (r.source_ref or "").startswith("#/packages")}
    assert scopes == {"shared": "mixed", "prod-leaf": "runtime", "dev-leaf": "dev"}


def test_yarn_nested_projects_do_not_leak_scope_to_parent_lock():
    lock = 'build@1.0.0:\n  version "1.0.0"\n'
    records, errors = parse_dependencies_with_errors({
        "package.json": '{"devDependencies":{"build":"1.0.0"}}',
        "yarn.lock": lock,
        "nested/package.json": '{"dependencies":{"build":"1.0.0"}}',
        "nested/yarn.lock": lock,
    })
    assert errors == []
    assert {r.source_file: r.scope for r in records if r.source_file.endswith("yarn.lock")} == {
        "yarn.lock": "dev", "nested/yarn.lock": "runtime",
    }


def test_unrooted_graph_context_is_not_discounted_as_dev():
    files = {
        "package.json": '{"devDependencies":{"helper":"1.0.0"}}',
        "yarn.lock": 'helper@1.0.0:\n  version "1.0.0"\norphan@1.0.0:\n  version "1.0.0"\n  dependencies:\n    # a valid nested comment\n    helper "1.0.0"\n',
    }
    records, errors = parse_dependencies_with_errors(files)
    assert errors == []
    assert next(r for r in records if r.name == "helper" and r.source_file == "yarn.lock").scope == "mixed"


@pytest.mark.parametrize("manager", ["pnpm", "yarn"])
def test_scope_reaches_real_vulnerability_findings_and_scoring(manager):
    from src.routers.trust import _load_scorer
    _load_scorer()
    from src.intent import _compute_i2_score

    scores = {}
    for section, scope in (("dependencies", "runtime"), ("devDependencies", "dev")):
        files = {"package.json": json.dumps({section: {"build": "1.0.0"}})}
        if manager == "pnpm":
            files["pnpm-lock.yaml"] = yaml.safe_dump({
                "lockfileVersion": "9.0",
                "importers": {".": {section: {"build": {"version": "1.0.0"}}}},
                "packages": {"build@1.0.0": {}, "helper@1.0.0": {}},
                "snapshots": {"build@1.0.0": {"dependencies": {"helper": "1.0.0"}}, "helper@1.0.0": {}},
            })
        else:
            files["yarn.lock"] = 'build@1.0.0:\n  version "1.0.0"\n  dependencies:\n    helper "1.0.0"\nhelper@1.0.0:\n  version "1.0.0"\n'
        scanner = scan_dependencies(files, ["CVE-2099-1234"])
        findings = [f for f in scanner.findings if "CVE-2099-1234" in f["title"]]
        assert len(findings) == 2
        assert {o["scope"] for f in findings for o in f["occurrences"]["items"]} == {scope}
        scores[scope] = _compute_i2_score(findings)
    assert scores["runtime"] < scores["dev"] < 100
