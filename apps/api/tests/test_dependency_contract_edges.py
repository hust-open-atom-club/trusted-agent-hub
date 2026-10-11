"""Boundary contracts for evidence serialization and local/locked coordinates."""

import json

import jsonschema
import pytest
import yaml

from scanners.risk_scanner.dependency_parsers import parse_dependencies_with_errors, parse_dependency_sources
from scanners.risk_scanner.dependency_parsers.models import DependencyRecord
from scanners.risk_scanner.dependency_parsers.osv_client import dependency_coordinate, dependency_queryability
from scanners.risk_scanner.scanner import RiskScanner
from src.models.packages import FindingOccurrence, FindingOccurrences
from tests.test_dependency_scope_regressions import SCHEMA, RecordingOSVClient, scan_dependencies


@pytest.mark.parametrize("occurrence", [
    {"file": "helper.py", "line": 1},
    {"file": "helper.py", "field_locations": {"name": {"source_ref": "L1", "line": 1}}},
    {"file": "package-lock.json", "ecosystem": "npm", "scope": "dev", "direct": False},
])
@pytest.mark.parametrize("mode", ["python", "json"])
def test_ordinary_occurrence_default_dump_conforms_to_schema(occurrence, mode):
    result = FindingOccurrence.model_validate(occurrence).model_dump(mode=mode)
    jsonschema.validate(result, {"$defs": SCHEMA["$defs"], "$ref": "#/$defs/evidence_location"})
    if "direct" in occurrence:
        assert result["direct"] is False


@pytest.mark.parametrize("reference", ["file:../ui", "file:./archives/ui.tgz", "file:///tmp/ui"])
def test_file_dependency_is_local_inventory(reference):
    files = {"package.json": json.dumps({"dependencies": {"ui": reference}})}
    scanner = scan_dependencies(files)
    assert not any("版本未锁定" in f["title"] for f in scanner.findings)
    assert scanner.osv_client.calls == []
    assert scanner.dependency_scan["status"] == "complete"
    assert scanner.dependency_scan["inventory_only"] == 1
    assert scanner.dependency_scan["vulnerability_status"] == "not_assessed"
    assert parse_dependency_sources(files) == []


def test_npm_link_and_target_are_not_queried_as_registry_packages():
    scanner = scan_dependencies({"package-lock.json": json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"ui": "file:packages/ui"}},
            "node_modules/ui": {"link": True, "resolved": "packages/ui"},
            "packages/ui": {"name": "ui", "version": "1.0.0"},
        },
    })})
    assert not any("版本未锁定" in f["title"] for f in scanner.findings)
    assert scanner.osv_client.calls == []
    assert scanner.dependency_scan["status"] == "complete"
    assert scanner.dependency_scan["inventory_only"] > 0


@pytest.mark.parametrize("version", [0, 4, 999, -1, "3", 3.0, True, False, None, [], {}])
@pytest.mark.parametrize("filename", ["package-lock.json", "npm-shrinkwrap.json"])
def test_invalid_npm_lockfile_versions_are_parse_gaps(filename, version):
    files = {filename: json.dumps({"lockfileVersion": version, "packages": {}})}
    records, errors = parse_dependencies_with_errors(files)
    assert records == []
    assert errors
    scan = scan_dependencies(files).dependency_scan
    assert scan["status"] == "partial"
    assert scan["known_vulnerabilities"] is None


@pytest.mark.parametrize("nodes", [
    {},
    {"packages": {"missing@1.0.0": {}}},
    {"packages": {"missing@1.0.0": {}}, "snapshots": {}},
    {"packages": {"missing@2.0.0": {}}, "snapshots": {"missing@2.0.0": {}}},
    {"packages": {"missing@1.0.0": {}}, "snapshots": {"missing@1.0.0(peer@2.0.0)": {}}},
])
def test_pnpm_unresolved_importer_is_not_clean(nodes):
    lock = {"lockfileVersion": "9.0", "importers": {".": {
        "dependencies": {"missing": {"specifier": "1.0.0", "version": "1.0.0"}},
    }}, **nodes}
    files = {"pnpm-lock.yaml": yaml.safe_dump(lock)}
    _, errors = parse_dependencies_with_errors(files)
    assert errors
    scan = scan_dependencies(files).dependency_scan
    assert scan["status"] == "partial"
    assert scan["known_vulnerabilities"] is None


def test_ordinary_occurrences_round_trip_inside_report(tmp_path):
    (tmp_path / "helper.py").write_text('import os\nos.system(input())\n', encoding="utf-8")
    report = RiskScanner(str(tmp_path), osv_client=RecordingOSVClient()).scan()
    occurrences = [item["occurrences"] for item in report["findings"] if item.get("occurrences")]
    assert occurrences
    for finding in report["findings"]:
        if finding.get("occurrences"):
            finding["occurrences"] = FindingOccurrences.model_validate(finding["occurrences"]).model_dump()
    jsonschema.validate(report, SCHEMA)


@pytest.mark.parametrize("version", [None, 1, 2, 3])
@pytest.mark.parametrize("filename", ["package-lock.json", "npm-shrinkwrap.json"])
def test_supported_npm_layouts_still_scan(filename, version):
    lock = {} if version is None else {"lockfileVersion": version}
    if version in {None, 1}:
        lock["dependencies"] = {"demo": {"version": "1.0.0"}}
    else:
        lock["packages"] = {"node_modules/demo": {"version": "1.0.0"}}
    files = {filename: json.dumps(lock)}
    records, errors = parse_dependencies_with_errors(files)
    assert errors == []
    assert {(r.name, r.version) for r in records} == {("demo", "1.0.0")}
    scanner = scan_dependencies(files)
    assert scanner.osv_client.calls == [("demo", "1.0.0")]
    assert scanner.dependency_scan["status"] == "complete"


@pytest.mark.parametrize("lock", [
    {},
    {"lockfileVersion": 1, "packages": {}},
    {"lockfileVersion": 2, "dependencies": {}},
    {"lockfileVersion": 3, "dependencies": {}},
    {"lockfileVersion": 3, "packages": []},
])
def test_npm_version_layout_mismatch_preserves_other_files(lock):
    files = {
        "package-lock.json": json.dumps(lock),
        "requirements.txt": "demo==1.0.0\n",
    }
    records, errors = parse_dependencies_with_errors(files)
    assert errors and errors[0]["file"] == "package-lock.json"
    assert {(r.name, r.version) for r in records} == {("demo", "1.0.0")}
    scanner = scan_dependencies(files, ["CVE-2099-0001"])
    assert scanner.dependency_scan["status"] == "partial"
    assert scanner.osv_client.calls
    assert any("CVE-2099-0001" in f["title"] for f in scanner.findings)


@pytest.mark.parametrize("filename,lock", [
    ("package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": {
        "ui": {"version": "file:../ui"},
    }})),
    ("package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/ui": {"version": "1.0.0", "resolved": "file:./ui.tgz"},
    }})),
    ("pnpm-lock.yaml", yaml.safe_dump({"lockfileVersion": "9.0", "importers": {".": {
        "dependencies": {"ui": {"specifier": "file:./ui.tgz", "version": "file:ui.tgz"}},
    }}, "packages": {"ui@file:ui.tgz": {"version": "1.0.0", "resolution": {"tarball": "file:ui.tgz"}}},
        "snapshots": {"ui@file:ui.tgz": {}}})),
    ("yarn.lock", '"ui@file:../ui":\n  version "1.0.0"\n'),
])
def test_local_lock_entries_are_inventory(filename, lock):
    files = {filename: lock}
    records, errors = parse_dependencies_with_errors(files)
    assert records and errors == []
    assert parse_dependency_sources(files, records) == []
    scanner = scan_dependencies(files)
    assert scanner.osv_client.calls == []
    assert not any("版本未锁定" in f["title"] for f in scanner.findings)
    assert scanner.dependency_scan["status"] == "complete"
    assert scanner.dependency_scan["inventory_only"] > 0
    assert scanner.dependency_scan["vulnerability_status"] == "not_assessed"


def test_local_exact_version_never_merges_with_remote_coordinate():
    scanner = scan_dependencies({"package-lock.json": json.dumps({
        "lockfileVersion": 3, "packages": {
            "packages/ui": {"name": "ui", "version": "1.0.0"},
            "node_modules/ui": {"version": "1.0.0"},
        },
    })}, ["CVE-2099-0001"])
    assert scanner.osv_client.calls == [("ui", "1.0.0")]
    assert scanner.dependency_scan["inventory_only"] == 1
    assert scanner.dependency_scan["succeeded"] == 1
    assert scanner.dependency_scan["known_vulnerabilities"] is None
    finding = next(f for f in scanner.findings if "CVE-2099-0001" in f["title"])
    assert {item["source_ref"] for item in finding["occurrences"]["items"]} == {"#/packages/node_modules~1ui"}
    assert scanner.dependency_scan["scope_summary"]["coverage"]["runtime"]["unassessed_occurrences"] == 1


def test_local_lock_does_not_resolve_remote_manifest_range():
    scanner = scan_dependencies({
        "package.json": '{"dependencies":{"ui":"^1.0.0"}}',
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/ui": {"version": "1.0.0", "resolved": "file:./ui.tgz"},
        }}),
    })
    assert scanner.osv_client.calls == []
    assert any("版本未锁定" in f["title"] for f in scanner.findings)
    assert scanner.dependency_scan["unsupported"] == 1


def test_osv_coordinate_and_queryability_preserve_local_identity():
    local = DependencyRecord("ui", "1.0.0", "npm", True, "package-lock.json", local_reference="file:ui.tgz")
    remote = DependencyRecord("ui", "1.0.0", "npm", True, "package-lock.json")
    assert dependency_coordinate(local) != dependency_coordinate(remote)
    assert dependency_queryability(local) == (False, "local_workspace_dependency")
    assert dependency_queryability(remote) == (True, None)


@pytest.mark.parametrize("version,key", [("5.4", "/demo/1.0.0"), ("6.0", "/demo@1.0.0"), ("9.0", "demo@1.0.0")])
def test_pnpm_resolved_importer_preserves_dev_scope(version, key):
    lock = {"lockfileVersion": version, "importers": {".": {"devDependencies": {
        "demo": {"specifier": "^1.0.0", "version": "1.0.0"},
    }}}, "packages": {key: {}}}
    if version == "9.0":
        lock["snapshots"] = {key: {}}
    files = {"pnpm-lock.yaml": yaml.safe_dump(lock)}
    records, errors = parse_dependencies_with_errors(files)
    assert errors == []
    assert {r.scope for r in records} == {"dev"}
    scanner = scan_dependencies(files)
    assert scanner.osv_client.calls == [("demo", "1.0.0")]
    assert scanner.dependency_scan["status"] == "complete"


@pytest.mark.parametrize("reference", ["workspace:*", "link:../ui", "file:../ui"])
def test_local_pnpm_importer_does_not_require_registry_node(reference):
    lock = {"lockfileVersion": "9.0", "importers": {".": {"dependencies": {
        "ui": {"specifier": reference, "version": reference},
    }}}}
    files = {"pnpm-lock.yaml": yaml.safe_dump(lock)}
    records, errors = parse_dependencies_with_errors(files)
    assert records and errors == []
    scanner = scan_dependencies(files)
    assert scanner.osv_client.calls == []
    assert scanner.dependency_scan["inventory_only"] == 1
    assert scanner.dependency_scan["status"] == "complete"


def test_pnpm_dangling_reference_preserves_valid_siblings_and_vulnerabilities(tmp_path):
    lock = {"lockfileVersion": "9.0", "importers": {".": {"dependencies": {
        "dangling": {"specifier": "^1.0.0", "version": "1.0.0"},
        "demo": {"specifier": "^2.0.0", "version": "2.0.0"},
    }}}, "packages": {"demo@2.0.0": {}}, "snapshots": {"demo@2.0.0": {}}}
    (tmp_path / "pnpm-lock.yaml").write_text(yaml.safe_dump(lock), encoding="utf-8")
    client = RecordingOSVClient(["CVE-2099-0001"])
    report = RiskScanner(str(tmp_path), osv_client=client).scan()
    assert ("demo", "2.0.0") in client.calls
    assert any("CVE-2099-0001" in f["title"] for f in report["findings"])
    assert report["dependency_scan"]["parse_errors"][0]["source_ref"] == "#/importers/./dependencies/dangling/version"
    assert report["dependency_scan"]["status"] == "partial"
    assert report["scan_status"]["state"] == "partial"
    assert report["dependency_check"]["known_vulnerabilities"] is None
    jsonschema.validate(report, SCHEMA)
