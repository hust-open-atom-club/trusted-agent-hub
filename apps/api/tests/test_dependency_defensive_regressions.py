"""Dependency declarations and malformed input must preserve report contracts."""

import json
import sys

import jsonschema
import pytest
from pydantic import ValidationError

from scanners.risk_scanner.dependency_parsers import parse_dependencies_with_errors, parse_dependency_sources
from scanners.risk_scanner.evidence import bounded_dependency_reachability
from scanners.risk_scanner.scanner import RiskScanner
from src.models.packages import FindingOccurrence, RegistryPolicyOccurrence
from tests.test_dependency_scope_regressions import SCHEMA, RecordingOSVClient, scan_dependencies


@pytest.mark.parametrize("bundle_field", ["bundledDependencies", "bundleDependencies"])
@pytest.mark.parametrize("section", ["dependencies", "devDependencies", "optionalDependencies"])
def test_bundling_does_not_exempt_install_ranges_from_locking(bundle_field, section):
    files = {"package.json": json.dumps({section: {"foo": "^1.0.0"}, bundle_field: ["foo"]})}
    records, errors = parse_dependencies_with_errors(files)
    assert errors == []
    assert [(r.name, r.scope) for r in records] == [("foo", "mixed")]
    scanner = scan_dependencies(files)
    assert any("版本未锁定: foo" in f["title"] for f in scanner.findings)
    assert scanner.dependency_scan["inventory_only"] == 0
    assert scanner.dependency_scan["unsupported"] == 1


@pytest.mark.parametrize("in_bundle", [False, True])
def test_bundled_install_manifest_and_lock_keep_consistent_scopes(in_bundle):
    manifest = {"dependencies": {"foo": "^1.0.0"}, "bundledDependencies": ["foo"]}
    files = {
        "package.json": json.dumps(manifest),
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "": manifest,
            "node_modules/foo": {"version": "1.0.0", "inBundle": in_bundle},
        }}),
    }
    scanner = scan_dependencies(files, ["CVE-2099-0001"])
    assert scanner.osv_client.calls == [("foo", "1.0.0")]
    assert scanner.dependency_scan["scope_summary"]["occurrence_counts"]["mixed"] == 2
    assert scanner.dependency_scan["inventory_only"] == 0
    finding = next(f for f in scanner.findings if "CVE-2099-0001" in f["title"])
    assert {item["scope"] for item in finding["occurrences"]["items"]} == {"mixed"}


def test_bundled_exact_install_is_still_queried():
    scanner = scan_dependencies({"package.json": json.dumps({
        "dependencies": {"foo": "1.0.0"}, "bundledDependencies": ["foo"],
    })}, ["CVE-2099-0001"])
    assert scanner.osv_client.calls == [("foo", "1.0.0")]
    assert scanner.dependency_scan["known_vulnerabilities"] == 1


def test_peer_range_with_bundled_name_remains_inventory():
    scanner = scan_dependencies({"package.json": json.dumps({
        "peerDependencies": {"foo": "^1.0.0"}, "bundledDependencies": ["foo"],
    })})
    assert not any("版本未锁定" in f["title"] for f in scanner.findings)
    assert scanner.dependency_scan["inventory_only"] == 1
    assert scanner.dependency_scan["skipped"] == 0


@pytest.mark.parametrize("lock_version", [1, 3])
def test_long_transitive_parent_keeps_every_report_surface_schema_valid(tmp_path, lock_version):
    parent = "p" * 350
    child = {"version": "1.0.0", "resolved": "https://unapproved.example/foo.tgz"}
    if lock_version == 1:
        lock = {"lockfileVersion": 1, "dependencies": {
            parent: {"version": "1.0.0", "dependencies": {"foo": child}},
        }}
    else:
        lock = {"lockfileVersion": 3, "packages": {
            f"node_modules/{parent}/node_modules/foo": child,
        }}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    report = RiskScanner(str(tmp_path), osv_client=RecordingOSVClient(["CVE-2099-0001"])).scan()
    assert any("CVE-2099-0001" in f["title"] for f in report["findings"])
    assert any(a.get("registry_policy") for a in report["review_advisories"])
    jsonschema.validate(report, SCHEMA)


@pytest.mark.parametrize("model,payload", [
    (FindingOccurrence, {"file": "package-lock.json"}),
    (RegistryPolicyOccurrence, {"file": "package-lock.json", "scope": "runtime",
        "resolved_url": "https://unapproved.example/foo.tgz", "usage": "resolved_download"}),
])
def test_api_rejects_oversized_reachability_items(model, payload):
    assert model.model_validate({**payload, "reachability": ["x" * 256]})
    with pytest.raises(ValidationError):
        model.model_validate({**payload, "reachability": ["x" * 257]})


def test_long_reachability_keeps_distinct_parent_identities():
    first = "transitive:" + "parent" * 60 + "a"
    second = "transitive:" + "parent" * 60 + "b"
    labels = bounded_dependency_reachability(["direct", first, second, first])
    assert len(labels) == 3
    assert labels[0] == "direct"
    assert labels[1] != labels[2]
    assert all(len(label) <= 256 for label in labels)
    assert all(label.startswith("transitive:") for label in labels[1:])


def _deep_content(filename):
    depth = sys.getrecursionlimit() + 100
    if filename.endswith("yaml"):
        return "lockfileVersion: '9.0'\npackages: " + "[" * depth + "0" + "]" * depth
    if filename.endswith("lock") and filename != "Pipfile.lock":
        return "nested = " + "[" * depth + "0" + "]" * depth
    return '{"nested":' + "[" * depth + "0" + "]" * depth + "}"


@pytest.mark.parametrize("filename", ["package.json", "package-lock.json", "Pipfile.lock", "pnpm-lock.yaml", "poetry.lock", "Cargo.lock"])
def test_deep_dependency_input_becomes_a_parse_gap_and_keeps_other_queries(filename):
    files = {filename: _deep_content(filename), "requirements.txt": "demo==1.0.0"}
    if filename == "package-lock.json":
        files["package.json"] = '{"dependencies":{"foo":"1.0.0"}}'
    records, errors = parse_dependencies_with_errors(files)
    assert any(r.name == "demo" for r in records)
    assert any(e["file"] == filename for e in errors)
    scanner = scan_dependencies(files)
    assert ("demo", "1.0.0") in scanner.osv_client.calls
    assert scanner.dependency_scan["status"] == "partial"
    assert scanner.dependency_scan["known_vulnerabilities"] is None
    assert scanner.dependency_scan["integrity"]["status"] == "partial"


def test_deep_package_manifest_does_not_abort_whole_scanner(tmp_path):
    (tmp_path / "package.json").write_text(_deep_content("package.json"), encoding="utf-8")
    report = RiskScanner(str(tmp_path), osv_client=RecordingOSVClient()).scan()
    assert report["dependency_scan"]["parse_errors"][0]["file"] == "package.json"
    assert report["scan_status"]["state"] == "partial"
    jsonschema.validate(report, SCHEMA)


def test_deep_pipfile_source_does_not_escape_through_source_collection():
    depth = sys.getrecursionlimit() + 100
    files = {"Pipfile.lock": '{"_meta":{"sources":[{"url":' + "[" * depth + "0" + "]" * depth + '}]}}'}
    records, errors = parse_dependencies_with_errors(files)
    assert errors
    assert parse_dependency_sources(files, records) == []
    assert scan_dependencies(files).dependency_scan["status"] == "partial"
