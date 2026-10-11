"""Regression coverage for dependency inventory, parse gaps and API round trips."""

import json
from pathlib import Path

import jsonschema
import pytest

from scanners.risk_scanner.dependency_parsers import parse_dependencies_with_errors
from scanners.risk_scanner.dependency_parsers.osv_client import OSVQueryResult
from scanners.risk_scanner.rules import supply_chain
from scanners.risk_scanner.scanner import RiskScanner
from src.models.packages import RegistryPolicyEvidence
from tests.scanner_mock import MockScanner


SCHEMA = json.loads((Path(__file__).resolve().parents[3] / "packages/schema/scan-report.schema.json").read_text(encoding="utf-8"))


class RecordingOSVClient:
    allow_private_coordinates = True
    max_queries = 5000

    def __init__(self, vulnerabilities=()):
        self.vulnerabilities = list(vulnerabilities)
        self.calls = []

    def reset_scan_state(self):
        self.calls.clear()

    def query(self, dependency):
        self.calls.append((dependency.name, dependency.version))
        return OSVQueryResult(self.vulnerabilities)


def scan_dependencies(files, vulnerabilities=()):
    scanner = MockScanner()
    scanner._file_contents = files
    scanner.osv_client = RecordingOSVClient(vulnerabilities)
    supply_chain.run(scanner)
    return scanner


@pytest.mark.parametrize("manifest", [
    {"peerDependencies": {"demo": "^1.0.0"}},
    {"bundledDependencies": ["demo"]},
])
def test_unresolved_peer_or_bundled_is_inventory_not_failure(manifest):
    scanner = scan_dependencies({"package.json": json.dumps(manifest)})
    assert not any("版本未锁定" in item["title"] for item in scanner.findings)
    scan = scanner.dependency_scan
    assert scan["status"] == "complete"
    assert scan["inventory_only"] == 1
    assert scan["unsupported"] == scan["skipped"] == scan["remaining"] == 0
    assert scan["known_vulnerabilities"] is None
    assert scan["vulnerability_status"] == "not_assessed"
    assert scanner.osv_client.calls == []
    assert scan["query_results"][0]["failure_reason"] == "manifest_inventory_only"
    jsonschema.validate(scan, {"$defs": SCHEMA["$defs"], **SCHEMA["properties"]["dependency_scan"]})


@pytest.mark.parametrize("manifest", [
    {"peerDependencies": {"demo": "^1.0.0"}},
    {"bundledDependencies": ["demo"]},
])
def test_resolved_peer_or_bundled_is_queried_and_vulnerability_retained(manifest):
    scanner = scan_dependencies({
        "package.json": json.dumps(manifest),
        "package-lock.json": json.dumps({"packages": {"": manifest, "node_modules/demo": {"version": "1.2.0"}}}),
    }, ["CVE-2099-0001"])
    assert scanner.osv_client.calls == [("demo", "1.2.0")]
    assert scanner.dependency_scan["status"] == "complete"
    assert scanner.dependency_scan["vulnerability_status"] == "assessed"
    assert scanner.dependency_scan["known_vulnerabilities"] == 1
    assert scanner.dependency_scan["inventory_only"] == 0
    finding = next(item for item in scanner.findings if "CVE-2099-0001" in item["title"])
    assert {item["file"] for item in finding["occurrences"]["items"]} == {"package.json", "package-lock.json"}
    scope = "peer" if "peerDependencies" in manifest else "bundled"
    coverage = scanner.dependency_scan["scope_summary"]["coverage"][scope]
    assert coverage["unassessed_occurrences"] == 0
    assert coverage["vulnerability_count"] == 1


def test_inventory_does_not_mask_runtime_query_failure():
    scanner = MockScanner()
    scanner._file_contents = {"package.json": json.dumps({
        "dependencies": {"runtime-demo": "1.0.0"},
        "peerDependencies": {"peer-demo": "^1.0.0"},
    })}
    supply_chain.run(scanner)
    assert scanner.dependency_scan["status"] != "complete"
    assert scanner.dependency_scan["inventory_only"] == 1
    assert scanner.dependency_scan["remaining"] == 1


def test_inventory_with_successful_runtime_query_is_complete_but_not_all_assessed():
    scanner = scan_dependencies({"package.json": json.dumps({
        "dependencies": {"runtime-demo": "1.0.0"},
        "peerDependencies": {"peer-demo": "^1.0.0"},
    })}, ["CVE-2099-0001"])
    scan = scanner.dependency_scan
    assert scanner.osv_client.calls == [("runtime-demo", "1.0.0")]
    assert scan["status"] == "complete"
    assert scan["inventory_only"] == scan["succeeded"] == 1
    assert scan["known_vulnerabilities"] is None
    assert scan["vulnerability_status"] == "not_assessed"
    assert scan["scope_summary"]["vulnerability_counts"]["runtime"] == 1
    assert any("CVE-2099-0001" in item["title"] for item in scanner.findings)
    jsonschema.validate(scan, {"$defs": SCHEMA["$defs"], **SCHEMA["properties"]["dependency_scan"]})


def test_peer_inventory_does_not_make_whole_scan_partial(tmp_path):
    (tmp_path / "package.json").write_text('{"peerDependencies":{"demo":"^1.0.0"}}', encoding="utf-8")
    report = RiskScanner(str(tmp_path), osv_client=RecordingOSVClient()).scan()
    assert report["scan_status"]["state"] == "complete"
    assert report["dependency_check"]["known_vulnerabilities"] is None
    assert report["dependency_check"]["vulnerability_status"] == "not_assessed"
    jsonschema.validate(report, SCHEMA)


def test_runtime_range_still_requires_locking():
    scanner = scan_dependencies({"package.json": '{"dependencies":{"demo":"^1.0.0"}}'})
    assert any("版本未锁定" in item["title"] for item in scanner.findings)
    assert scanner.dependency_scan["status"] == "unsupported"


@pytest.mark.parametrize("filename,content", [
    ("pnpm-lock.yaml", "packages: [broken"),
    ("pnpm-lock.yaml", "not a lockfile"),
    ("pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages: []\n"),
    ("pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  invalid: {}\n"),
    ("pnpm-lock.yaml", "packages:\n  demo@1.0.0: [broken\n"),
    ("yarn.lock", "not a lockfile"),
    ("yarn.lock", 'demo@^1.0.0:\n  version "1.0.0"\n\nBROKEN\n'),
    ("yarn.lock", 'demo@^1.0.0:\n  version "unterminated\n'),
    ("yarn.lock", 'demo@^1.0.0:\n  resolved "https://registry.yarnpkg.com/demo.tgz"\n'),
    ("yarn.lock", '__metadata:\n  version: 8\n'),
    ("yarn.lock", ""),
])
def test_lockfile_parse_gaps_never_report_clean(filename, content):
    _records, errors = parse_dependencies_with_errors({filename: content})
    assert errors and errors[0]["file"] == filename
    scanner = scan_dependencies({filename: content})
    assert scanner.dependency_scan["parse_errors"] == errors
    assert scanner.dependency_scan["status"] == "partial"
    assert scanner.dependency_scan["known_vulnerabilities"] is None
    assert scanner.dependency_scan["vulnerability_status"] == "not_assessed"


@pytest.mark.parametrize("filename,content,names", [
    ("pnpm-lock.yaml", "lockfileVersion: '9.0'\nimporters: {}\n", set()),
    ("yarn.lock", "# yarn lockfile v1\n", set()),
    ("yarn.lock", 'demo@^1.0.0:   \n  version "1.0.0"\n', {("demo", "1.0.0")}),
    ("yarn.lock", 'demo@^1.0.0:\n  version "1.0.0"\n  dependencies:\n    version "^2.0.0"\nversion@^2.0.0:\n  version "2.0.0"\n', {("demo", "1.0.0"), ("version", "2.0.0")}),
    ("yarn.lock", 'demo@^1.0.0, demo@~1.0.0:\n\n  version "1.0.0"\n  dependencies:\n    helper "^2.0.0"\n\nhelper@^2.0.0:\n  version "2.0.0"\n', {("demo", "1.0.0"), ("helper", "2.0.0")}),
    ("pnpm-lock.yaml", "lockfileVersion: '9.0'\nimporters:\n  .:\n    devDependencies:\n      '@scope/demo':\n        specifier: ^1.0.0\n        version: 1.2.0\npackages:\n  '@scope/demo@1.2.0':\n    resolution: {integrity: sha512-demo}\nsnapshots:\n  '@scope/demo@1.2.0': {}\n", {("@scope/demo", "1.2.0")}),
    ("pnpm-lock.yaml", "lockfileVersion: 5.4\ndependencies:\n  demo: 1.2.0\npackages:\n  /demo/1.2.0:\n    resolution: {integrity: sha512-demo}\n", {("demo", "1.2.0")}),
])
def test_recognized_lockfiles_preserve_inventory(filename, content, names):
    records, errors = parse_dependencies_with_errors({filename: content})
    assert errors == []
    assert {(record.name, record.version) for record in records} == names


def test_bad_lockfile_with_valid_dependencies_remains_partial():
    scanner = scan_dependencies({
        "package.json": '{"dependencies":{"demo":"1.0.0"}}',
        "yarn.lock": "garbage",
    })
    assert scanner.osv_client.calls == [("demo", "1.0.0")]
    assert scanner.dependency_scan["status"] == "partial"
    assert scanner.dependency_scan["known_vulnerabilities"] is None


@pytest.mark.parametrize("filename", ["pnpm-lock.yaml", "yarn.lock"])
def test_lockfile_parse_error_propagates_to_whole_report(tmp_path, filename):
    (tmp_path / filename).write_text("not a lockfile", encoding="utf-8")
    report = RiskScanner(str(tmp_path), osv_client=RecordingOSVClient()).scan()
    assert report["scan_status"]["state"] == "partial"
    assert report["dependency_check"]["known_vulnerabilities"] is None
    assert report["dependency_check"]["vulnerability_status"] == "not_assessed"
    assert report["dependency_scan"]["parse_errors"][0]["file"] == filename
    jsonschema.validate(report, SCHEMA)


@pytest.mark.parametrize("exclude_none", [False, True])
@pytest.mark.parametrize("filename,content", [
    (".npmrc", "registry=https://unapproved.example/\n"),
    ("package-lock.json", json.dumps({"packages": {"node_modules/demo": {
        "version": "1.2.0",
        "resolved": "https://unapproved.example/demo/-/demo-1.2.0.tgz",
        "integrity": "sha512-demo",
    }}}, indent=2)),
])
def test_registry_policy_model_dump_conforms_to_report_schema(tmp_path, exclude_none, filename, content):
    (tmp_path / filename).write_text(content, encoding="utf-8")
    report = RiskScanner(str(tmp_path), osv_client=RecordingOSVClient()).scan()
    advisory = next(item for item in report["review_advisories"] if item["code"] == "dependency_registry_policy")
    if filename == "package-lock.json":
        assert advisory["registry_policy"]["occurrences"][0]["field_locations"]
    advisory["registry_policy"] = RegistryPolicyEvidence.model_validate(advisory["registry_policy"]).model_dump(exclude_none=exclude_none)
    jsonschema.validate(report, SCHEMA)
