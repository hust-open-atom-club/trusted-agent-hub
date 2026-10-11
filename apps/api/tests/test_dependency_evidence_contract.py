"""Dependency evidence must obey length and uniqueness contracts end to end."""

import json

import jsonschema
import pytest
from pydantic import ValidationError

from scanners.risk_scanner.dependency_parsers.models import DependencyRecord
from scanners.risk_scanner.rules import supply_chain
from scanners.risk_scanner.scanner import RiskScanner
from src.models.packages import FindingOccurrence, RegistryPolicyEvidence, RegistryPolicyOccurrence
from tests.test_dependency_scope_regressions import SCHEMA, RecordingOSVClient


REGISTRY_SCHEMA = SCHEMA["properties"]["review_advisories"]["items"]["properties"]["registry_policy"]
QUERY_OCCURRENCE_SCHEMA = SCHEMA["properties"]["dependency_scan"]["properties"]["query_results"]["items"]["properties"]["occurrences"]["items"]
MODEL_CASES = [
    (FindingOccurrence, {"file": "manifest.json"}, {"$ref": "#/$defs/evidence_location"}),
    (RegistryPolicyOccurrence, {
        "file": "manifest.json", "scope": "runtime", "usage": "registry_api",
        "resolved_url": "https://unapproved.example/",
    }, REGISTRY_SCHEMA["properties"]["occurrences"]["items"]),
]


@pytest.mark.parametrize("model,payload,schema", MODEL_CASES)
@pytest.mark.parametrize("invalid", [
    {"ecosystem": "x" * 65},
    {"scopes": ["runtime", "runtime"]},
    {"reachability": ["direct", "direct"]},
])
def test_api_rejects_evidence_that_violates_schema(model, payload, schema, invalid):
    with pytest.raises(ValidationError):
        model.model_validate({**payload, **invalid})


@pytest.mark.parametrize("model,payload,schema", MODEL_CASES)
def test_api_boundary_values_preserve_order_and_round_trip(model, payload, schema):
    value = {
        **payload, "ecosystem": "x" * 64,
        "scopes": ["dev", "runtime"], "reachability": ["direct", "x" * 256],
    }
    result = model.model_validate(value).model_dump(mode="json")
    assert all(result[field] == value[field] for field in ("ecosystem", "scopes", "reachability"))
    jsonschema.validate(result, {"$defs": SCHEMA["$defs"], **schema})
    properties = model.model_json_schema()["properties"]
    assert properties["scopes"]["uniqueItems"] is True
    assert properties["reachability"]["uniqueItems"] is True


@pytest.mark.parametrize("length", [64, 65, 300])
def test_unknown_manifest_ecosystem_keeps_report_valid_and_source_identifiable(tmp_path, length):
    ecosystem = "vendor/" + "x" * (length - len("vendor/"))
    manifest = {"name": "demo", "dependencies": {ecosystem: [{
        "name": "helper", "version": "1.0.0", "registry": "http://unapproved.example/",
    }]}}
    records = supply_chain._manifest_records(manifest)
    assert records[0].ecosystem == ecosystem
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    client = RecordingOSVClient()
    report = RiskScanner(str(tmp_path), osv_client=client).scan()
    jsonschema.validate(report, SCHEMA)
    advisory = next(a for a in report["review_advisories"] if a.get("registry_policy"))
    occurrence = advisory["registry_policy"]["occurrences"][0]
    assert len(occurrence["ecosystem"]) <= 64
    assert occurrence["source_ref"] == "#/dependencies/" + ecosystem.replace("/", "~1") + "/0"
    advisory["registry_policy"] = RegistryPolicyEvidence.model_validate(advisory["registry_policy"]).model_dump()
    jsonschema.validate(report, SCHEMA)
    assert client.calls == []
    assert report["dependency_scan"]["non_osv_manifest_dependencies"]["categories"][ecosystem] == 1


@pytest.mark.parametrize("surface", ["location", "finding_location", "query_occurrence"])
def test_every_dependency_evidence_projection_bounds_ecosystem(surface):
    record = DependencyRecord("helper", "1.0.0", "vendor-" + "x" * 100, True, "manifest.json")
    if surface == "location":
        value = supply_chain._dependency_location(record)
    elif surface == "finding_location":
        value = supply_chain._dependency_finding_location([record], [supply_chain._dependency_location(record)])
    else:
        value = supply_chain._dependency_occurrence(record)
    schema = QUERY_OCCURRENCE_SCHEMA if surface == "query_occurrence" else {"$ref": "#/$defs/evidence_location"}
    jsonschema.validate(value, {"$defs": SCHEMA["$defs"], **schema})
    assert len(value["ecosystem"]) <= 64
