"""Protocol collisions and resource bounds at the redaction trust boundaries."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from typing import get_args
from unittest.mock import Mock

import jsonschema
import pytest

from scanners.risk_scanner import credentials, redaction
from scanners.risk_scanner.credentials import (
    MAX_LITERAL_CHARS, MAX_LITERAL_VALUES, CredentialLimitExceeded,
    literal_pattern, mask_literals,
)
from scanners.risk_scanner.redaction import credential_redactions, redact_report, redact_value
from scanners.risk_scanner.reporting import aggregate_findings
from scanners.risk_scanner.scanner import RiskScanner
from src.models.packages import EVIDENCE_TYPE, ScanFinding, ScanReport
from src.routers import trust
from src.services import source_snapshots


ROOT = Path(__file__).resolve().parents[3]
SCHEMA = json.loads((ROOT / "packages/schema/scan-report.schema.json").read_text(encoding="utf-8"))


def enum_paths(node, path=()):
    if "$ref" in node:
        referenced = SCHEMA
        for part in node["$ref"].removeprefix("#/").split("/"):
            referenced = referenced[part.replace("~1", "/").replace("~0", "~")]
        yield from enum_paths(referenced, path)
    for value in node.get("enum", []) + node.get("x-redaction-public-values", []):
        if isinstance(value, str):
            yield pytest.param(path, value, id=".".join(p or "[]" for p in path) + "=" + value)
    for key, child in node.get("properties", {}).items():
        yield from enum_paths(child, (*path, key))
    if isinstance(node.get("items"), dict):
        yield from enum_paths(node["items"], (*path, None))
    if isinstance(node.get("additionalProperties"), dict):
        yield from enum_paths(node["additionalProperties"], (*path, "custom-key"))
    for keyword in ("allOf", "anyOf", "oneOf"):
        for child in node.get(keyword, []):
            yield from enum_paths(child, path)


@pytest.mark.parametrize(("path", "value"), list(enum_paths(SCHEMA)))
def test_every_schema_enum_survives_a_matching_credential(path, value):
    document = value
    for key in reversed(path):
        document = [document] if key is None else {key: document}
    matcher = credential_redactions([f'password = "{value}"'])
    assert redact_report(document, literal_redactions=matcher) == document
    # The same vocabulary is still private when it occurs in free source text.
    assert redact_report({"findings": [{"description": value}]}, literal_redactions=matcher) == {
        "findings": [{"description": "[REDACTED]"}],
    }


def test_metadata_cannot_bypass_redaction_by_copying_protocol_field_names():
    value = {"evidence_type": "synthetic", "state": "complete", "types": ["password"],
             "nested": {"classification": "unknown", "rules": ["bearer-token"]}}
    matcher = literal_pattern(["synthetic", "complete", "password", "unknown", "bearer-token"])
    assert redact_value(value, literal_redactions=matcher) == {
        "evidence_type": "[REDACTED]", "state": "[REDACTED]", "types": ["[REDACTED]"],
        "nested": {"classification": "[REDACTED]", "rules": ["[REDACTED]"]},
    }


def test_new_contract_enums_refs_and_nullable_constants_need_no_redactor_allowlist(monkeypatch):
    schema = deepcopy(SCHEMA)
    schema["$defs"]["future_enum"] = {"enum": ["future_protocol_value"]}
    schema["properties"]["future"] = {"anyOf": [
        {"type": "null"},
        {"type": "object", "properties": {
            "value": {"$ref": "#/$defs/future_enum"},
            "marker": {"const": "new_protocol_constant"},
        }},
    ]}
    monkeypatch.setattr(redaction, "_report_schema", lambda: schema)
    document = {"future": {"value": "future_protocol_value", "marker": "new_protocol_constant"}}
    matcher = literal_pattern(document["future"].values())
    assert redact_report(document, literal_redactions=matcher) == document


def test_open_protocol_code_fields_do_not_exempt_unknown_source_values():
    value = "source-authored-secret"
    document = {"findings": [{"credential_evidence": {"rules": ["bearer-token", value], "reasons": [value]}}]}
    result = redact_report(document, literal_redactions=literal_pattern([value]))
    evidence = result["findings"][0]["credential_evidence"]
    assert evidence["rules"] == ["bearer-token", "[REDACTED]"]
    assert evidence["reasons"] == ["[REDACTED]"]


@pytest.mark.parametrize("value", get_args(EVIDENCE_TYPE))
def test_llm_review_preserves_aggregated_evidence_types(monkeypatch, value):
    scanner = SimpleNamespace(_file_contents={"main.py": f'password = "{value}"'}, _package_metadata={"description": value})
    findings = aggregate_findings([{
        "id": "finding-123456789abc", "rule_id": "SR-001", "severity": "high",
        "category": "prompt_injection", "title": "Review", "description": value,
        "requires_llm_validation": True, "location": {"file": "main.py", "line": 1},
    }])
    findings[0]["evidence_type"] = value
    for hit in findings[0]["detector_hits"]:
        hit["evidence_type"] = value
    inputs = []

    def review(**kwargs):
        inputs.append(deepcopy(kwargs))
        return {"status": "completed", "labels": {}, "decisions": {}}

    monkeypatch.setattr(trust, "_load_llm_reviewer", lambda: SimpleNamespace(run_llm_review=review))
    trust._run_llm_review_with_fallback(findings, scanner)
    assert inputs
    submitted = inputs[0]["findings"][0]
    assert submitted["evidence_type"] == value
    assert submitted["detector_hits"][0]["evidence_type"] == value
    assert submitted["description"] == "[REDACTED]"
    assert inputs[0]["manifest"]["description"] == "[REDACTED]"
    ScanFinding.model_validate(findings[0])


def test_literal_count_limit_stops_consumption_before_compile(monkeypatch):
    def values():
        for index in range(MAX_LITERAL_VALUES + 1):
            yield f"value_{index}"
        pytest.fail("consumed values beyond the budget")

    compile_pattern = Mock(side_effect=AssertionError("must not compile an oversized alternation"))
    monkeypatch.setattr(credentials.re, "compile", compile_pattern)
    matcher = literal_pattern(values())
    assert matcher.limited
    assert matcher.pattern is None
    compile_pattern.assert_not_called()
    assert "value_999999" not in mask_literals('print("value_999999")', matcher)
    with pytest.raises(CredentialLimitExceeded):
        list(matcher.finditer("source"))


@pytest.mark.parametrize("values", [["x" * (MAX_LITERAL_CHARS + 1)], ["x" * (MAX_LITERAL_CHARS // 2), "y" * (MAX_LITERAL_CHARS // 2 + 1)]])
def test_literal_character_limit_masks_omitted_values_and_preserves_lines(values):
    matcher = literal_pattern(values)
    assert matcher.limited
    for text in ["first\nsecond\nlast", "first\nsecond\n", "", "unseen-secret"]:
        masked = mask_literals(text, matcher)
        assert len(masked.splitlines()) == len(text.splitlines())
        assert not text or text not in masked


def test_bounded_matcher_keeps_longest_matches_word_boundaries_and_multiline_values():
    matcher = literal_pattern(["abc"] * (MAX_LITERAL_VALUES + 1) + ["abc-def", "line one\nline two", "密钥"])
    assert not matcher.limited
    source = "xabc abc_def abc-def abc 密钥 密钥词 line one\nline two"
    assert [match[0] for match in matcher.finditer(source)] == ["abc-def", "abc", "密钥", "line one\nline two"]
    assert mask_literals(source, matcher) == "xabc abc_def [REDACTED] [REDACTED] [REDACTED] 密钥词 [REDACTED]\n[REDACTED]"


def test_twenty_thousand_literals_fail_closed_before_sr004_grouping(monkeypatch):
    # A subprocess timeout bounds regressions without depending on subsecond timings.
    monkeypatch.delenv("PYTHONPATH", raising=False)
    subprocess.run([sys.executable, "-c", "\n".join([
        "from types import SimpleNamespace",
        "from scanners.risk_scanner.credentials import CredentialLimitExceeded, mask_literals",
        "from scanners.risk_scanner.redaction import credential_redactions",
        "from scanners.risk_scanner.rules import hardcoded_secrets",
        "source = '\\n'.join('password = ' + repr('unique_' + str(i)) for i in range(20000))",
        "matcher = credential_redactions([source])",
        "assert matcher.limited and matcher.pattern is None",
        "assert 'unique_19999' not in mask_literals('unique_19999', matcher)",
        "scanner = SimpleNamespace(scanned_files=['config.env'], _read_file_content=lambda _: source, get_credential_redactions=lambda: matcher)",
        "hardcoded_secrets.find_credentials = lambda _: (_ for _ in ()).throw(AssertionError('grouping must not run'))",
        "try:",
        "    hardcoded_secrets.run(scanner)",
        "except CredentialLimitExceeded:",
        "    pass",
        "else:",
        "    raise AssertionError('oversized analysis did not stop')",
    ])], check=True, timeout=10, capture_output=True, cwd=ROOT)


def test_overflow_scan_report_preview_and_llm_fail_closed(tmp_path, monkeypatch):
    source = "\n".join(f'password = "unique_{i}"' for i in range(MAX_LITERAL_VALUES + 1))
    files = {"config.env": source, "main.py": 'print("unique_512")'}
    for name, content in files.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    scanner = RiskScanner(tmp_path)
    report = scanner.scan()
    ScanReport.model_validate(report)
    jsonschema.validate(report, SCHEMA)
    assert report["scan_status"]["state"] == "partial"
    assert report["scan_status"]["conclusion"] == "inconclusive"
    assert "credential_literal_limit_exceeded" in report["scan_limits"]["exceeded"]
    serialized = json.dumps(report)
    assert all(f"unique_{index}" not in serialized for index in range(MAX_LITERAL_VALUES + 1))
    store = source_snapshots.SourceSnapshotStore(tmp_path / "snapshots")
    snapshot_id = store.save(files)["snapshot_id"]
    assert "unique_512" not in store.load_context(snapshot_id, "main.py")["content"]
    reviewer = Mock()
    monkeypatch.setattr(trust, "_load_llm_reviewer", lambda: reviewer)
    findings = [{"id": "finding-123456789abc", "rule_id": "SR-001", "severity": "high", "category": "prompt_injection", "title": "Review", "description": "unique_512", "requires_llm_validation": True, "location": {"file": "main.py", "line": 1}, "evidence_type": "source"}]
    trust._run_llm_review_with_fallback(findings, scanner)
    reviewer.run_llm_review.assert_not_called()
    assert findings[0]["requires_manual_review"] is True
    assert "unique_512" not in json.dumps(findings)
    ScanFinding.model_validate(findings[0])


def test_scanner_matcher_is_reused_and_resets_on_rescan(tmp_path, monkeypatch):
    from scanners.risk_scanner import scanner as scanner_module
    recognize = Mock(wraps=scanner_module.credential_redactions)
    monkeypatch.setattr(scanner_module, "credential_redactions", recognize)
    (tmp_path / "main.py").write_text('password = "old-value"', encoding="utf-8")
    scanner = RiskScanner(tmp_path)
    scanner.scan()
    matcher = scanner.get_credential_redactions()
    assert scanner.get_credential_redactions() is matcher
    recognize.assert_called_once()
    (tmp_path / "main.py").write_text('password = "new-value"', encoding="utf-8")
    scanner.scan()
    assert recognize.call_count == 2
    assert scanner.get_credential_redactions() is not matcher
    assert mask_literals("old-value new-value", scanner.get_credential_redactions()) == "old-value [REDACTED]"


def test_preview_reuses_matcher_between_files_in_same_snapshot(tmp_path, monkeypatch):
    recognize = Mock(wraps=source_snapshots.credential_redactions)
    monkeypatch.setattr(source_snapshots, "credential_redactions", recognize)
    store = source_snapshots.SourceSnapshotStore(tmp_path)
    identity = store.save({"config.py": 'password = "shared-value"', "main.py": 'print("shared-value")'})["snapshot_id"]
    for path in ["config.py", "main.py"]:
        assert "shared-value" not in store.load_context(identity, path)["content"]
    recognize.assert_called_once()
