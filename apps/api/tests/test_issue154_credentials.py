"""SR-004 evidence, fail-closed grading and privacy across public boundaries."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest

from scanners.risk_scanner import llm_reviewer
from scanners.risk_scanner.credentials import find_credentials
from scanners.risk_scanner.llm_candidates import evaluate_llm_candidate
from scanners.risk_scanner.redaction import redact_report, redact_text
from scanners.risk_scanner.reporting import aggregate_findings, build_findings_summary
from scanners.risk_scanner.rules.hardcoded_secrets import run
from scanners.risk_scanner.scanner import RiskScanner
from scanners.risk_scanner.source_context import build_finding_context_bundle
from src.models.packages import ScanReport
from src.routers.trust import _apply_llm_decisions
from src.services.source_snapshots import SourceSnapshotStore
from tests.scanner_mock import MockScanner


FORMATS = [
    ('token = "ghp_' + 'a' * 36 + '"', "github_token", "github-token"),
    ('token = "github_pat_' + 'x' * 30 + '"', "github_token", "github-token"),
    ('key = "sk-proj-' + 'x' * 40 + '"', "api_key", "openai-key"),
    ('key = "ASIA' + 'X' * 16 + '"', "cloud_credential", "aws-access-key"),
    ('key = "AIza' + 'x' * 35 + '"', "cloud_credential", "google-api-key"),
    ('key = "dop_v1_' + 'a' * 64 + '"', "cloud_credential", "digitalocean-token"),
    ('key = "xoxb-1234567890-abcdef"', "token", "slack-token"),
    ('token = "eyJabcdefghijk.abcdefghijk.abcdefghijk"', "token", "jwt"),
    ('url = "postgresql://user:db-password-value@host/database"', "connection_string", "connection-password"),
    ('key = """-----BEGIN PRIVATE KEY-----\nprivate-body-value\n-----END PRIVATE KEY-----"""', "private_key", "private-key"),
    ('-----BEGIN OPENSSH PRIVATE KEY-----\nunclosed-private-body', "private_key", "private-key"),
]


def scan_rule(files):
    scanner = MockScanner(files=files)
    run(scanner)
    return aggregate_findings(scanner.findings)


@pytest.mark.parametrize(("source", "kind", "rule"), FORMATS)
@pytest.mark.parametrize("file", ["src/main.ts", "src/tools/__tests__/fakeNodemwBot.ts", "smoke.test.ts", "README.md"])
def test_credential_formats_never_get_fixture_or_documentation_exemption(source, kind, rule, file):
    findings = scan_rule({file: source})
    assert len(findings) == 1
    finding = findings[0]
    evidence = finding["credential_evidence"]
    assert finding["severity"] == "high"
    assert finding["requires_manual_review"] is True
    assert evidence["classification"] == "credential_format"
    assert kind in evidence["types"]
    assert rule in evidence["rules"]
    assert evidence["matches"][0]["file"] == file
    assert evidence["confidence"] >= 0.95
    for matched in find_credentials(source):
        assert matched.value not in json.dumps(findings)
        assert hashlib.sha256(matched.value.encode()).hexdigest() not in json.dumps(findings)


@pytest.mark.parametrize(("source", "classification", "severity"), [
    ('apiKey = "YOUR_API_KEY_HERE"', "placeholder", "info"),
    ('token = "example-token"', "example", "info"),
    ('password = "test-password"\nexpect(password).toBe("test-password")', "test_fixture", "info"),
    ('password = "test-password"', "unknown", "medium"),
    ('token = "faketoken1234567"', "unknown", "medium"),
    ('password = "let me in please"', "unknown", "medium"),
    ('apiKey = "fAkE2wJ7pS9mL4cR6tY8zN0qV5dX"', "suspected", "high"),
    ('AWS_SECRET_ACCESS_KEY="fAkE2wJ7pS9mL4cR6tY8zN0qV5dX"', "suspected", "high"),
])
def test_content_classification_does_not_depend_on_path(source, classification, severity):
    for file in ["main.py", "tests/fake.py", "docs/examples.md"]:
        finding, = scan_rule({file: source})
        assert finding["credential_evidence"]["classification"] == classification
        assert finding["severity"] == severity
        assert bool(finding.get("requires_manual_review")) == (severity != "info")
        summary = build_findings_summary([finding])
        assert summary["pass_rate"] == {"high": 85.0, "medium": 92.0, "info": 100.0}[severity]


@pytest.mark.parametrize("usage", [
    'fetch("https://example.com", {body: password})',
    'fs.writeFileSync(".env", password)',
])
def test_fixture_does_not_override_usage_elsewhere_in_file(usage):
    source = 'password = "test-password"\nexpect(password).toBe("test-password")\n' + '\n' * 10 + usage
    finding, = scan_rule({"tests/fake.ts": source})
    assert finding["severity"] == "high"
    assert finding["credential_evidence"]["classification"] == "suspected"


def test_repeated_material_is_scored_once_and_all_exposures_are_traceable():
    value = "ambiguous-shared-value"
    files = {"a.py": f'password = "{value}"\nassert password == "{value}"', "b.ts": f'const fixture = "{value}";'}
    findings = scan_rule(files)
    finding, = findings
    assert finding["occurrences"]["count"] == 3
    assert {(item["file"], item["line"]) for item in finding["occurrences"]["items"]} == {("a.py", 1), ("a.py", 2), ("b.ts", 1)}
    assert "cross_file_reuse" in finding["credential_evidence"]["reasons"]
    assert finding["severity"] == "high"
    assert build_findings_summary(findings)["pass_rate"] == 85.0
    assert aggregate_findings(findings)[0]["id"] == finding["id"]
    assert value not in json.dumps(findings)


def test_distinct_credentials_and_scan_scoped_fingerprints():
    findings = scan_rule({"config.py": 'password = "alpha-value"\ntoken = "beta-value"'})
    assert len(findings) == 2
    assert len({f["id"] for f in findings}) == 2
    again = scan_rule({"config.py": 'password = "alpha-value"\ntoken = "beta-value"'})
    assert {f["id"] for f in findings} == {f["id"] for f in again}
    assert {f["credential_evidence"]["fingerprint"] for f in findings}.isdisjoint(
        {f["credential_evidence"]["fingerprint"] for f in again}
    )


@pytest.mark.parametrize("value", [
    "password", "secret", "info", "line", "x", "synthetic", "dependency",
    "registry_policy", "risks_found", "inconclusive", "assessed", "not_queried",
    "hardcoded_secret", "supply_chain",
])
def test_common_password_words_do_not_corrupt_the_report_contract(tmp_path, value):
    (tmp_path / "main.py").write_text(f'password = "{value}"', encoding="utf-8")
    report = RiskScanner(tmp_path).scan()
    ScanReport.model_validate(report)
    finding, = [f for f in report["findings"] if f["rule_id"] == "SR-004"]
    assert finding["credential_evidence"]["types"] == ["password"]
    assert finding["credential_evidence"]["classification"] == "unknown"


@pytest.mark.parametrize("comment", [
    '# assert password == "test-password"', '// expect(password).toBe("test-password")',
    'assert True', 'assert password', 'assert password # == "test-password"',
    'expect(password).toBeTruthy() // toBe("test-password")',
])
def test_comment_or_unrelated_assertion_is_not_fixture_proof(comment):
    finding, = scan_rule({"tests/fake.py": 'password = "test-password"\n' + comment})
    assert finding["severity"] == "medium"


def test_large_exposure_set_retains_count_and_explicit_truncation():
    finding, = scan_rule({"main.py": 'token = "YOUR_TOKEN"\n' * 101})
    assert finding["occurrences"]["count"] == 101
    assert len(finding["occurrences"]["items"]) == 100
    assert finding["credential_evidence"]["truncated"] is True
    assert finding["requires_manual_review"] is True
    assert finding["severity"] == "medium"


@pytest.mark.parametrize("content", [
    'token = process.env.API_TOKEN', 'password = os.environ["PASSWORD"]',
    'const token = suppliedToken;', 'heroku_token', 'digitalocean_key',
    'api_key: str', 'token: string', 'password = None', 'token = null',
    'password == "sample"',
    'api_key = await ctx.elicit()', 'token = value + suffix',
])
def test_names_and_environment_reads_are_not_hardcoded_credentials(content):
    assert not scan_rule({"main.ts": content})


def test_type_annotated_literal_is_detected():
    finding, = scan_rule({"main.py": 'password: str = "unverified-value"'})
    assert finding["credential_evidence"]["classification"] == "unknown"


def test_generic_token_word_cannot_corrupt_rule_identity(tmp_path):
    (tmp_path / "README.md").write_text('Authorization: Bearer token', encoding="utf-8")
    report = RiskScanner(tmp_path).scan()
    finding, = [f for f in report["findings"] if f["rule_id"] == "SR-004"]
    assert finding["credential_evidence"]["rules"] == ["bearer-token"]


def test_real_scan_api_schema_source_preview_and_llm_privacy(tmp_path, monkeypatch, caplog):
    value = "Unverified#LocalPassword!42"
    files = {
        "config.json": json.dumps({"dbPassword": value}),
        "README.md": f'password = "{value}"',
        "main.py": f'print("{value}")\n# safe context\n',
    }
    for file, content in files.items():
        (tmp_path / file).write_text(content, encoding="utf-8")
    report = RiskScanner(tmp_path).scan()
    credentials = [f for f in report["findings"] if f["rule_id"] == "SR-004"]
    finding, = credentials
    assert finding["severity"] == "high"
    assert finding["occurrences"]["count"] == 3
    assert finding["credential_evidence"]["matches"][1]["field"] == "dbPassword"
    assert "downgraded" not in finding
    schema = json.loads((Path(__file__).parents[3] / "packages/schema/scan-report.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(report, schema)
    serialized = ScanReport.model_validate(report).model_dump_json()
    assert value not in serialized
    assert "credential_evidence" in serialized
    assert value not in json.dumps(redact_report(report))

    store = SourceSnapshotStore(tmp_path / "snapshots")
    snapshot = store.save(files)
    preview = store.load_context(snapshot["snapshot_id"], "main.py")
    assert preview and value not in preview["content"]
    other_finding = {"id": "stable-context-id", "rule_id": "SR-001", "severity": "high", "category": "prompt_injection", "title": "Review", "requires_llm_validation": True, "location": {"file": "main.py", "line": 1}}
    contexts, audit = build_finding_context_bundle([other_finding], files)
    prompts = []

    def judge(prompt):
        prompts.append(prompt)
        return {"is_vulnerability": False, "harmful": False, "impact": "unknown", "intent": "benign", "confidence": 0.4, "evidence_sufficient": False, "missing_context": ["validity unknown"], "explanation": "Needs manual review"}

    monkeypatch.setattr(llm_reviewer, "_call_llm", judge)
    llm_reviewer.run_llm_review([other_finding], contexts, {"dbPassword": value}, context_audit=audit)
    assert prompts
    assert value not in json.dumps(prompts)
    assert "stable-context-id" in json.dumps(prompts)
    assert value not in caplog.text


def test_llm_cannot_override_credentials_even_with_legacy_opt_in():
    finding, = scan_rule({"README.md": 'token = "ghp_' + 'x' * 36 + '"'})
    finding.update(llm_adjudication_eligible=True, requires_llm_validation=True, llm_review_exempt=False)
    original = deepcopy(finding)
    assert not evaluate_llm_candidate(finding).eligible
    _apply_llm_decisions([finding], {"labels": {finding["id"]: "llm:likely-benign"}, "decisions": {finding["id"]: {"verdict": "likely_benign", "impact": "none", "confidence": 1, "rounds": 3, "evidence_sufficient": True}}})
    assert finding == original


@pytest.mark.parametrize("source", [
    '{"password": "a password with spaces"}',
    'DB_PASSWORD="a password with spaces"',
    'clientSecret = "a password with spaces"',
])
def test_quoted_json_env_and_camel_case_redaction(source):
    value = "a password with spaces"
    redacted = redact_text(source + '\nprint("' + value + '")')
    assert value not in redacted
    assert redact_text(redacted) == redacted


def test_cross_file_redaction_cache_tracks_scope_changes(tmp_path, monkeypatch):
    from src.services import source_snapshots
    original = source_snapshots.credential_redactions
    calls = []

    def recognize(contents):
        calls.append(True)
        return original(contents)

    monkeypatch.setattr(source_snapshots, "credential_redactions", recognize)
    value = "previously-unknown-value"
    store = SourceSnapshotStore(tmp_path)
    snapshot = store.save({"main.py": f'print("{value}")', "config.py": "safe = True"})
    identity = snapshot["snapshot_id"]
    assert value in store.load_context(identity, "main.py")["content"]
    store.load_context(identity, "main.py")
    assert len(calls) == 1
    # Model a cross-worker replacement without trusting stale metadata hashes.
    path = tmp_path / f"{identity}.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["files"]["config.py"] = f'password = "{value}"'
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert value not in store.load_context(identity, "main.py")["content"]
    assert len(calls) == 2


def test_rule_error_logs_and_report_never_expose_payload(tmp_path, monkeypatch, caplog):
    from scanners.risk_scanner.rules import hardcoded_secrets
    value = "exception-only-password-value"
    (tmp_path / "config.py").write_text(f'password = "{value}"', encoding="utf-8")

    def fail(_scanner):
        raise ValueError(value)

    monkeypatch.setattr(hardcoded_secrets, "run", fail)
    report = RiskScanner(tmp_path).scan()
    assert value not in json.dumps(report)
    assert value not in caplog.text
    assert report["scan_status"]["state"] == "partial"


def test_llm_orchestration_redacts_metadata_and_failure_output(monkeypatch, capsys):
    from src.routers import trust
    value = "metadata-reused-password-value"
    scanner = SimpleNamespace(
        _file_contents={"config.py": f'password = "{value}"', "main.py": f'print("{value}")'},
        _package_metadata={"description": value},
    )
    findings = [{"id": "stable-finding", "rule_id": "SR-001", "severity": "high", "category": "prompt_injection", "title": "Review", "description": value,
                 "requires_llm_validation": True, "location": {"file": "main.py", "line": 1}}]
    inputs = []

    def review(**kwargs):
        inputs.append(kwargs)
        raise RuntimeError(value)

    monkeypatch.setattr(trust, "_load_llm_reviewer", lambda: SimpleNamespace(run_llm_review=review))
    result = trust._run_llm_review_with_fallback(findings, scanner)
    assert inputs
    assert value not in json.dumps(inputs, default=str)
    assert value not in json.dumps(result)
    assert value not in capsys.readouterr().out
    assert result["status"] == "call_failed"
    assert findings[0]["id"] == "stable-finding"
    assert findings[0]["requires_manual_review"] is True
