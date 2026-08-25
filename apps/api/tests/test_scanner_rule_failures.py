from types import SimpleNamespace

from packages.schema.constants import FINDING_CATEGORY_POLICY
from scanners.risk_scanner.rule_runner import RULE_SPECS, RuleRunner, RuleSpec


def test_rule_failure_isolated_and_later_rule_runs(monkeypatch):
    calls: list[str] = []

    def fake_import(name: str):
        if name.endswith("bad"):
            def bad(scanner):
                calls.append("bad")
                raise ValueError("invalid structure at C:\\secret\\token")
            return SimpleNamespace(run=bad)

        def good(scanner):
            calls.append("good")
            scanner._add_finding(
                rule_id="SR-OK",
                severity="high",
                category="metadata_quality",
                title="kept",
            )
        return SimpleNamespace(run=good)

    monkeypatch.setattr("scanners.risk_scanner.rule_runner.importlib.import_module", fake_import)
    scanner = SimpleNamespace(findings=[])
    scanner._add_finding = lambda **kwargs: scanner.findings.append(kwargs)
    results = RuleRunner((
        RuleSpec("SR-BAD", "bad", categories=frozenset({"metadata_quality"})),
        RuleSpec("SR-GOOD", "good", categories=frozenset({"metadata_quality"})),
    )).run_all(scanner)

    assert calls == ["bad", "good"]
    assert [r.status for r in results] == ["failed", "succeeded"]
    assert results[0].error_type == "ValueError"
    assert "C:\\secret" not in (results[0].error_message or "")
    assert len(scanner.findings) == 1


def test_rule_category_mismatch_is_reported_as_rule_failure(monkeypatch):
    def fake_import(name: str):
        def run(scanner):
            scanner._add_finding(
                rule_id="SR-TEST",
                severity="high",
                category="metadata_quality",
                title="unexpected category",
            )
        return SimpleNamespace(run=run)

    monkeypatch.setattr("scanners.risk_scanner.rule_runner.importlib.import_module", fake_import)
    scanner = SimpleNamespace(findings=[])
    scanner._add_finding = lambda **kwargs: scanner.findings.append(kwargs)
    result = RuleRunner((
        RuleSpec(
            "SR-TEST",
            "test",
            categories=frozenset({"prompt_injection"}),
        ),
    )).run_all(scanner)

    assert result[0].status == "failed"
    assert result[0].error_type == "ValueError"
    assert "metadata_quality" in (result[0].error_message or "")


def test_builtin_rules_declare_categories_known_to_shared_policy():
    for spec in RULE_SPECS:
        assert spec.categories is not None
        assert spec.categories <= FINDING_CATEGORY_POLICY.keys()
