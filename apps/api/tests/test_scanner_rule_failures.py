from types import SimpleNamespace

from scanners.risk_scanner.rule_runner import RuleRunner, RuleSpec


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
            scanner._add_finding(rule_id="SR-OK", severity="high", category="test", title="kept")
        return SimpleNamespace(run=good)

    monkeypatch.setattr("scanners.risk_scanner.rule_runner.importlib.import_module", fake_import)
    scanner = SimpleNamespace(findings=[])
    scanner._add_finding = lambda **kwargs: scanner.findings.append(kwargs)
    results = RuleRunner((RuleSpec("SR-BAD", "bad"), RuleSpec("SR-GOOD", "good"))).run_all(scanner)

    assert calls == ["bad", "good"]
    assert [r.status for r in results] == ["failed", "succeeded"]
    assert results[0].error_type == "ValueError"
    assert "C:\\secret" not in (results[0].error_message or "")
    assert len(scanner.findings) == 1
