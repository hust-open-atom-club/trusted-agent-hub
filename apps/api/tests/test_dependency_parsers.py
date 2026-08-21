from scanners.risk_scanner.dependency_parsers import parse_dependencies


def test_dependency_parsers_normalize_manifest_and_lockfiles():
    records = parse_dependencies({
        "package.json": '{"dependencies":{"lodash":"^4.17.0"}}',
        "package-lock.json": '{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21","integrity":"sha512-x"}}}',
        "requirements.txt": "requests==2.31.0\nflask\n",
        "Cargo.lock": '[[package]]\nname = "serde"\nversion = "1.0.0"\n',
    })
    assert any(r.name == "lodash" and r.ecosystem == "npm" for r in records)
    assert any(r.name == "flask" and r.version is None for r in records)
    assert any(r.name == "serde" and r.ecosystem == "crates.io" for r in records)


def test_dependency_scan_reports_osv_query_failures(tmp_path):
    from scanners.risk_scanner.scanner import RiskScanner

    (tmp_path / "package.json").write_text(
        '{"name":"demo","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}',
        encoding="utf-8",
    )
    scanner = RiskScanner(tmp_path)

    class FailedClient:
        max_queries = 10
        queried = 1

        def query(self, dependency):
            from scanners.risk_scanner.dependency_parsers.osv_client import OSVQueryResult
            return OSVQueryResult([], "TimeoutError")

    scanner.osv_client = FailedClient()
    report = scanner.scan()
    assert report["dependency_scan"]["status"] == "partial"
    assert report["dependency_scan"]["dependencies_found"] == 1
    assert report["dependency_scan"]["query_failures"] == 1
    assert report["scan_status"]["state"] == "partial"


def test_osv_query_limit_comes_from_scan_policy(tmp_path):
    from scanners.risk_scanner.policy import ScanPolicy
    from scanners.risk_scanner.scanner import RiskScanner

    scanner = RiskScanner(tmp_path, policy=ScanPolicy(max_osv_queries=3))

    assert scanner.osv_client.max_queries == 3
    assert scanner.policy.as_dict()["max_osv_queries"] == 3
