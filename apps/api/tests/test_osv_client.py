from __future__ import annotations

import json
import sqlite3
import threading
import urllib.error
from datetime import date
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jsonschema
import pytest

from scanners.risk_scanner.dependency_parsers import osv_client as osv_client_module
from scanners.risk_scanner.dependency_parsers.models import DependencyRecord
from scanners.risk_scanner.dependency_parsers.osv_client import (
    OSVClient,
    OSVHTTPResponse,
    OSVQueryResult,
    dependency_coordinate,
)
from scanners.risk_scanner.registry_policy import (
    RegistryClassification,
    RegistryEntry,
    RegistryPolicy,
)
from scanners.risk_scanner.scanner import RiskScanner
from scanners.risk_scanner.policy import ScanPolicy
from scanners.risk_scanner.dependency_coverage import (
    MAX_OSV_QUERY_RESULTS,
    MAX_OSV_QUERY_RESULT_OCCURRENCES,
    MAX_OSV_QUERY_RESULTS_BYTES,
)


_REPORT_SCHEMA = json.loads(
    (Path(__file__).resolve().parents[3] / "packages/schema/scan-report.schema.json")
    .read_text(encoding="utf-8")
)


def _dependency(
    name: str,
    version: str = "1.0.0",
    *,
    ecosystem: str = "npm",
    source_file: str = "package-lock.json",
    registry: str | None = "https://registry.npmjs.org/",
) -> DependencyRecord:
    return DependencyRecord(
        name=name,
        version=version,
        ecosystem=ecosystem,
        direct=True,
        source_file=source_file,
        registry=registry,
        scope="runtime",
        source_ref=f"#/dependencies/{name}",
        line=1,
    )


def _success_response(payload: bytes, _timeout: float) -> OSVHTTPResponse:
    queries = json.loads(payload)["queries"]
    return OSVHTTPResponse(200, json.dumps({"results": [{} for _ in queries]}).encode(), {})


def test_constructor_initializes_counters_without_dispatching_reset_override(
    tmp_path: Path,
) -> None:
    reset_calls: list[str] = []

    class CustomResetClient(OSVClient):
        def reset_scan_state(self) -> None:
            super().reset_scan_state()
            reset_calls.append("reset")

    client = CustomResetClient(requester=_success_response, max_queries=1)

    result = client.query(_dependency("example"))

    assert result.status == "succeeded"
    assert client.queried == client.request_count == 1
    assert client.failures == client.rate_limited == client.skipped == 0
    assert client.cache_hits == 0
    assert client.limit_reached is False
    assert reset_calls == []

    limited = client.query(_dependency("another-package"))
    assert limited.status == "not_queried"
    assert client.limit_reached is True
    scanner = RiskScanner(tmp_path, osv_client=client)

    for scan_number in range(1, 3):
        report = scanner.scan()

        assert report["dependency_scan"]["status"] == "complete"
        assert client.queried == client.request_count == 0
        assert client.failures == client.rate_limited == client.skipped == 0
        assert client.cache_hits == 0
        assert client.limit_reached is False
        assert reset_calls == ["reset"] * scan_number


def test_queries_all_396_unique_dependencies_in_bounded_batches() -> None:
    batch_sizes: list[int] = []

    def requester(payload: bytes, timeout: float) -> OSVHTTPResponse:
        assert timeout == 2
        queries = json.loads(payload)["queries"]
        batch_sizes.append(len(queries))
        return OSVHTTPResponse(
            200,
            json.dumps({"results": [{} for _ in queries]}).encode(),
            {},
        )

    dependencies = [_dependency(f"package-{index}") for index in range(396)]
    client = OSVClient(
        requester=requester,
        timeout=2,
        max_queries=5000,
        batch_size=100,
        max_concurrency=4,
    )

    results = client.query_many(dependencies)

    assert len(results) == 396
    assert all(result.status == "succeeded" for result in results.values())
    assert client.queried == 396
    assert client.request_count == 4
    assert sorted(batch_sizes) == [96, 100, 100, 100]


@pytest.mark.parametrize("batch_size", [1, 2])
def test_repeated_scans_get_independent_results_with_cache_disabled(
    tmp_path: Path, batch_size: int,
) -> None:
    (tmp_path / "requirements.txt").write_text(
        "--index-url https://pypi.org/simple/\n"
        "control-package==1.0.0\nrepeat-package==1.0.0\n",
        encoding="utf-8",
    )
    vulnerable = True

    def requester(payload: bytes, _timeout: float) -> OSVHTTPResponse:
        results = [
            {"vulns": [{"id": "OSV-REPEAT-1"}]}
            if vulnerable and query["package"]["name"] == "repeat-package"
            else {}
            for query in json.loads(payload)["queries"]
        ]
        return OSVHTTPResponse(200, json.dumps({"results": results}).encode(), {})

    client = OSVClient(
        requester=requester, max_queries=2, cache_ttl=0, batch_size=batch_size,
    )
    scanner = RiskScanner(tmp_path, osv_client=client)

    first = scanner.scan()
    vulnerable = False
    second = scanner.scan()

    assert first["dependency_check"]["known_vulnerabilities"] == 1
    assert {
        result["package_name"]: result["vulnerability_count"]
        for result in first["dependency_scan"]["query_results"]
    } == {"control-package": 0, "repeat-package": 1}
    assert second["dependency_check"]["known_vulnerabilities"] == 0
    assert not any(
        finding.get("source_kind") == "osv_advisory"
        for finding in second["findings"]
    )
    for report in (first, second):
        assert report["dependency_scan"]["status"] == "complete"
        assert report["dependency_scan"]["queried"] == 2
        assert report["dependency_scan"]["provider_requests"] == 2 // batch_size
        assert report["dependency_scan"]["cache_hits"] == 0
        jsonschema.validate(report, _REPORT_SCHEMA)
    assert client.queried == 2
    assert client.request_count == 2 // batch_size
    assert client.failures == client.rate_limited == client.skipped == 0
    assert client.limit_reached is False


def test_repeated_scans_reset_osv_limit_state_and_reuse_cache(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "--index-url https://pypi.org/simple/\nalpha==1.0.0\nbeta==1.0.0\n",
        encoding="utf-8",
    )
    sent: list[str] = []

    def requester(payload: bytes, timeout: float) -> OSVHTTPResponse:
        sent.extend(
            query["package"]["name"] for query in json.loads(payload)["queries"]
        )
        return _success_response(payload, timeout)

    client = OSVClient(requester=requester, max_queries=1)
    scanner = RiskScanner(tmp_path, osv_client=client)

    first = scanner.scan()

    assert first["dependency_scan"]["status"] == "partial"
    assert first["dependency_scan"]["succeeded"] == 1
    assert first["dependency_scan"]["skipped"] == 1
    assert first["dependency_scan"]["remaining"] == 1
    assert first["dependency_check"]["known_vulnerabilities"] is None
    assert client.skipped == 1
    assert client.limit_reached is True

    cached = client.query(_dependency("alpha", ecosystem="PyPI"))
    assert cached.from_cache is True
    assert client.cache_hits == 1

    second = scanner.scan()

    assert sent == ["alpha", "beta"]
    assert second["dependency_scan"]["status"] == "complete"
    assert second["dependency_scan"]["succeeded"] == 2
    assert second["dependency_scan"]["skipped"] == 0
    assert second["dependency_scan"]["remaining"] == 0
    assert second["dependency_scan"]["provider_requests"] == 1
    assert second["dependency_scan"]["cache_hits"] == 1
    assert second["dependency_scan"]["failure_reasons"] == {}
    assert second["dependency_check"]["known_vulnerabilities"] == 0
    cached_result, fresh_result = second["dependency_scan"]["query_results"]
    assert cached_result["cache_source"] == "memory"
    assert cached_result["attempts"] == 0
    assert fresh_result["from_cache"] is False
    assert client.queried == client.request_count == client.cache_hits == 1
    assert client.failures == client.rate_limited == client.skipped == 0
    assert client.limit_reached is False
    for report in (first, second):
        jsonschema.validate(report, _REPORT_SCHEMA)


@pytest.mark.parametrize(
    ("response_status", "counter", "reason"),
    [(503, "failed", "provider_server_error"), (429, "rate_limited", "rate_limited")],
)
@pytest.mark.parametrize("restart_client", [False, True])
def test_repeated_scans_resume_386_failed_osv_queries(
    tmp_path: Path, response_status: int, counter: str, reason: str,
    restart_client: bool,
) -> None:
    names = [f"package-{index:03d}" for index in range(396)]
    target = tmp_path / "package"
    target.mkdir()
    (target / "requirements.txt").write_text(
        "--index-url https://pypi.org/simple/\n"
        + "\n".join(f"{name}==1.0.0" for name in names)
        + "\n",
        encoding="utf-8",
    )
    provider_available = False
    sent: list[str] = []

    def requester(payload: bytes, timeout: float) -> OSVHTTPResponse:
        batch_names = [
            query["package"]["name"] for query in json.loads(payload)["queries"]
        ]
        sent.extend(batch_names)
        if not provider_available and batch_names[0] >= names[10]:
            return OSVHTTPResponse(response_status, b"{}", {})
        return _success_response(payload, timeout)

    cache_path = tmp_path / "osv.sqlite3"
    client_options = dict(
        requester=requester, max_queries=396, batch_size=10,
        max_concurrency=1, max_retries=0, cache_path=cache_path,
    )
    client = OSVClient(**client_options)
    scanner = RiskScanner(target, osv_client=client)

    first = scanner.scan()

    assert sent == names
    assert first["dependency_scan"]["status"] == "partial"
    assert first["dependency_scan"]["total_unique_dependencies"] == 396
    assert first["dependency_scan"]["queried"] == 396
    assert first["dependency_scan"]["succeeded"] == 10
    assert first["dependency_scan"][counter] == 386
    assert first["dependency_scan"]["query_failures"] == 386
    assert first["dependency_scan"]["remaining"] == 386
    assert first["dependency_scan"]["provider_requests"] == 40
    assert first["dependency_scan"]["failure_reasons"] == {reason: 386}
    assert first["dependency_scan"]["known_vulnerabilities"] is None
    assert first["dependency_scan"]["vulnerability_status"] == "not_assessed"
    assert first["dependency_check"]["known_vulnerabilities"] is None
    assert first["dependency_check"]["vulnerability_status"] == "not_assessed"
    assert first["scan_status"]["state"] == "partial"
    assert any(
        advisory["code"] == "dependency_vulnerability_coverage"
        for advisory in first["review_advisories"]
    )
    with sqlite3.connect(cache_path) as connection:
        assert dict(connection.execute(
            "SELECT status, COUNT(*) FROM osv_query_state GROUP BY status"
        )) == {"succeeded": 10, counter: 386}
        assert connection.execute(
            "SELECT COUNT(*) FROM osv_query_state "
            "WHERE failure_reason = ? AND response_status = ? "
            "AND queried_at IS NOT NULL AND attempts = 1",
            (reason, response_status),
        ).fetchone() == (386,)

    provider_available = True
    sent.clear()
    if restart_client:
        client = OSVClient(**client_options)
        scanner = RiskScanner(target, osv_client=client)
    second = scanner.scan()

    assert sent == names[10:]
    assert second["dependency_scan"]["status"] == "complete"
    assert second["dependency_scan"]["queried"] == 396
    assert second["dependency_scan"]["succeeded"] == 396
    assert second["dependency_scan"]["remaining"] == 0
    assert second["dependency_scan"]["query_failures"] == 0
    assert second["dependency_scan"]["provider_requests"] == 39
    assert second["dependency_scan"]["resumed_queries"] == 386
    assert second["dependency_scan"]["cache_hits"] == 10
    assert second["dependency_scan"]["failure_reasons"] == {}
    assert second["dependency_scan"]["known_vulnerabilities"] == 0
    assert second["dependency_scan"]["vulnerability_status"] == "assessed"
    assert second["dependency_check"]["known_vulnerabilities"] == 0
    assert not any(
        advisory["code"] == "dependency_vulnerability_coverage"
        for advisory in second["review_advisories"]
    )
    assert client.queried == 386
    assert client.request_count == 39
    assert client.cache_hits == 10
    assert client.failures == client.rate_limited == client.skipped == 0
    assert client.limit_reached is False
    with sqlite3.connect(cache_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM osv_query_state "
            "WHERE status = 'succeeded' AND failure_reason IS NULL"
        ).fetchone() == (396,)
        assert connection.execute(
            "SELECT COUNT(*) FROM osv_query_state WHERE from_cache = 1"
        ).fetchone() == (10,)
    for report in (first, second):
        jsonschema.validate(report, _REPORT_SCHEMA)


def test_scan_without_dependencies_resets_all_osv_counters(tmp_path: Path) -> None:
    client = OSVClient(requester=_success_response)
    counters = (
        "queried", "failures", "rate_limited", "skipped", "cache_hits", "request_count", "resumed_queries",
    )
    for counter in counters:
        setattr(client, counter, 7)
    client.limit_reached = True

    report = RiskScanner(tmp_path, osv_client=client).scan()

    assert report["dependency_scan"]["status"] == "complete"
    assert report["dependency_scan"]["provider_requests"] == 0
    assert {counter: getattr(client, counter) for counter in counters} == dict.fromkeys(
        counters, 0,
    )
    assert client.limit_reached is False


@pytest.mark.parametrize(
    "attributes", [{}, {"reset_scan_state": None}, {"reset_scan_state": 0}],
)
def test_scan_requires_callable_client_reset_hook(tmp_path: Path, attributes) -> None:
    (tmp_path / "requirements.txt").write_text(
        "--index-url https://pypi.org/simple/\nexample==1.0.0\n",
        encoding="utf-8",
    )

    def unexpected_query(_dependency):
        pytest.fail("an invalid client must be rejected before querying")

    client = SimpleNamespace(query=unexpected_query, **attributes)
    scanner = RiskScanner(tmp_path, osv_client=client)

    with pytest.raises(
        TypeError, match="osv_client must implement reset_scan_state",
    ) as error:
        scanner.scan()
    assert "add a no-op for stateless clients" in str(error.value)


def test_normalized_duplicates_are_queried_once_and_result_order_is_mapped() -> None:
    request_count = 0

    def requester(payload: bytes, _timeout: float) -> OSVHTTPResponse:
        nonlocal request_count
        request_count += 1
        queries = json.loads(payload)["queries"]
        results = [
            {"vulns": [{"id": f"OSV-{query['package']['name'].casefold()}"}]}
            for query in queries
        ]
        return OSVHTTPResponse(200, json.dumps({"results": results}).encode(), {})

    first = _dependency("My_Package", ecosystem="PyPI")
    duplicate = _dependency("my-package", ecosystem="python", source_file="requirements.txt")
    second = _dependency("another-package", ecosystem="PyPI")
    client = OSVClient(requester=requester, batch_size=100)

    results = client.query_many([first, duplicate, second])

    assert len(results) == 2
    assert request_count == 1
    assert dependency_coordinate(first) == dependency_coordinate(duplicate)
    assert results[dependency_coordinate(first)].vulnerability_ids == ["OSV-my_package"]
    assert results[dependency_coordinate(second)].vulnerability_ids == ["OSV-another-package"]


def test_rate_limit_retries_with_backoff_then_succeeds() -> None:
    calls = 0
    delays: list[float] = []

    def requester(payload: bytes, _timeout: float) -> OSVHTTPResponse:
        nonlocal calls
        calls += 1
        if calls == 1:
            return OSVHTTPResponse(429, b"{}", {"Retry-After": "0.2"})
        return _success_response(payload, _timeout)

    client = OSVClient(
        requester=requester,
        max_retries=2,
        sleeper=delays.append,
    )

    result = client.query(_dependency("retry-me"))

    assert result.status == "succeeded"
    assert result.attempts == 2
    assert calls == 2
    assert delays == [0.2]


@pytest.mark.parametrize("ecosystem,version,expected", [
    ("PyPI", "==1.2.3+linux.x86", "1.2.3+linux.x86"),
    ("crates.io", "=1.2.3-exp.x", "1.2.3-exp.x"),
    ("npm", "1.2.3-exp.x", "1.2.3-exp.x"),
])
def test_exact_ecosystem_versions_are_queryable(ecosystem, version, expected):
    dependency = _dependency("demo", version, ecosystem=ecosystem)
    sent = []

    def requester(payload, timeout):
        sent.extend(json.loads(payload)["queries"])
        return _success_response(payload, timeout)

    assert OSVClient(requester=requester).query(dependency).status == "succeeded"
    assert sent[0]["version"] == expected


@pytest.mark.parametrize(
    ("invalid_row", "reason"),
    [
        (None, "provider_query_error"),
        ({"error": "provider failure"}, "provider_query_error"),
        ({"error": None, "vulns": []}, "provider_query_error"),
        ({"vulns": None}, "response_parse_error"),
    ],
)
def test_invalid_batch_rows_fail_individually_and_are_never_cached(
    tmp_path: Path, invalid_row: object, reason: str,
) -> None:
    dependencies = [_dependency("broken"), _dependency("healthy")]
    cache_path = tmp_path / "osv.sqlite3"

    def requester(payload: bytes, _timeout: float) -> OSVHTTPResponse:
        rows = [
            invalid_row if query["package"]["name"] == "broken" else {}
            for query in json.loads(payload)["queries"]
        ]
        return OSVHTTPResponse(200, json.dumps({"results": rows}).encode(), {})

    client = OSVClient(requester=requester, cache_path=cache_path)
    results = client.query_many(dependencies)
    broken_key, healthy_key = map(dependency_coordinate, dependencies)
    assert results[broken_key].status == "failed"
    assert results[broken_key].failure_reason == reason
    assert results[broken_key].response_status == 200
    assert results[healthy_key].status == "succeeded"
    assert client.failures == 1
    assert client._cached(broken_key) is None
    with sqlite3.connect(cache_path) as connection:
        assert connection.execute(
            "SELECT package_name FROM osv_query_cache_v2"
        ).fetchall() == [("healthy",)]

    resumed = OSVClient(requester=requester, cache_path=cache_path)
    resumed_results = resumed.query_many(dependencies)
    assert resumed_results[broken_key].status == "failed"
    assert resumed_results[broken_key].from_cache is False
    assert resumed_results[healthy_key].cache_source == "persistent"
    assert resumed.queried == 1


def test_all_failed_batch_rows_leave_both_caches_empty(tmp_path: Path) -> None:
    cache_path = tmp_path / "osv.sqlite3"
    client = OSVClient(
        cache_path=cache_path,
        requester=lambda _payload, _timeout: OSVHTTPResponse(
            200, b'{"results": [null, {"error": "unavailable"}]}', {}
        ),
    )

    results = client.query_many([_dependency("alpha"), _dependency("beta")])

    assert {result.status for result in results.values()} == {"failed"}
    assert client._cache == {}
    with sqlite3.connect(cache_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM osv_query_cache_v2").fetchone() == (0,)


def test_exhausted_rate_limit_and_query_budget_are_explicit() -> None:
    def rate_limited(_payload: bytes, _timeout: float) -> OSVHTTPResponse:
        return OSVHTTPResponse(429, b"{}", {})

    client = OSVClient(
        requester=rate_limited,
        max_queries=2,
        max_retries=0,
        sleeper=lambda _delay: None,
    )
    dependencies = [_dependency(f"package-{index}") for index in range(3)]

    results = client.query_many(dependencies)
    statuses = sorted(result.status for result in results.values())

    assert statuses == ["not_queried", "rate_limited", "rate_limited"]
    assert client.queried == 2
    assert client.skipped == 1
    assert client.limit_reached is True


@pytest.mark.parametrize("cancel_at", ["before_query", "between_batches", "before_retry"])
def test_scan_cancellation_stops_new_batches_and_retries(tmp_path: Path, cancel_at: str) -> None:
    cancelled = threading.Event()
    if cancel_at == "before_query":
        cancelled.set()

    def requester(payload: bytes, timeout: float) -> OSVHTTPResponse:
        cancelled.set()
        if cancel_at == "before_retry":
            return OSVHTTPResponse(429, b"{}", {"Retry-After": "5"})
        return _success_response(payload, timeout)

    cache_path = tmp_path / "osv.sqlite3"
    client = OSVClient(
        requester=requester,
        cancel_event=cancelled,
        batch_size=1,
        max_concurrency=1,
        cache_path=cache_path,
    )
    results = client.query_many([_dependency("alpha"), _dependency("beta")])
    alpha, beta = results.values()
    assert client.request_count == (0 if cancel_at == "before_query" else 1)
    assert beta.status == "not_queried"
    assert beta.failure_reason == "cancelled"
    assert beta.attempts == 0
    assert client.skipped == (2 if cancel_at == "before_query" else 1)
    if cancel_at == "before_retry":
        assert alpha.status == "failed"
        assert alpha.failure_reason == "cancelled"
        assert alpha.attempts == 1
        assert client._cache == {}
    elif cancel_at == "between_batches":
        assert alpha.status == "succeeded"
    with sqlite3.connect(cache_path) as connection:
        assert connection.execute(
            "SELECT status, failure_reason, queried_at, attempts "
            "FROM osv_query_state WHERE package_name = 'beta'"
        ).fetchone() == ("not_queried", "cancelled", None, 0)
        assert connection.execute(
            "SELECT status, failure_reason, queried_at, attempts "
            "FROM osv_query_state WHERE package_name = 'alpha'"
        ).fetchone() == (alpha.status, alpha.failure_reason, alpha.queried_at, alpha.attempts)


def test_non_exact_and_vcs_dependencies_are_unsupported_not_queried(
    tmp_path: Path,
) -> None:
    def unexpected_request(_payload: bytes, _timeout: float) -> OSVHTTPResponse:
        raise AssertionError("unsupported coordinates must not reach OSV")

    client = OSVClient(requester=unexpected_request)
    unsupported = [
        _dependency("range-package", "^1.2.3"),
        _dependency("git-package", "git+https://example.test/repo.git"),
    ]

    results = client.query_many(unsupported)

    assert {result.status for result in results.values()} == {"unsupported"}
    assert client.queried == 0
    assert client.request_count == 0

    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "example",
                "version": "1.0.0",
                "dependencies": {"range-package": "^1.2.3"},
            }
        ),
        encoding="utf-8",
    )
    report = RiskScanner(tmp_path, osv_client=client).scan()
    assert report["dependency_scan"]["status"] == "unsupported"
    assert report["dependency_scan"]["unsupported"] == 1
    assert report["dependency_check"]["known_vulnerabilities"] is None
    assert report["scan_status"]["state"] == "partial"
    assert "dependency_scan_partial" in report["scan_limits"]["exceeded"]
    assert any(
        advisory["code"] == "dependency_vulnerability_coverage"
        for advisory in report["review_advisories"]
    )


def test_disabled_provider_never_sends_queryable_coordinates(tmp_path: Path) -> None:
    def unexpected_request(_payload: bytes, _timeout: float) -> OSVHTTPResponse:
        raise AssertionError("disabled OSV lookup must not perform a request")

    cache_path = tmp_path / "osv.sqlite3"
    client = OSVClient(enabled=False, requester=unexpected_request, cache_path=cache_path)

    result = client.query(_dependency("private-by-policy"))

    assert result.status == "not_queried"
    assert result.failure_reason == "provider_disabled"
    assert client.queried == 0
    assert client.request_count == 0
    with sqlite3.connect(cache_path) as connection:
        assert connection.execute(
            "SELECT status, failure_reason, queried_at FROM osv_query_state"
        ).fetchall() == [("not_queried", "provider_disabled", None)]


def test_agent_manifest_queries_pip_and_separates_non_osv_categories(
    tmp_path: Path,
) -> None:
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "name": "mixed-dependencies",
                "version": "1.0.0",
                "type": "skill",
                "description": "mixed dependency fixture",
                "author": "tester",
                "license": "Apache-2.0",
                "dependencies": {
                    "pip": [{
                        "name": "requests", "version": "2.32.0",
                        "registry": "https://pypi.org/simple/",
                    }],
                    "system": ["python"],
                    "docker": [{"image": "postgres", "tag": "16"}],
                    "mcp_servers": [{"name": "local-server", "command": "python"}],
                },
            }
        ),
        encoding="utf-8",
    )
    queries: list[dict[str, Any]] = []

    def requester(payload: bytes, _timeout: float) -> OSVHTTPResponse:
        queries.extend(json.loads(payload)["queries"])
        return _success_response(payload, _timeout)

    report = RiskScanner(
        tmp_path,
        osv_client=OSVClient(requester=requester),
    ).scan()

    assert queries == [
        {
            "package": {"name": "requests", "ecosystem": "PyPI"},
            "version": "2.32.0",
        }
    ]
    assert report["dependency_scan"]["status"] == "complete"
    assert report["dependency_scan"]["dependencies_found"] == 1
    assert report["dependency_scan"]["non_osv_manifest_dependencies"] == {
        "total": 3,
        "categories": {"docker": 1, "mcp_servers": 1, "system": 1},
    }
    assert report["dependency_check"]["total_dependencies"] == 4
    assert report["scan_status"]["state"] == "complete"
    jsonschema.validate(report, _REPORT_SCHEMA)


def test_manifest_osv_dependencies_are_kept_when_dependency_files_exist(
    tmp_path: Path,
) -> None:
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "name": "manifest-and-file-dependencies",
                "version": "1.0.0",
                "dependencies": {
                    "pip": [
                        {"name": "manifest-only", "version": "1.2.3"}
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text(
        "--index-url https://pypi.org/simple/\nrequirements-only==4.5.6\n",
        encoding="utf-8",
    )
    queries: list[dict[str, Any]] = []

    def requester(payload: bytes, _timeout: float) -> OSVHTTPResponse:
        queries.extend(json.loads(payload)["queries"])
        return _success_response(payload, _timeout)

    report = RiskScanner(
        tmp_path,
        osv_client=OSVClient(requester=requester),
    ).scan()

    assert {
        (query["package"]["name"], query["version"])
        for query in queries
    } == {
        ("manifest-only", "1.2.3"),
        ("requirements-only", "4.5.6"),
    }
    assert report["dependency_scan"]["total_unique_dependencies"] == 2
    assert report["dependency_scan"]["status"] == "complete"


@pytest.mark.parametrize("allow_private", [False, True])
def test_non_public_registry_coordinates_require_explicit_opt_in(
    tmp_path: Path,
    allow_private: bool,
) -> None:
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "name": "private-dependency",
                "version": "1.0.0",
                "dependencies": {
                    "npm": [
                        {
                            "name": "internal-package",
                            "version": "1.0.0",
                            "registry": "https://npm.corp.example/",
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    policy = RegistryPolicy(
        [
            RegistryEntry(
                ecosystem="npm",
                classification=RegistryClassification.APPROVED_PRIVATE,
                exact_host="npm.corp.example",
                evidence_url="https://security.corp.example/npm",
                allow_as_resolved_download=False,
                note="Approved internal npm registry.",
                reviewed_at=date(2026, 9, 20),
            )
        ]
    )

    queries = []

    def requester(payload: bytes, timeout: float) -> OSVHTTPResponse:
        queries.extend(json.loads(payload)["queries"])
        return _success_response(payload, timeout)

    report = RiskScanner(
        tmp_path,
        registry_policy=policy,
        osv_client=OSVClient(
            requester=requester, allow_private_coordinates=allow_private
        ),
    ).scan()

    if allow_private:
        assert queries == [{
            "package": {"name": "internal-package", "ecosystem": "npm"},
            "version": "1.0.0",
        }]
        assert report["dependency_scan"]["status"] == "complete"
        return

    assert queries == []
    assert report["dependency_scan"]["status"] == "not_queried"
    assert report["dependency_scan"]["failure_reasons"] == {
        "non_public_registry_not_queried": 1
    }
    assert report["dependency_scan"]["query_failures"] == 0
    assert report["dependency_scan"]["provider_requests"] == 0
    assert report["dependency_check"]["known_vulnerabilities"] is None


@pytest.mark.parametrize("allow_private", [False, True])
@pytest.mark.parametrize("files", [
    {
        "package.json": '{"dependencies":{"@corp/internal":"1.0.0"}}',
        ".npmrc": "registry=https://npm.corp.example/\n",
    },
    {
        "package.json": '{"dependencies":{"@corp/internal":"1.0.0"}}',
        ".npmrc": "registry=https://registry.npmjs.org/\n@corp:REGISTRY=https://npm.corp.example/\n",
    },
    {
        "package.json": '{"dependencies":{"@corp/internal":"1.0.0"}}',
        ".npmrc": "registry=https://registry.npmjs.org/\n@corp:registry=${PRIVATE_REGISTRY}\n",
    },
    {
        "package.json": '{"dependencies":{"@corp/internal":"1.0.0"}}',
        ".npmrc": "registry=http://registry.npmjs.org/\n",
    },
    {
        "requirements.txt": "--index-url https://pypi.org/simple/\n--extra-index-url https://python.corp.example/simple/\ninternal==1.0.0\n",
    },
    {
        "requirements.txt": "--index-url https://pypi.org/simple/\n--extra-index-url ${PRIVATE_REGISTRY}\ninternal==1.0.0\n",
    },
    {
        "requirements.txt": "--index-url https://pypi.org/simple/\ninternal==1.0.0\n--index-url https://python.corp.example/simple/\nother==2.0.0\n",
    },
    {
        "poetry.lock": '[[package]]\nname = "internal"\nversion = "1.0.0"\n',
        "pyproject.toml": '[[tool.poetry.source]]\nname = "corp"\nurl = "https://python.corp.example/simple/"\n',
    },
    {
        "Cargo.lock": '[[package]]\nname = "internal"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n',
        ".cargo/config.toml": '[source.corp]\nregistry = "sparse+https://cargo.corp.example/"\n',
    },
    {
        "package.json": '{"dependencies":{"@corp/internal":"1.0.0"}}',
        ".npmrc": "registry=https://registry.npmjs.org/\n",
        "setup.sh": "npm install --registry https://npm.corp.example/ @corp/internal\n",
    },
])
def test_source_privacy_boundary_requires_explicit_opt_in(
    tmp_path: Path, files: dict[str, str], allow_private: bool,
) -> None:
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    queries = []

    def requester(payload: bytes, timeout: float) -> OSVHTTPResponse:
        queries.extend(json.loads(payload)["queries"])
        return _success_response(payload, timeout)

    client = OSVClient(
        requester=requester, allow_private_coordinates=allow_private
    )
    report = RiskScanner(tmp_path, osv_client=client).scan()
    scan = report["dependency_scan"]

    if allow_private:
        assert len(queries) == scan["total_unique_dependencies"] > 0
        assert scan["status"] == "complete"
        assert scan["skipped"] == 0
        return

    assert queries == []
    assert client.request_count == 0
    assert scan["status"] == "not_queried"
    assert scan["skipped"] == scan["total_unique_dependencies"] > 0
    assert scan["query_failures"] == 0
    assert scan["failure_reasons"] == {
        "non_public_registry_not_queried": scan["skipped"]
    }
    assert report["dependency_check"]["known_vulnerabilities"] is None
    assert report["scan_status"]["state"] == "partial"
    jsonschema.validate(report, _REPORT_SCHEMA)


@pytest.mark.parametrize("permission", [None, False, "true", 1])
def test_injected_client_requires_boolean_private_opt_in(
    tmp_path: Path, permission: object,
) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"internal":"1.0.0"}}', encoding="utf-8"
    )
    (tmp_path / ".npmrc").write_text("registry=https://npm.corp.example/\n", encoding="utf-8")
    queried = []
    client = SimpleNamespace(
        query=lambda record: queried.append(record),
        reset_scan_state=queried.clear,
    )
    if permission is not None:
        client.allow_private_coordinates = permission

    report = RiskScanner(tmp_path, osv_client=client).scan()

    assert queried == []
    assert report["dependency_scan"]["status"] == "not_queried"


@pytest.mark.parametrize("files", [
    {"requirements.txt": "requests==2.31.0\n"},
    {"Cargo.lock": '[[package]]\nname = "serde"\nversion = "1.0.0"\n'},
    {"poetry.lock": '[[package]]\nname = "requests"\nversion = "2.31.0"\n'},
    {"package-lock.json": '{"packages":{"node_modules/public-package":{"version":"1.0.0"}}}'},
    {"manifest.json": '{"dependencies":{"npm":[{"name":"public-package","version":"1.0.0"}]}}'},
    {"package.json": '{"dependencies":{"public-package":"1.0.0"}}'},
    {
        "package.json": '{"dependencies":{"public-package":"1.0.0"}}',
        ".npmrc": "@other:registry=https://npm.corp.example/\n",
    },
    {
        "package.json": '{"dependencies":{"public-package":"1.0.0"}}',
        "other/.npmrc": "registry=https://registry.npmjs.org/\n",
    },
])
def test_undeclared_registry_uses_ecosystem_public_default(tmp_path, files):
    for name, content in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    queries = []

    def requester(payload, timeout):
        queries.extend(json.loads(payload)["queries"])
        return _success_response(payload, timeout)

    report = RiskScanner(tmp_path, osv_client=OSVClient(requester=requester)).scan()

    assert len(queries) == 1
    assert report["dependency_scan"]["status"] == "complete"
    assert report["dependency_check"]["known_vulnerabilities"] == 0


def test_missing_registry_policy_remains_fail_closed(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    client = OSVClient(requester=_success_response)
    scanner = RiskScanner(tmp_path, osv_client=client)
    scanner.registry_policy = None

    report = scanner.scan()

    assert client.request_count == 0
    assert report["dependency_scan"]["status"] == "not_queried"


def test_public_registry_scope_does_not_disclose_private_packages(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies":{"public-package":"1.0.0","@corp/internal":"1.0.0"}}',
        encoding="utf-8",
    )
    (tmp_path / ".npmrc").write_text(
        "registry=https://registry.npmjs.org/\n@corp:registry=https://npm.corp.example/\n",
        encoding="utf-8",
    )
    queries = []

    def requester(payload: bytes, timeout: float) -> OSVHTTPResponse:
        queries.extend(json.loads(payload)["queries"])
        return _success_response(payload, timeout)

    cache_path = tmp_path / "osv.sqlite3"
    client = OSVClient(requester=requester, cache_path=cache_path)
    report = RiskScanner(tmp_path, osv_client=client).scan()

    assert [query["package"]["name"] for query in queries] == ["public-package"]
    assert report["dependency_scan"]["status"] == "partial"
    assert report["dependency_scan"]["succeeded"] == 1
    assert report["dependency_scan"]["skipped"] == 1
    with sqlite3.connect(cache_path) as connection:
        assert connection.execute(
            "SELECT status, queried_at, failure_reason FROM osv_query_state "
            "WHERE package_name = '@corp/internal'"
        ).fetchone() == ("not_queried", None, "non_public_registry_not_queried")


def test_instance_query_override_uses_sequential_path_without_network(
    tmp_path: Path,
) -> None:
    (tmp_path / ".npmrc").write_text(
        "registry=https://registry.npmjs.org/\n", encoding="utf-8"
    )
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "example",
                "version": "1.0.0",
                "dependencies": {"injected-package": "1.0.0"},
            }
        ),
        encoding="utf-8",
    )
    provider_calls = 0
    query_calls: list[DependencyRecord] = []

    def unexpected_request(_payload: bytes, _timeout: float) -> OSVHTTPResponse:
        nonlocal provider_calls
        provider_calls += 1
        raise AssertionError("an instance-level query override must bypass query_many")

    def query_override(dependency: DependencyRecord) -> OSVQueryResult:
        query_calls.append(dependency)
        return OSVQueryResult([])

    client = OSVClient(requester=unexpected_request)
    client.query = query_override  # type: ignore[method-assign]

    report = RiskScanner(tmp_path, osv_client=client).scan()

    assert len(query_calls) == 1
    assert provider_calls == 0
    assert client.request_count == 0
    assert report["dependency_scan"]["status"] == "complete"
    assert report["dependency_scan"]["succeeded"] == 1


def test_class_query_override_uses_sequential_path_without_network(
    tmp_path: Path,
) -> None:
    (tmp_path / ".npmrc").write_text(
        "registry=https://registry.npmjs.org/\n", encoding="utf-8"
    )
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "example",
                "version": "1.0.0",
                "dependencies": {"subclass-package": "1.0.0"},
            }
        ),
        encoding="utf-8",
    )
    query_calls: list[DependencyRecord] = []

    def unexpected_request(_payload: bytes, _timeout: float) -> OSVHTTPResponse:
        raise AssertionError("a class-level query override must bypass query_many")

    class OfflineOSVClient(OSVClient):
        def query(self, dependency: DependencyRecord) -> OSVQueryResult:
            query_calls.append(dependency)
            return OSVQueryResult([])

    client = OfflineOSVClient(requester=unexpected_request)
    report = RiskScanner(tmp_path, osv_client=client).scan()

    assert len(query_calls) == 1
    assert client.request_count == 0
    assert report["dependency_scan"]["status"] == "complete"
    assert report["dependency_scan"]["succeeded"] == 1


def test_success_cache_is_reused_by_a_new_client(tmp_path: Path) -> None:
    cache_path = tmp_path / "osv-cache.sqlite3"
    dependency = _dependency("cached-package")
    first = OSVClient(
        requester=_success_response,
        cache_path=cache_path,
        clock=lambda: 1000.0,
    )

    first_result = first.query(dependency)

    # Simulate the success-only database created before query-state persistence.
    with sqlite3.connect(cache_path) as connection:
        connection.execute("DROP TABLE osv_query_state")

    def unexpected_request(_payload: bytes, _timeout: float) -> OSVHTTPResponse:
        raise AssertionError("persistent cache should avoid a provider request")

    resumed = OSVClient(
        requester=unexpected_request,
        cache_path=cache_path,
        clock=lambda: 1001.0,
    )
    resumed_result = resumed.query(dependency)

    assert first_result.status == "succeeded"
    assert resumed_result.status == "succeeded"
    assert resumed_result.from_cache is True
    assert resumed_result.cache_source == "persistent"
    assert resumed_result.cache_age_seconds == 1
    assert resumed.request_count == 0
    with sqlite3.connect(cache_path) as connection:
        assert connection.execute(
            "SELECT status, from_cache, cache_source, cache_age_seconds "
            "FROM osv_query_state"
        ).fetchall() == [("succeeded", 1, "persistent", 1)]


def test_recording_cache_hits_does_not_refresh_success_ttl(tmp_path: Path) -> None:
    cache_path = tmp_path / "osv.sqlite3"
    now = 1000.0
    requests = []

    def requester(payload: bytes, timeout: float) -> OSVHTTPResponse:
        requests.append(payload)
        return _success_response(payload, timeout)

    options = dict(
        requester=requester, cache_path=cache_path, cache_ttl=10, clock=lambda: now,
    )
    dependency = _dependency("cached-package")
    first = OSVClient(**options)
    first.query(dependency)
    now = 1009.0
    assert first.query(dependency).cache_source == "memory"
    resumed = OSVClient(**options)
    assert resumed.query(dependency).cache_source == "persistent"
    now = 1011.0
    result = resumed.query(dependency)

    assert len(requests) == 2
    assert result.from_cache is False
    assert result.queried_at == "1970-01-01T00:16:51+00:00"


@pytest.mark.parametrize("cache_ttl", [0, 3600])
def test_all_query_states_are_durable_but_only_successes_are_reused(
    tmp_path: Path, cache_ttl: int,
) -> None:
    cache_path = tmp_path / "osv.sqlite3"
    dependencies = [
        _dependency("a-success"), _dependency("b-timeout"),
        _dependency("c-limited"), _dependency("d-skipped"),
        _dependency("e-unsupported", "^1.0.0"),
    ]

    def requester(payload: bytes, timeout: float) -> OSVHTTPResponse:
        name = json.loads(payload)["queries"][0]["package"]["name"]
        if name == "b-timeout":
            raise TimeoutError()
        if name == "c-limited":
            return OSVHTTPResponse(429, b"{}", {})
        return _success_response(payload, timeout)

    client = OSVClient(
        requester=requester, cache_path=cache_path, max_queries=3,
        batch_size=1, max_concurrency=1, max_retries=0,
        cache_ttl=cache_ttl, clock=lambda: 1000.0,
    )
    results = client.query_many(dependencies)

    expected = {
        "a-success": ("succeeded", None, 200, 1),
        "b-timeout": ("failed", "osv_timeout", None, 1),
        "c-limited": ("rate_limited", "rate_limited", 429, 1),
        "d-skipped": ("not_queried", "query_limit_exceeded", None, 0),
        "e-unsupported": ("unsupported", "non_exact_version", None, 0),
    }
    with sqlite3.connect(cache_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("SELECT * FROM osv_query_state").fetchall()
        assert len(rows) == len(dependencies)
        for row in rows:
            name = row["package_name"]
            assert (row["status"], row["failure_reason"], row["response_status"], row["attempts"]) == expected[name]
            assert row["provider"] == "https://api.osv.dev"
            assert row["data_source"] == "OSV"
            assert row["recorded_at"] == 1000.0
            assert (row["queried_at"] is not None) == (row["attempts"] > 0)
            assert row["queried_at"] == results[("npm", name, row["version"])].queried_at
        assert connection.execute("SELECT COUNT(*) FROM osv_query_cache_v2").fetchone()[0] == int(cache_ttl > 0)

    sent: list[str] = []

    def recovered(payload: bytes, timeout: float) -> OSVHTTPResponse:
        sent.extend(query["package"]["name"] for query in json.loads(payload)["queries"])
        return _success_response(payload, timeout)

    resumed = OSVClient(
        requester=recovered, cache_path=cache_path,
        cache_ttl=cache_ttl, clock=lambda: 1001.0,
    )
    resumed.query_many(dependencies)

    assert sent == [
        "b-timeout", "c-limited", "d-skipped",
    ] + (["a-success"] if cache_ttl == 0 else [])
    with sqlite3.connect(cache_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM osv_query_state "
            "WHERE status = 'succeeded' AND failure_reason IS NULL"
        ).fetchone() == (4,)
        assert connection.execute(
            "SELECT from_cache, cache_source, cache_age_seconds, queried_at "
            "FROM osv_query_state WHERE package_name = 'a-success'"
        ).fetchone() == (
            (1, "persistent", 1, "1970-01-01T00:16:40+00:00") if cache_ttl else
            (0, None, None, "1970-01-01T00:16:41+00:00")
        )


def test_query_plan_and_completed_batches_survive_interruption(tmp_path: Path) -> None:
    cache_path = tmp_path / "osv.sqlite3"
    dependencies = [_dependency(name) for name in ("alpha", "beta", "gamma")]

    def interrupted(payload: bytes, timeout: float) -> OSVHTTPResponse:
        if json.loads(payload)["queries"][0]["package"]["name"] == "beta":
            with sqlite3.connect(cache_path) as connection:
                assert connection.execute(
                    "SELECT package_name, status, failure_reason FROM osv_query_state "
                    "ORDER BY package_name"
                ).fetchall() == [
                    ("alpha", "succeeded", None),
                    ("beta", "not_queried", "query_pending"),
                    ("gamma", "not_queried", "query_pending"),
                ]
            raise KeyboardInterrupt()
        return _success_response(payload, timeout)

    client = OSVClient(
        requester=interrupted, cache_path=cache_path,
        batch_size=1, max_concurrency=1,
    )
    with pytest.raises(KeyboardInterrupt):
        client.query_many(dependencies)
    with sqlite3.connect(cache_path) as connection:
        assert connection.execute(
            "SELECT package_name, failure_reason, run_id, lease_expires_at "
            "FROM osv_query_state WHERE status = 'not_queried' ORDER BY package_name"
        ).fetchall() == [
            ("beta", "query_interrupted", None, None),
            ("gamma", "query_interrupted", None, None),
        ]

    sent: list[str] = []

    def recovered(payload: bytes, timeout: float) -> OSVHTTPResponse:
        sent.extend(query["package"]["name"] for query in json.loads(payload)["queries"])
        return _success_response(payload, timeout)

    results = OSVClient(
        requester=recovered, cache_path=cache_path, max_queries=2,
    ).query_many(dependencies)

    assert sent == ["beta", "gamma"]
    assert all(result.status == "succeeded" for result in results.values())
    with sqlite3.connect(cache_path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM osv_query_state WHERE status = 'succeeded'"
        ).fetchone() == (3,)


def test_query_state_retention_is_bounded_independently_of_success_ttl(
    tmp_path: Path, monkeypatch,
) -> None:
    cache_path = tmp_path / "osv.sqlite3"
    monkeypatch.setattr(osv_client_module, "_PERSISTENT_CACHE_MAX_ROWS", 3)
    client = OSVClient(
        requester=lambda _payload, _timeout: OSVHTTPResponse(503, b"{}", {}),
        cache_path=cache_path, cache_ttl=1, max_retries=0, clock=lambda: 1000.0,
    )
    client.query_many([_dependency(f"package-{index}") for index in range(5)])
    OSVClient(cache_path=cache_path, cache_ttl=1, clock=lambda: 2000.0)._ensure_cache()

    with sqlite3.connect(cache_path) as connection:
        assert connection.execute(
            "SELECT status, failure_reason FROM osv_query_state"
        ).fetchall() == [("failed", "provider_server_error")] * 3


def test_zero_ttl_query_does_not_modify_shared_success_cache(tmp_path: Path) -> None:
    cache_path = tmp_path / "osv.sqlite3"
    dependency = _dependency("shared-success")
    for provider in ("https://api.osv.dev", "https://osv.example.test"):
        OSVClient(
            requester=_success_response, cache_path=cache_path,
            cache_ttl=3600, base_url=provider, clock=lambda: 1000.0,
        ).query(dependency)
    with sqlite3.connect(cache_path) as connection:
        original = connection.execute("SELECT * FROM osv_query_cache_v2 ORDER BY provider").fetchall()
    fresh = OSVClient(
        requester=_success_response, cache_path=cache_path,
        cache_ttl=0, clock=lambda: 1001.0,
    )

    assert fresh.query(dependency).from_cache is False
    assert fresh.request_count == 1
    with sqlite3.connect(cache_path) as connection:
        assert connection.execute("SELECT * FROM osv_query_cache_v2 ORDER BY provider").fetchall() == original
        assert connection.execute("SELECT COUNT(*) FROM osv_query_state").fetchone() == (2,)
    resumed = OSVClient(
        requester=_success_response, cache_path=cache_path,
        cache_ttl=3600, clock=lambda: 1002.0,
    )
    assert resumed.query(dependency).cache_source == "persistent"
    assert resumed.request_count == 0


def test_active_dispatch_renews_its_query_plan_lease(tmp_path: Path, monkeypatch) -> None:
    cache_path = tmp_path / "osv.sqlite3"
    now = 1000.0
    wait_calls = 0
    real_wait = osv_client_module.wait

    def controlled_wait(futures, *, timeout, return_when):
        nonlocal now, wait_calls
        assert timeout <= 30
        now += 110
        wait_calls += 1
        observer = OSVClient(cache_path=cache_path, clock=lambda: now)
        assert observer._load_incomplete_states([("npm", "active", "1.0.0")]) == set()
        with sqlite3.connect(cache_path) as connection:
            assert connection.execute(
                "SELECT failure_reason FROM osv_query_state WHERE package_name = 'active'"
            ).fetchone() == ("query_pending",)
        if wait_calls == 1:
            return set(), set(futures)
        return real_wait(futures, timeout=timeout, return_when=return_when)

    monkeypatch.setattr(osv_client_module, "wait", controlled_wait)
    client = OSVClient(cache_path=cache_path, requester=_success_response, clock=lambda: now)
    assert client.query(_dependency("active")).status == "succeeded"
    assert wait_calls == 2


def test_legacy_query_state_is_migrated_before_recovery(tmp_path: Path) -> None:
    cache_path = tmp_path / "osv.sqlite3"
    with sqlite3.connect(cache_path) as connection:
        connection.execute("""
            CREATE TABLE osv_query_state (
                provider TEXT NOT NULL, ecosystem TEXT NOT NULL,
                package_name TEXT NOT NULL, version TEXT NOT NULL,
                data_source TEXT NOT NULL, status TEXT NOT NULL, recorded_at REAL NOT NULL,
                queried_at TEXT, response_status INTEGER, failure_reason TEXT,
                attempts INTEGER NOT NULL, vulnerability_ids TEXT NOT NULL,
                from_cache INTEGER NOT NULL, cache_source TEXT, cache_age_seconds INTEGER,
                PRIMARY KEY (provider, ecosystem, package_name, version)
            )
        """)
        connection.execute("""
            INSERT INTO osv_query_state VALUES (
                'https://api.osv.dev', 'npm', 'legacy', '1.0.0', 'OSV', 'not_queried',
                1000, NULL, NULL, 'query_pending', 0, '[]', 0, NULL, NULL
            )
        """)
    client = OSVClient(cache_path=cache_path, clock=lambda: 1001.0)

    assert client._load_incomplete_states([("npm", "legacy", "1.0.0")]) == {("npm", "legacy", "1.0.0")}
    with sqlite3.connect(cache_path) as connection:
        assert connection.execute(
            "SELECT failure_reason, run_id, lease_expires_at FROM osv_query_state"
        ).fetchall() == [("query_interrupted", None, None)]


def test_durable_failures_are_prioritized_over_new_coordinates(tmp_path: Path) -> None:
    cache_path = tmp_path / "osv.sqlite3"
    retry = _dependency("z-retry")
    OSVClient(
        requester=lambda _p, _t: OSVHTTPResponse(503, b"{}", {}),
        max_retries=0, cache_path=cache_path,
    ).query(retry)
    sent = []

    def requester(payload, timeout):
        sent.extend(query["package"]["name"] for query in json.loads(payload)["queries"])
        return _success_response(payload, timeout)

    resumed = OSVClient(requester=requester, cache_path=cache_path, max_queries=1)
    results = resumed.query_many([_dependency("a-new"), retry])

    assert sent == ["z-retry"]
    assert resumed.resumed_queries == 1
    assert results[dependency_coordinate(retry)].status == "succeeded"
    assert results[dependency_coordinate(_dependency("a-new"))].failure_reason == "query_limit_exceeded"


def test_expired_and_legacy_plans_converge_without_requerying_their_coordinates(tmp_path: Path) -> None:
    cache_path = tmp_path / "osv.sqlite3"
    pending = OSVQueryResult([], status="not_queried", failure_reason="query_pending")
    abandoned = OSVClient(cache_path=cache_path, clock=lambda: 1000.0)
    abandoned.record_results({("npm", "orphan", "1.0.0"): pending}, run_id="abandoned")
    abandoned.record_results({("npm", "legacy", "1.0.0"): pending})
    now = 1100.0
    live = OSVClient(cache_path=cache_path, clock=lambda: now)
    live.record_results({("npm", "live", "1.0.0"): pending}, run_id="active")
    now = 1200.0
    live._update_query_lease("active")
    observer = OSVClient(
        cache_path=cache_path, requester=_success_response, clock=lambda: now,
    )
    observer.query(_dependency("unrelated"))

    with sqlite3.connect(cache_path) as connection:
        assert connection.execute(
            "SELECT package_name, failure_reason FROM osv_query_state "
            "WHERE status = 'not_queried' ORDER BY package_name"
        ).fetchall() == [
            ("legacy", "query_interrupted"), ("live", "query_pending"),
            ("orphan", "query_interrupted"),
        ]
    # Reconcile on an existing reader too; renewing one owner preserves its
    # live lease, and completing a different owner cannot close it.
    observer._update_query_lease("abandoned", finished=True)
    now = 1240.0
    assert observer._load_incomplete_states([("npm", "live", "1.0.0")]) == set()
    now = 1321.0
    assert observer._load_incomplete_states([("npm", "live", "1.0.0")]) == {("npm", "live", "1.0.0")}
    with sqlite3.connect(cache_path) as connection:
        assert connection.execute(
            "SELECT failure_reason, run_id, lease_expires_at FROM osv_query_state "
            "WHERE package_name = 'live'"
        ).fetchone() == ("query_interrupted", None, None)


@pytest.mark.parametrize("long_paths", [False, True])
def test_report_details_bound_aggregate_occurrences_and_serialized_bytes(long_paths):
    from dataclasses import replace
    from scanners.risk_scanner.rules.supply_chain import _bounded_osv_query_results

    groups = {}
    results = {}
    # Enough unique coordinates to exceed the result cap, each with 100 sources.
    for index in range(1200):
        record = _dependency(f"package-{index:04d}")
        key = dependency_coordinate(record)
        groups[key] = [replace(
            record, source_file=("依" * 950 if long_paths else "nested") + f"/{source}/package-lock.json",
        ) for source in range(100)]
        results[key] = OSVQueryResult([])
    last = ("npm", "package-1199", "1.0.0")
    results[last] = OSVQueryResult(["OSV-CONFIRMED-1"])

    details = _bounded_osv_query_results(groups, results)

    assert details[0]["package_name"] == "package-1199"
    assert 0 < len(details) <= MAX_OSV_QUERY_RESULTS
    assert sum(len(row["occurrences"]) for row in details) <= MAX_OSV_QUERY_RESULT_OCCURRENCES
    assert len(json.dumps(details).encode("utf-8")) <= MAX_OSV_QUERY_RESULTS_BYTES
    assert all(row["occurrence_count"] == 100 and row["occurrences_truncated"] for row in details)
    if long_paths:
        assert len(details) < MAX_OSV_QUERY_RESULTS  # Byte limit, not just the row cap.
    jsonschema.validate(details, _REPORT_SCHEMA["properties"]["dependency_scan"]["properties"]["query_results"])


def test_cached_coordinates_do_not_bypass_outbound_query_budget(tmp_path):
    cache_path = tmp_path / "osv.sqlite3"
    cached = [_dependency(f"cached-{index}") for index in range(3)]
    OSVClient(cache_path=cache_path, requester=_success_response).query_many(cached)
    sent = []

    def requester(payload, timeout):
        sent.extend(json.loads(payload)["queries"])
        return _success_response(payload, timeout)

    client = OSVClient(cache_path=cache_path, requester=requester, max_queries=1)
    fresh = [_dependency("fresh-0"), _dependency("fresh-1")]
    first = client.query_many([*cached, *fresh])
    second = client.query_many([*cached, *fresh, _dependency("fresh-2")])

    assert len(sent) == client.queried == client.request_count == 1
    assert sum(result.status == "succeeded" for result in first.values()) == 4
    assert first[dependency_coordinate(fresh[1])].failure_reason == "query_limit_exceeded"
    assert sum(result.status == "not_queried" for result in second.values()) == 2


def test_persistent_cache_is_isolated_by_provider_origin(tmp_path: Path) -> None:
    cache_path = tmp_path / "osv-cache.sqlite3"
    dependency = _dependency("provider-specific-package")
    OSVClient(
        requester=_success_response,
        cache_path=cache_path,
        clock=lambda: 1000.0,
    ).query(dependency)
    requests = 0

    def mirror_response(payload: bytes, _timeout: float) -> OSVHTTPResponse:
        nonlocal requests
        requests += 1
        queries = json.loads(payload)["queries"]
        return OSVHTTPResponse(
            200,
            json.dumps(
                {
                    "results": [
                        {"vulns": [{"id": "INTERNAL-2026-1"}]}
                        for _query in queries
                    ]
                }
            ).encode(),
            {},
        )

    mirror = OSVClient(
        base_url="https://osv.internal.example",
        requester=mirror_response,
        cache_path=cache_path,
        clock=lambda: 1001.0,
    )

    result = mirror.query(dependency)

    assert requests == 1
    assert result.from_cache is False
    assert result.vulnerability_ids == ["INTERNAL-2026-1"]


def test_persistent_cache_prunes_oldest_rows_to_hard_limit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cache_path = tmp_path / "osv-cache.sqlite3"
    seed = OSVClient(
        requester=_success_response,
        cache_path=cache_path,
        cache_ttl=10_000,
        clock=lambda: 1_000.0,
    )
    seed._ensure_cache()
    with sqlite3.connect(cache_path) as connection:
        connection.executemany(
            """
            INSERT INTO osv_query_cache_v2 (
                provider, ecosystem, package_name, version, queried_at,
                response_status, vulnerability_ids
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    "https://api.osv.dev",
                    "npm",
                    f"package-{index}",
                    "1.0.0",
                    index,
                    200,
                    "[]",
                )
                for index in range(5)
            ],
        )

    monkeypatch.setattr(osv_client_module, "_PERSISTENT_CACHE_MAX_ROWS", 3)
    pruner = OSVClient(
        requester=_success_response,
        cache_path=cache_path,
        cache_ttl=10_000,
        clock=lambda: 1_000.0,
    )

    pruner._ensure_cache()

    with sqlite3.connect(cache_path) as connection:
        rows = connection.execute(
            "SELECT package_name FROM osv_query_cache_v2 ORDER BY queried_at"
        ).fetchall()
    assert rows == [("package-2",), ("package-3",), ("package-4",)]


def test_persistent_cache_write_failure_disables_cache(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cache_path = tmp_path / "osv-cache.sqlite3"
    client = OSVClient(
        requester=_success_response,
        cache_path=cache_path,
        clock=lambda: 1_000.0,
    )
    client._ensure_cache()

    def locked_connect(*_args, **_kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(sqlite3, "connect", locked_connect)
    client.record_results({
        ("npm", "locked-package", "1.0.0"): OSVQueryResult([]),
    })

    assert client._cache_ready is False


def test_persistent_cache_is_prefetched_with_bounded_selects(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cache_path = tmp_path / "osv-cache.sqlite3"
    dependencies = [_dependency(f"cached-package-{index}") for index in range(700)]
    seed = OSVClient(
        requester=_success_response,
        cache_path=cache_path,
        batch_size=1000,
        clock=lambda: 1000.0,
    )
    seed.query_many(dependencies)

    real_connect = sqlite3.connect
    connect_calls = 0
    select_statements: list[str] = []

    def counting_connect(*args, **kwargs):
        nonlocal connect_calls
        connect_calls += 1
        connection = real_connect(*args, **kwargs)
        connection.set_trace_callback(
            lambda statement: select_statements.append(statement)
            if statement.lstrip().upper().startswith("SELECT ")
            else None
        )
        return connection

    def unexpected_request(_payload: bytes, _timeout: float) -> OSVHTTPResponse:
        raise AssertionError("persistent cache hits must not reach OSV")

    monkeypatch.setattr(sqlite3, "connect", counting_connect)
    resumed = OSVClient(
        requester=unexpected_request,
        cache_path=cache_path,
        batch_size=1000,
        clock=lambda: 1001.0,
    )

    results = resumed.query_many(dependencies)

    assert len(results) == 700
    # Schema/expiry setup, one bulk read, and one bulk state update for cache hits.
    assert connect_calls == 3
    assert len(select_statements) == 3  # 300 + 300 + 100 coordinates
    assert resumed.cache_hits == 700
    assert resumed.request_count == 0
    assert {result.cache_source for result in results.values()} == {"persistent"}


@pytest.mark.parametrize(
    ("error", "reason"),
    [(urllib.error.URLError("offline"), "network_error"), (TimeoutError(), "osv_timeout")],
)
def test_api_unavailable_never_becomes_a_clean_report(
    tmp_path: Path, error: Exception, reason: str,
) -> None:
    (tmp_path / ".npmrc").write_text(
        "registry=https://registry.npmjs.org/\n", encoding="utf-8"
    )
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "example",
                "version": "1.0.0",
                "dependencies": {"lodash": "4.17.21"},
            }
        ),
        encoding="utf-8",
    )

    def unavailable(_payload: bytes, _timeout: float) -> OSVHTTPResponse:
        raise error

    client = OSVClient(
        requester=unavailable,
        max_retries=1,
        sleeper=lambda _delay: None,
    )
    report = RiskScanner(tmp_path, osv_client=client).scan()

    assert report["dependency_scan"]["status"] == "unavailable"
    assert report["dependency_scan"]["queryable"] == 1
    assert report["dependency_scan"]["succeeded"] == 0
    assert report["dependency_scan"]["failed"] == 1
    assert report["dependency_scan"]["remaining"] == 1
    assert report["dependency_scan"]["failure_reasons"] == {reason: 1}
    assert report["dependency_check"]["known_vulnerabilities"] is None
    assert report["dependency_check"]["vulnerability_status"] == "not_assessed"
    assert report["scan_status"]["state"] == "partial"
    assert any(
        advisory["code"] == "dependency_vulnerability_coverage"
        for advisory in report["review_advisories"]
    )
    jsonschema.validate(report, _REPORT_SCHEMA)


def test_query_result_maps_duplicate_occurrences_to_sources(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "name": "example",
                "version": "1.0.0",
                "dependencies": {"lodash": "^4.17.0"},
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "example",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"lodash": "^4.17.0"}},
                    "node_modules/lodash": {
                        "version": "4.17.21",
                        "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    def vulnerable(payload: bytes, _timeout: float) -> OSVHTTPResponse:
        queries = json.loads(payload)["queries"]
        return OSVHTTPResponse(
            200,
            json.dumps(
                {"results": [{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm"}]} for _ in queries]}
            ).encode(),
            {},
        )

    report = RiskScanner(tmp_path, osv_client=OSVClient(requester=vulnerable)).scan()
    dependency_scan = report["dependency_scan"]

    assert dependency_scan["status"] == "complete"
    assert dependency_scan["total_unique_dependencies"] == 1
    assert dependency_scan["queried"] == 1
    result = dependency_scan["query_results"][0]
    assert result["status"] == "succeeded"
    assert result["vulnerability_count"] == 1
    assert result["occurrence_count"] >= 2
    assert {item["source_file"] for item in result["occurrences"]} == {
        "package.json",
        "package-lock.json",
    }
    osv_findings = [
        finding
        for finding in report["findings"]
        if "GHSA-35jh-r3h4-6jhm" in finding["title"]
    ]
    assert len(osv_findings) == 1
    assert "已知 OSV 漏洞" in osv_findings[0]["title"]
    assert osv_findings[0]["source_kind"] == "osv_advisory"
    assert osv_findings[0]["occurrences"]["count"] >= 2
    assert report["dependency_check"]["known_vulnerabilities"] == 1
    assert report["dependency_check"]["total_dependencies"] == 1
    jsonschema.validate(report, _REPORT_SCHEMA)


def test_manifest_and_lockfile_share_one_dependency_total(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({
        "dependencies": {
            "npm": [{"name": "dep-0", "version": "1.0.0"}],
            "system": ["python"],
        },
    }), encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(
        '{"packages":{"node_modules/dep-0":{"version":"1.0.0"}}}', encoding="utf-8",
    )

    report = RiskScanner(tmp_path, osv_client=OSVClient(requester=_success_response)).scan()

    assert report["dependency_scan"]["dependencies_found"] == 2
    assert report["dependency_scan"]["total_unique_dependencies"] == 1
    assert report["dependency_check"]["total_dependencies"] == 2


def test_osv_occurrences_are_aggregated_before_finding_budget(tmp_path):
    for index in range(110):
        directory = tmp_path / f"package-{index:03d}"
        directory.mkdir()
        (directory / "package-lock.json").write_text(
            '{"packages":{"node_modules/dep-0":{"version":"1.0.0"}}}', encoding="utf-8",
        )

    def vulnerable(_payload, _timeout):
        return OSVHTTPResponse(200, b'{"results":[{"vulns":[{"id":"OSV-1"},{"id":"OSV-2"}]}]}', {})

    scanner = RiskScanner(
        tmp_path, policy=ScanPolicy(max_findings=3),
        osv_client=OSVClient(requester=vulnerable),
    )
    report = scanner.scan()
    raw = [finding for finding in scanner.findings if finding.get("source_kind") == "osv_advisory"]
    findings = [finding for finding in report["findings"] if finding.get("source_kind") == "osv_advisory"]

    assert len(raw) == len(findings) == 2
    assert "findings_limit_exceeded" not in report["scan_limits"]["exceeded"]
    assert report["dependency_check"]["total_dependencies"] == 1
    assert report["dependency_check"]["known_vulnerabilities"] == 2
    assert all(finding["occurrences"]["count"] == 110 for finding in findings)
    assert all(len(finding["occurrences"]["items"]) == 100 for finding in findings)
    assert all(finding["occurrences"]["truncated"] is True for finding in findings)
    jsonschema.validate(report, _REPORT_SCHEMA)


@pytest.mark.parametrize(("dependency_count", "fail_last", "query_budget"), [
    (501, False, 1000), (501, True, 1000), (5001, False, 1000), (1200, False, 2000),
])
def test_query_results_have_explicit_bounds_without_losing_coverage(
    tmp_path: Path,
    dependency_count: int,
    fail_last: bool,
    query_budget: int,
) -> None:
    dependencies = [f"package-{index:05d}==1.0.0" for index in range(dependency_count)]
    (tmp_path / "requirements.txt").write_text(
        "--index-url https://pypi.org/simple/\n" + "\n".join(dependencies) + "\n",
        encoding="utf-8",
    )
    def requester(payload: bytes, timeout: float) -> OSVHTTPResponse:
        rows = [
            {"error": "provider failure"}
            if fail_last and query["package"]["name"] == f"package-{dependency_count - 1:05d}"
            else {}
            for query in json.loads(payload)["queries"]
        ]
        return OSVHTTPResponse(200, json.dumps({"results": rows}).encode(), {})

    client = OSVClient(
        requester=requester,
        max_queries=query_budget,
        batch_size=100,
    )

    report = RiskScanner(tmp_path, osv_client=client).scan()
    dependency_scan = report["dependency_scan"]

    succeeded = min(dependency_count, query_budget) - int(fail_last)
    assert dependency_scan["status"] == ("complete" if succeeded == dependency_count else "partial")
    assert dependency_scan["total_unique_dependencies"] == dependency_count
    assert dependency_scan["succeeded"] == succeeded
    assert dependency_scan["remaining"] == dependency_count - succeeded
    details = dependency_scan["query_results"]
    assert len(details) == min(dependency_count, MAX_OSV_QUERY_RESULTS)
    assert dependency_scan["query_results_truncated"] is (dependency_count > len(details))
    assert dependency_scan["query_results_omitted"] == dependency_count - len(details)
    assert len(json.dumps(details).encode("utf-8")) <= MAX_OSV_QUERY_RESULTS_BYTES
    assert sum(len(result["occurrences"]) for result in details) <= MAX_OSV_QUERY_RESULT_OCCURRENCES
    if fail_last:
        assert details[0]["package_name"] == f"package-{dependency_count - 1:05d}"
    if dependency_count > query_budget:
        assert all(result["status"] == "not_queried" for result in details)
    for result in details:
        index = int(result["package_name"].split("-")[-1])
        expected_status, expected_reason = "succeeded", None
        if index >= query_budget:
            expected_status, expected_reason = "not_queried", "query_limit_exceeded"
        elif fail_last and index == dependency_count - 1:
            expected_status, expected_reason = "failed", "provider_query_error"
        assert result["status"] == expected_status
        assert result["failure_reason"] == expected_reason
        assert result["occurrences"][0]["source_file"] == "requirements.txt"
    jsonschema.validate(report, _REPORT_SCHEMA)


def test_partial_scan_retains_confirmed_vulnerabilities_without_claiming_full_assessment(
    tmp_path: Path,
) -> None:
    (tmp_path / "requirements.txt").write_text(
        "alpha==1.0.0\nbeta==1.0.0\n", encoding="utf-8",
    )
    client = OSVClient(requester=lambda _payload, _timeout: OSVHTTPResponse(
        200, b'{"results":[{"vulns":[{"id":"OSV-CONFIRMED-1"}]},{"error":"unavailable"}]}', {},
    ))

    report = RiskScanner(tmp_path, osv_client=client).scan()

    assert report["dependency_scan"]["status"] == "partial"
    for field in ("dependency_scan", "dependency_check"):
        assert report[field]["known_vulnerabilities"] is None
        assert report[field]["vulnerability_status"] == "not_assessed"
    assert report["dependency_scan"]["query_results"][0]["vulnerability_count"] == 1
    assert any(
        finding.get("source_kind") == "osv_advisory"
        and "OSV-CONFIRMED-1" in finding["title"]
        for finding in report["findings"]
    )
    jsonschema.validate(report, _REPORT_SCHEMA)
