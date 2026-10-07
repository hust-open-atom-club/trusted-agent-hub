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
def test_scan_cancellation_stops_new_batches_and_retries(cancel_at: str) -> None:
    cancelled = threading.Event()
    if cancel_at == "before_query":
        cancelled.set()

    def requester(payload: bytes, timeout: float) -> OSVHTTPResponse:
        cancelled.set()
        if cancel_at == "before_retry":
            return OSVHTTPResponse(429, b"{}", {"Retry-After": "5"})
        return _success_response(payload, timeout)

    client = OSVClient(
        requester=requester,
        cancel_event=cancelled,
        batch_size=1,
        max_concurrency=1,
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


def test_disabled_provider_never_sends_queryable_coordinates() -> None:
    def unexpected_request(_payload: bytes, _timeout: float) -> OSVHTTPResponse:
        raise AssertionError("disabled OSV lookup must not perform a request")

    client = OSVClient(enabled=False, requester=unexpected_request)

    result = client.query(_dependency("private-by-policy"))

    assert result.status == "not_queried"
    assert result.failure_reason == "provider_disabled"
    assert client.queried == 0
    assert client.request_count == 0


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
    {"package.json": '{"dependencies":{"@corp/internal":"1.0.0"}}'},
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
        "package.json": '{"dependencies":{"@corp/internal":"1.0.0"}}',
        ".npmrc": "@other:registry=https://registry.npmjs.org/\n",
    },
    {
        "package.json": '{"dependencies":{"@corp/internal":"1.0.0"}}',
        "other/.npmrc": "registry=https://registry.npmjs.org/\n",
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
    queried = []
    client = SimpleNamespace(query=lambda record: queried.append(record))
    if permission is not None:
        client.allow_private_coordinates = permission

    report = RiskScanner(tmp_path, osv_client=client).scan()

    assert queried == []
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

    report = RiskScanner(tmp_path, osv_client=OSVClient(requester=requester)).scan()

    assert [query["package"]["name"] for query in queries] == ["public-package"]
    assert report["dependency_scan"]["status"] == "partial"
    assert report["dependency_scan"]["succeeded"] == 1
    assert report["dependency_scan"]["skipped"] == 1


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
    client._store_successes({
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
    assert connect_calls == 2  # schema/expiry setup, then one bulk read connection
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
    jsonschema.validate(report, _REPORT_SCHEMA)


def test_query_results_are_bounded_without_losing_summary_counts(
    tmp_path: Path,
) -> None:
    dependencies = [f"bounded-package-{index}==1.0.0" for index in range(501)]
    (tmp_path / "requirements.txt").write_text(
        "--index-url https://pypi.org/simple/\n" + "\n".join(dependencies) + "\n",
        encoding="utf-8",
    )
    client = OSVClient(
        requester=_success_response,
        max_queries=1000,
        batch_size=100,
    )

    report = RiskScanner(tmp_path, osv_client=client).scan()
    dependency_scan = report["dependency_scan"]

    assert dependency_scan["status"] == "complete"
    assert dependency_scan["total_unique_dependencies"] == 501
    assert dependency_scan["succeeded"] == 501
    assert len(dependency_scan["query_results"]) == 500
    assert dependency_scan["query_results_truncated"] is True
    jsonschema.validate(report, _REPORT_SCHEMA)
