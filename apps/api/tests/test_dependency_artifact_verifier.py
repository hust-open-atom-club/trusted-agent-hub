"""Trusted dependency-artifact acquisition and digest-only verification tests."""

from __future__ import annotations

import base64
from collections.abc import Mapping
import hashlib
import json
from pathlib import Path
import threading
import time
from types import SimpleNamespace

import pytest

from scanners.risk_scanner import dependency_artifact_verifier
from scanners.risk_scanner.dependency_artifact_verifier import (
    ArtifactFetchConfig,
    DependencyArtifactAcquisition,
    DependencyArtifactVerification,
    acquire_dependency_verifications,
)
from scanners.risk_scanner.dependency_parsers.models import DependencyRecord
from scanners.risk_scanner.dependency_parsers.osv_client import OSVQueryResult
from scanners.risk_scanner.registry_policy import DEFAULT_REGISTRY_POLICY
from scanners.risk_scanner.rules import supply_chain
from scanners.risk_scanner.scanner import RiskScanner
from src.routers import trust


_PUBLIC_IP = "93.184.216.34"


class _FakeResponse:
    def __init__(
        self,
        status: int,
        body: bytes = b"",
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.status = status
        self._body = body
        self._offset = 0
        self._headers = {key.casefold(): value for key, value in (headers or {}).items()}
        self.closed = False
        self.timeouts: list[float] = []

    def get_header(self, name: str) -> str | None:
        return self._headers.get(name.casefold())

    def read(self, size: int) -> bytes:
        chunk = self._body[self._offset : self._offset + size]
        self._offset += len(chunk)
        return chunk

    def set_timeout(self, seconds: float) -> None:
        self.timeouts.append(seconds)

    def close(self) -> None:
        self.closed = True


class _FakeTransport:
    def __init__(self, responses: Mapping[str, _FakeResponse | BaseException]) -> None:
        self._responses = dict(responses)
        self.calls: list[dict[str, object]] = []
        self._lock = threading.Lock()

    def open(self, **kwargs: object) -> _FakeResponse:
        with self._lock:
            self.calls.append(dict(kwargs))
        result = self._responses[str(kwargs["url"])]
        if isinstance(result, BaseException):
            raise result
        return result


class _SlowFirstTransport(_FakeTransport):
    def open(self, **kwargs: object) -> _FakeResponse:
        response = super().open(**kwargs)
        if len(self.calls) == 1:
            time.sleep(0.03)
        return response


def _integrity(content: bytes) -> str:
    digest = base64.b64encode(hashlib.sha512(content).digest()).decode("ascii")
    return f"sha512-{digest}"


def _write_package_lock(
    root: Path,
    artifacts: list[tuple[str, str, str]],
) -> None:
    packages = {
        f"node_modules/{name}": {
            "version": "1.0.0",
            "resolved": url,
            "integrity": integrity,
        }
        for name, url, integrity in artifacts
    }
    (root / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": packages}),
        encoding="utf-8",
    )


def _config(**overrides: object) -> ArtifactFetchConfig:
    values: dict[str, object] = {
        "max_artifacts": 10,
        "max_concurrency": 1,
        "max_artifact_bytes": 1024,
        "max_total_bytes": 4096,
        "timeout_seconds": 1.0,
        "max_redirects": 2,
        "chunk_size": 3,
    }
    values.update(overrides)
    return ArtifactFetchConfig(**values)  # type: ignore[arg-type]


def _public_resolver(_host: str, _port: int) -> tuple[str, ...]:
    return (_PUBLIC_IP,)


def test_acquisition_streams_digest_without_retaining_artifact_bytes(tmp_path: Path) -> None:
    url = "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"
    content = b"trusted dependency archive"
    _write_package_lock(tmp_path, [("demo", url, _integrity(content))])
    response = _FakeResponse(200, content, {"Content-Length": str(len(content))})
    transport = _FakeTransport({url: response})

    acquisition = acquire_dependency_verifications(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
        config=_config(),
        transport=transport,
        resolver=_public_resolver,
    )

    assert acquisition.status == "complete"
    assert acquisition.as_dict() == {
        "status": "complete",
        "requested_count": 1,
        "fetched_count": 1,
        "unavailable_count": 0,
        "bytes_downloaded": len(content),
        "unavailable_reasons": {},
        "collection_errors": [],
    }
    verification = acquisition.verifications[url]
    assert verification.status == "fetched"
    assert verification.size_bytes == len(content)
    assert verification.digests["sha512"] == hashlib.sha512(content).hexdigest()
    assert not hasattr(verification, "content")
    assert transport.calls[0]["connect_ip"] == _PUBLIC_IP
    assert response.closed is True
    assert response.timeouts


def test_unknown_length_body_may_exactly_fill_total_budget(tmp_path: Path) -> None:
    url = "https://registry.npmjs.org/exact.tgz"
    content = b"exact"
    _write_package_lock(tmp_path, [("exact", url, _integrity(content))])
    transport = _FakeTransport({url: _FakeResponse(200, content)})

    acquisition = acquire_dependency_verifications(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
        config=_config(max_total_bytes=len(content), chunk_size=3),
        transport=transport,
        resolver=_public_resolver,
    )

    assert acquisition.status == "complete"
    assert acquisition.fetched_count == 1
    assert acquisition.bytes_downloaded == len(content)


def test_concurrent_exact_fit_is_not_scheduling_dependent(tmp_path: Path) -> None:
    first_url = "https://registry.npmjs.org/a-exact.tgz"
    second_url = "https://registry.npmjs.org/b-exact.tgz"
    first = b"abc"
    second = b"de"
    _write_package_lock(
        tmp_path,
        [
            ("a-exact", first_url, _integrity(first)),
            ("b-exact", second_url, _integrity(second)),
        ],
    )
    transport = _FakeTransport({
        first_url: _FakeResponse(200, first),
        second_url: _FakeResponse(200, second),
    })

    acquisition = acquire_dependency_verifications(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
        config=_config(
            max_concurrency=2,
            max_total_bytes=len(first) + len(second),
            chunk_size=3,
        ),
        transport=transport,
        resolver=_public_resolver,
    )

    assert acquisition.status == "complete"
    assert acquisition.fetched_count == 2
    assert acquisition.bytes_downloaded == len(first) + len(second)


def test_ambiguous_transfer_encoding_and_content_length_is_rejected(
    tmp_path: Path,
) -> None:
    url = "https://registry.npmjs.org/ambiguous.tgz"
    body = b"prefix-evil-suffix"
    _write_package_lock(tmp_path, [("ambiguous", url, _integrity(b"prefix"))])
    response = _FakeResponse(
        200,
        body,
        {"Content-Length": "6", "Transfer-Encoding": "chunked"},
    )

    acquisition = acquire_dependency_verifications(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
        config=_config(),
        transport=_FakeTransport({url: response}),
        resolver=_public_resolver,
    )

    assert acquisition.status == "partial"
    assert acquisition.verifications[url].reason == "ambiguous_response_framing"
    assert response.closed is True


def test_dependency_parser_recursion_failure_is_structured_partial(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fail_to_parse(_files: Mapping[str, str]) -> list[DependencyRecord]:
        raise RecursionError("deterministic parser recursion failure")

    monkeypatch.setattr(
        dependency_artifact_verifier,
        "parse_dependencies",
        fail_to_parse,
    )

    acquisition = acquire_dependency_verifications(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
        config=_config(),
        transport=_FakeTransport({}),
        resolver=_public_resolver,
        manifest_files={"package-lock.json": "{}"},
    )

    assert acquisition.status == "partial"
    assert acquisition.requested_count == 0
    assert acquisition.collection_errors == ("dependency_parse_error",)


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://registry.npmjs.org/demo.tgz", "insecure_scheme"),
        (
            "https://user:secret@registry.npmjs.org/demo.tgz",
            "credentials_in_url",
        ),
        ("https://unapproved.example/demo.tgz", "registry_not_allowed"),
    ],
)
def test_untrusted_urls_are_structured_partial_without_network(
    tmp_path: Path,
    url: str,
    reason: str,
) -> None:
    _write_package_lock(tmp_path, [("demo", url, _integrity(b"archive"))])
    transport = _FakeTransport({})

    acquisition = acquire_dependency_verifications(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
        config=_config(),
        transport=transport,
        resolver=_public_resolver,
    )

    assert acquisition.status == "partial"
    assert acquisition.verifications[url].reason == reason
    assert acquisition.unavailable_reasons == {reason: 1}
    assert transport.calls == []


def test_unapproved_flood_does_not_consume_approved_artifact_budget(
    tmp_path: Path,
) -> None:
    blocked_url = "https://aaa-unapproved.example/blocked.tgz"
    approved_url = "https://registry.npmjs.org/approved.tgz"
    content = b"approved archive"
    _write_package_lock(
        tmp_path,
        [
            ("blocked", blocked_url, _integrity(b"blocked")),
            ("approved", approved_url, _integrity(content)),
        ],
    )
    transport = _FakeTransport({approved_url: _FakeResponse(200, content)})

    acquisition = acquire_dependency_verifications(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
        config=_config(max_artifacts=1),
        transport=transport,
        resolver=_public_resolver,
    )

    assert acquisition.verifications[blocked_url].reason == "registry_not_allowed"
    assert acquisition.verifications[approved_url].status == "fetched"
    assert [call["url"] for call in transport.calls] == [approved_url]


def test_unsupported_integrity_uses_no_network_and_is_reported(
    tmp_path: Path,
) -> None:
    url = "https://registry.npmjs.org/demo.tgz"
    _write_package_lock(tmp_path, [("demo", url, "md5-deadbeef")])
    transport = _FakeTransport({})

    acquisition = acquire_dependency_verifications(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
        config=_config(),
        transport=transport,
        resolver=_public_resolver,
    )

    assert acquisition.status == "not_applicable"
    assert acquisition.requested_count == 0
    assert transport.calls == []

    scanner = _IntegrityScanner(acquisition.verifications)
    supply_chain._check_dependency_integrity(
        scanner,
        [_record(url, "md5-deadbeef")],
    )
    assert scanner.dependency_scan["status"] == "complete"
    assert scanner.dependency_scan["integrity"] == {
        "status": "unsupported",
        "claimed_count": 1,
        "verified_count": 0,
        "mismatch_count": 0,
        "unavailable_count": 0,
        "unsupported_count": 1,
    }
    assert scanner.review_advisories[0]["code"] == "dependency_artifact_coverage"


@pytest.mark.parametrize(
    "addresses",
    [
        ("127.0.0.1",),
        ("10.0.0.8",),
        ("169.254.169.254",),
        (_PUBLIC_IP, "::1"),
    ],
)
def test_every_dns_answer_must_be_public_before_connect(
    tmp_path: Path,
    addresses: tuple[str, ...],
) -> None:
    url = "https://registry.npmjs.org/demo.tgz"
    _write_package_lock(tmp_path, [("demo", url, _integrity(b"archive"))])
    transport = _FakeTransport({})

    acquisition = acquire_dependency_verifications(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
        config=_config(),
        transport=transport,
        resolver=lambda _host, _port: addresses,
    )

    assert acquisition.status == "partial"
    assert acquisition.verifications[url].reason == "unsafe_address"
    assert transport.calls == []


def test_dns_resolution_is_bounded_by_batch_deadline(tmp_path: Path) -> None:
    url = "https://registry.npmjs.org/slow-dns.tgz"
    _write_package_lock(tmp_path, [("slow-dns", url, _integrity(b"archive"))])
    transport = _FakeTransport({})

    def slow_resolver(_host: str, _port: int) -> tuple[str, ...]:
        time.sleep(0.05)
        return (_PUBLIC_IP,)

    acquisition = acquire_dependency_verifications(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
        config=_config(timeout_seconds=0.01),
        transport=transport,
        resolver=slow_resolver,
    )

    assert acquisition.status == "partial"
    assert acquisition.verifications[url].reason == "timeout"
    assert transport.calls == []


def test_next_public_dns_address_is_tried_after_connect_failure(
    tmp_path: Path,
) -> None:
    url = "https://registry.npmjs.org/multi-address.tgz"
    content = b"archive"
    _write_package_lock(tmp_path, [("multi", url, _integrity(content))])

    class AddressTransport:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def open(self, **kwargs: object) -> _FakeResponse:
            address = str(kwargs["connect_ip"])
            self.calls.append(address)
            if len(self.calls) == 1:
                raise OSError("first address unavailable")
            return _FakeResponse(200, content)

    transport = AddressTransport()
    second_ip = "8.8.8.8"
    acquisition = acquire_dependency_verifications(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
        config=_config(),
        transport=transport,
        resolver=lambda _host, _port: (_PUBLIC_IP, second_ip),
    )

    assert acquisition.status == "complete"
    assert transport.calls == [_PUBLIC_IP, second_ip]


def test_redirect_target_repeats_registry_and_dns_checks(tmp_path: Path) -> None:
    source = "https://registry.npmjs.org/demo.tgz"
    target = "https://registry.yarnpkg.com/demo.tgz"
    content = b"redirected archive"
    _write_package_lock(tmp_path, [("demo", source, _integrity(content))])
    first = _FakeResponse(302, headers={"Location": target})
    second = _FakeResponse(200, body=content)
    transport = _FakeTransport({source: first, target: second})
    resolved_hosts: list[str] = []

    def resolver(host: str, _port: int) -> tuple[str, ...]:
        resolved_hosts.append(host)
        return (_PUBLIC_IP,)

    acquisition = acquire_dependency_verifications(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
        config=_config(),
        transport=transport,
        resolver=resolver,
    )

    assert acquisition.status == "complete"
    assert acquisition.verifications[source].redirect_count == 1
    assert resolved_hosts == ["registry.npmjs.org", "registry.yarnpkg.com"]
    assert [call["url"] for call in transport.calls] == [source, target]
    assert first.closed and second.closed


def test_redirect_to_unapproved_registry_is_not_requested(tmp_path: Path) -> None:
    source = "https://registry.npmjs.org/demo.tgz"
    target = "https://unapproved.example/demo.tgz"
    _write_package_lock(tmp_path, [("demo", source, _integrity(b"archive"))])
    response = _FakeResponse(302, headers={"Location": target})
    transport = _FakeTransport({source: response})

    acquisition = acquire_dependency_verifications(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
        config=_config(),
        transport=transport,
        resolver=_public_resolver,
    )

    assert acquisition.status == "partial"
    assert acquisition.verifications[source].reason == "registry_not_allowed"
    assert len(transport.calls) == 1


def test_per_artifact_and_total_download_limits_fail_closed(tmp_path: Path) -> None:
    first_url = "https://registry.npmjs.org/a.tgz"
    second_url = "https://registry.npmjs.org/b.tgz"
    first_body = b"aaaa"
    second_body = b"bbbb"
    _write_package_lock(
        tmp_path,
        [
            ("a", first_url, _integrity(first_body)),
            ("b", second_url, _integrity(second_body)),
        ],
    )
    transport = _FakeTransport({
        first_url: _FakeResponse(200, first_body),
        second_url: _FakeResponse(200, second_body),
    })

    acquisition = acquire_dependency_verifications(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
        config=_config(max_artifact_bytes=4, max_total_bytes=5),
        transport=transport,
        resolver=_public_resolver,
    )

    assert acquisition.status == "partial"
    assert acquisition.verifications[first_url].status == "fetched"
    assert acquisition.verifications[second_url].reason == "total_size_limit"
    # The verifier never reads beyond the shared five-byte network budget.
    assert acquisition.bytes_downloaded == 5

    declared_large = _FakeResponse(200, b"", {"Content-Length": "5"})
    transport = _FakeTransport({first_url: declared_large, second_url: _FakeResponse(200)})
    acquisition = acquire_dependency_verifications(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
        config=_config(max_artifact_bytes=4),
        transport=transport,
        resolver=_public_resolver,
    )
    assert acquisition.verifications[first_url].reason == "artifact_too_large"
    assert declared_large.closed


def test_timeout_and_artifact_count_limit_are_structured(tmp_path: Path) -> None:
    first_url = "https://registry.npmjs.org/a.tgz"
    second_url = "https://registry.npmjs.org/b.tgz"
    _write_package_lock(
        tmp_path,
        [
            ("a", first_url, _integrity(b"a")),
            ("b", second_url, _integrity(b"b")),
        ],
    )
    transport = _FakeTransport({first_url: TimeoutError()})

    acquisition = acquire_dependency_verifications(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
        config=_config(max_artifacts=1),
        transport=transport,
        resolver=_public_resolver,
    )

    assert acquisition.status == "partial"
    assert acquisition.verifications[first_url].reason == "timeout"
    assert acquisition.verifications[second_url].reason == "artifact_limit"
    assert acquisition.unavailable_reasons == {"artifact_limit": 1, "timeout": 1}


def test_timeout_is_shared_by_the_whole_acquisition_batch(tmp_path: Path) -> None:
    first_url = "https://registry.npmjs.org/a-timeout.tgz"
    second_url = "https://registry.npmjs.org/b-timeout.tgz"
    _write_package_lock(
        tmp_path,
        [
            ("a-timeout", first_url, _integrity(b"a")),
            ("b-timeout", second_url, _integrity(b"b")),
        ],
    )
    transport = _SlowFirstTransport({
        first_url: _FakeResponse(200, b"a"),
        second_url: _FakeResponse(200, b"b"),
    })

    acquisition = acquire_dependency_verifications(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
        config=_config(timeout_seconds=0.01, max_concurrency=1),
        transport=transport,
        resolver=_public_resolver,
    )

    assert acquisition.status == "partial"
    assert acquisition.unavailable_reasons == {"timeout": 2}
    called_urls = [call["url"] for call in transport.calls]
    assert len(called_urls) <= 1
    assert not called_urls or called_urls == [first_url]


class _IntegrityScanner:
    def __init__(self, verifications: Mapping[str, object]) -> None:
        self.dependency_artifacts: dict[str, bytes] = {}
        self.dependency_verifications = dict(verifications)
        self.dependency_scan: dict[str, object] = {"status": "complete"}
        self.findings: list[dict[str, object]] = []
        self.review_advisories: list[dict[str, object]] = []

    def _add_finding(self, **finding: object) -> None:
        self.findings.append(dict(finding))

    def _add_advisory(self, **advisory: object) -> None:
        self.review_advisories.append(dict(advisory))


def _record(url: str, integrity: str) -> DependencyRecord:
    return DependencyRecord(
        name="demo",
        version="1.0.0",
        ecosystem="npm",
        direct=False,
        source_file="package-lock.json",
        registry=url,
        integrity=integrity,
        registry_usage="resolved_download",
        source_ref="/packages/node_modules/demo",
    )


def test_scanner_consumes_digest_result_and_reports_mismatch() -> None:
    url = "https://registry.npmjs.org/demo.tgz"
    actual = b"actual archive"
    verification = DependencyArtifactVerification(
        status="fetched",
        digests={
            algorithm: hashlib.new(algorithm, actual).hexdigest()
            for algorithm in ("sha512", "sha384", "sha256", "sha1")
        },
        size_bytes=len(actual),
    )
    scanner = _IntegrityScanner({url: verification})

    supply_chain._check_dependency_integrity(
        scanner,
        [_record(url, _integrity(b"expected archive"))],
    )

    assert scanner.dependency_scan["integrity"] == {
        "status": "mismatch",
        "claimed_count": 1,
        "verified_count": 1,
        "mismatch_count": 1,
        "unavailable_count": 0,
        "unsupported_count": 0,
    }
    assert len(scanner.findings) == 1
    assert scanner.findings[0]["llm_review_exempt"] is True


def test_explicit_unavailable_result_is_advisory_only() -> None:
    url = "https://registry.npmjs.org/demo.tgz"
    scanner = _IntegrityScanner({
        url: DependencyArtifactVerification(
            status="unavailable",
            reason="timeout",
        )
    })

    supply_chain._check_dependency_integrity(
        scanner,
        [_record(url, _integrity(b"archive"))],
    )

    assert scanner.dependency_scan["status"] == "complete"
    assert scanner.dependency_scan["integrity"] == {
        "status": "partial",
        "claimed_count": 1,
        "verified_count": 0,
        "mismatch_count": 0,
        "unavailable_count": 1,
        "unsupported_count": 0,
        "unavailable_reasons": {"timeout": 1},
    }
    assert len(scanner.review_advisories) == 1
    advisory = scanner.review_advisories[0]
    assert advisory["code"] == "dependency_artifact_coverage"
    assert advisory["category"] == "provenance"
    assert advisory["affects_grade"] is False
    assert "timeout" in str(advisory["evidence"])


@pytest.mark.parametrize(
    "reason",
    ["timeout", "registry_not_allowed", "artifact_limit"],
)
def test_artifact_coverage_gap_does_not_make_report_inconclusive(
    tmp_path: Path,
    reason: str,
) -> None:
    url = "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz"
    _write_package_lock(tmp_path, [("demo", url, _integrity(b"archive"))])
    verification = DependencyArtifactVerification(
        status="unavailable",
        reason=reason,
    )
    acquisition = DependencyArtifactAcquisition(
        status="partial",
        verifications={url: verification},
        requested_count=1,
        fetched_count=0,
        unavailable_count=1,
        bytes_downloaded=0,
        unavailable_reasons={reason: 1},
    )
    scanner = RiskScanner(
        tmp_path,
        dependency_verifications=acquisition.verifications,
        dependency_acquisition=acquisition.as_dict(),
    )

    class NoVulnerabilityClient:
        max_queries = 10
        queried = 0

        def query(self, _dependency: DependencyRecord) -> OSVQueryResult:
            self.queried += 1
            return OSVQueryResult([], None)

    scanner.osv_client = NoVulnerabilityClient()
    report = scanner.scan()

    assert report["dependency_scan"]["status"] == "complete"
    assert report["dependency_scan"]["integrity"]["status"] == "partial"
    assert report["scan_status"]["state"] == "complete"
    assert report["scan_status"]["complete"] is True
    assert report["scan_status"]["conclusion"] != "inconclusive"
    assert report["scan_status"]["reasons"] == []
    assert "dependency_scan_partial" not in report["scan_limits"]["exceeded"]
    coverage = [
        advisory for advisory in report["review_advisories"]
        if advisory["code"] == "dependency_artifact_coverage"
    ]
    assert len(coverage) == 1
    assert coverage[0]["affects_grade"] is False


def test_mismatch_does_not_hide_partial_integrity_coverage() -> None:
    mismatch_url = "https://registry.npmjs.org/mismatch.tgz"
    unavailable_url = "https://registry.npmjs.org/unavailable.tgz"
    actual = b"actual archive"
    scanner = _IntegrityScanner({
        mismatch_url: DependencyArtifactVerification(
            status="fetched",
            digests={
                algorithm: hashlib.new(algorithm, actual).hexdigest()
                for algorithm in ("sha512", "sha384", "sha256", "sha1")
            },
            size_bytes=len(actual),
        ),
        unavailable_url: DependencyArtifactVerification(
            status="unavailable",
            reason="timeout",
        ),
    })

    supply_chain._check_dependency_integrity(
        scanner,
        [
            _record(mismatch_url, _integrity(b"expected archive")),
            _record(unavailable_url, _integrity(b"unavailable archive")),
        ],
    )

    assert scanner.dependency_scan["integrity"]["status"] == "mismatch"
    assert scanner.dependency_scan["integrity"]["mismatch_count"] == 1
    assert scanner.dependency_scan["integrity"]["unavailable_count"] == 1
    assert scanner.dependency_scan["status"] == "complete"
    assert scanner.review_advisories[0]["code"] == "dependency_artifact_coverage"


def test_collection_failure_is_preserved_even_without_integrity_claims() -> None:
    scanner = _IntegrityScanner({})
    scanner.dependency_acquisition = {
        "status": "partial",
        "requested_count": 0,
        "fetched_count": 0,
        "unavailable_count": 0,
        "bytes_downloaded": 0,
        "unavailable_reasons": {},
        "collection_errors": ["manifest_inventory_file_limit"],
    }

    supply_chain._check_dependency_integrity(scanner, [])

    assert scanner.dependency_scan["status"] == "partial"
    assert scanner.dependency_scan["integrity"]["status"] == "not_applicable"
    assert scanner.dependency_scan["artifact_acquisition"] == (
        scanner.dependency_acquisition
    )
    assert scanner.review_advisories[0]["code"] == "dependency_artifact_coverage"


def _api_artifact_settings(*, enabled: bool) -> SimpleNamespace:
    return SimpleNamespace(
        dependency_artifact_verification_enabled=enabled,
        dependency_artifact_max_artifacts=25,
        dependency_artifact_max_concurrency=2,
        dependency_artifact_max_bytes=1024,
        dependency_artifact_max_total_bytes=4096,
        dependency_artifact_timeout_seconds=5,
    )


def test_api_scan_acquisition_uses_operator_limits(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    expected = DependencyArtifactAcquisition(
        status="not_applicable",
        verifications={},
        requested_count=0,
        fetched_count=0,
        unavailable_count=0,
        bytes_downloaded=0,
        unavailable_reasons={},
    )
    captured: dict[str, object] = {}

    def fake_acquire(
        scan_dir: str | Path,
        registry_policy: object,
        *,
        config: ArtifactFetchConfig,
        manifest_files: Mapping[str, str],
        manifest_collection_errors: object,
    ) -> DependencyArtifactAcquisition:
        captured.update({
            "scan_dir": scan_dir,
            "registry_policy": registry_policy,
            "config": config,
            "manifest_files": manifest_files,
            "manifest_collection_errors": manifest_collection_errors,
        })
        return expected

    monkeypatch.setattr(
        trust,
        "get_settings",
        lambda: _api_artifact_settings(enabled=True),
    )
    monkeypatch.setattr(trust, "acquire_dependency_verifications", fake_acquire)

    result = trust._acquire_dependency_artifacts_for_scan(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
    )

    assert result is expected
    assert captured["scan_dir"] == tmp_path
    assert captured["registry_policy"] is DEFAULT_REGISTRY_POLICY
    config = captured["config"]
    assert isinstance(config, ArtifactFetchConfig)
    assert config.max_artifacts == 25
    assert config.max_concurrency == 2
    assert config.max_artifact_bytes == 1024
    assert config.max_total_bytes == 4096
    assert config.timeout_seconds == 5
    assert config.max_manifest_file_bytes == trust._SOURCE_POLICY.max_file_bytes
    assert captured["manifest_files"] == {}


def test_api_snapshot_rejects_oversized_lockfile_before_network(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    url = "https://registry.npmjs.org/oversized.tgz"
    prefix = json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "node_modules/oversized": {
                "version": "1.0.0",
                "resolved": url,
                "integrity": _integrity(b"archive"),
            }
        },
    })
    padding = " " * (trust._SOURCE_POLICY.max_file_bytes + 1 - len(prefix))
    (tmp_path / "package-lock.json").write_text(
        prefix + padding,
        encoding="utf-8",
    )
    monkeypatch.setattr(
        trust,
        "get_settings",
        lambda: _api_artifact_settings(enabled=True),
    )

    acquisition = trust._acquire_dependency_artifacts_for_scan(
        tmp_path,
        DEFAULT_REGISTRY_POLICY,
    )

    assert acquisition is not None
    assert acquisition.status == "partial"
    assert acquisition.requested_count == 0
    assert "manifest_file_too_large" in acquisition.collection_errors


def test_api_scan_acquisition_can_be_explicitly_disabled(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        trust,
        "get_settings",
        lambda: _api_artifact_settings(enabled=False),
    )
    monkeypatch.setattr(
        trust,
        "acquire_dependency_verifications",
        lambda *_args, **_kwargs: pytest.fail("disabled acquisition was called"),
    )

    assert (
        trust._acquire_dependency_artifacts_for_scan(
            tmp_path,
            DEFAULT_REGISTRY_POLICY,
        )
        is None
    )
