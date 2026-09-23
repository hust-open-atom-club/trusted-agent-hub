from __future__ import annotations

import json

import pytest

from scanners.risk_scanner.dependency_parsers.models import (
    DependencySourceUsage,
)
from scanners.risk_scanner.registry_policy import (
    DEFAULT_REGISTRY_POLICY,
    RegistryClassification,
    RegistryEntry,
    RegistryPolicy,
    RegistryUsage,
    build_registry_policy,
    parse_approved_private_registries,
)


def test_registry_usage_reuses_dependency_source_usage_enum():
    assert RegistryUsage is DependencySourceUsage


@pytest.mark.parametrize(
    ("ecosystem", "url", "usage"),
    [
        ("npm", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "resolved_download"),
        ("pypi", "https://pypi.org/simple", "registry_api"),
        ("pypi", "https://pypi.org/simple/requests/", "registry_api"),
        ("pypi", "https://files.pythonhosted.org/packages/demo.whl", "resolved_download"),
        ("cargo", "registry+https://github.com/rust-lang/crates.io-index", "registry_api"),
        ("cargo", "sparse+https://index.crates.io/", "registry_api"),
        ("nuget", "https://api.nuget.org/v3/index.json", "registry_api"),
    ],
)
def test_official_registry_endpoints_are_allowed(ecosystem, url, usage):
    decision = DEFAULT_REGISTRY_POLICY.evaluate(ecosystem, url, usage)

    assert decision.allowed is True
    assert decision.classification is RegistryClassification.OFFICIAL
    assert decision.reason == "matched"


def test_yarn_classic_default_registry_is_an_authoritative_mirror():
    decision = DEFAULT_REGISTRY_POLICY.evaluate(
        "npm",
        "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz",
        "resolved_download",
    )

    assert decision.allowed is True
    assert (
        decision.classification
        is RegistryClassification.AUTHORITATIVE_MIRROR
    )
    assert decision.reason == "matched"


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("https://registry.npmmirror.com/pkg/-/pkg.tgz", "unknown_host"),
        ("https://evil.registry.npmjs.org/pkg/-/pkg.tgz", "unknown_host"),
        ("https://registry.npmjs.org.evil.example/pkg.tgz", "unknown_host"),
        ("https://redirect.example/?url=https://registry.npmjs.org", "unknown_host"),
        ("http://registry.npmjs.org/pkg/-/pkg.tgz", "insecure_scheme"),
        ("http://registry.unknown.example/pkg/-/pkg.tgz", "insecure_scheme"),
        ("https://registry.npmjs.org:8443/pkg/-/pkg.tgz", "unapproved_port"),
        ("https://registry.npmjs.org/pkg with space.tgz", "invalid_url"),
        ("https://pypi.org/simple/../project/requests/", "invalid_url"),
        ("https://pypi.org/simple/%2e%2e/project/requests/", "invalid_url"),
        ("https://pypi.org/simple/.%2E/project/requests/", "invalid_url"),
        ("https://pypi.org/simple/%252e%252e/project/requests/", "invalid_url"),
        ("https://pypi.org/simple%2f..%2fproject/requests/", "invalid_url"),
        ("https://pypi.org/simple%5c..%5cproject/requests/", "invalid_url"),
    ],
)
def test_registry_matching_fails_closed(url, reason):
    decision = DEFAULT_REGISTRY_POLICY.evaluate("npm", url, "resolved_download")

    assert decision.allowed is False
    assert decision.reason == reason


def test_registry_entry_is_scoped_to_ecosystem_and_usage():
    wrong_ecosystem = DEFAULT_REGISTRY_POLICY.evaluate(
        "pypi", "https://registry.npmjs.org/pkg", "registry_api"
    )
    wrong_path = DEFAULT_REGISTRY_POLICY.evaluate(
        "pypi", "https://pypi.org/project/requests/", "registry_api"
    )
    wrong_usage = DEFAULT_REGISTRY_POLICY.evaluate(
        "pypi", "https://pypi.org/simple/requests/demo.whl", "resolved_download"
    )

    assert wrong_ecosystem.reason == "wrong_ecosystem"
    assert wrong_path.reason == "canonical_url_mismatch"
    assert wrong_usage.reason == "usage_not_allowed"
    assert not wrong_ecosystem.allowed
    assert not wrong_path.allowed
    assert not wrong_usage.allowed


def test_unknown_ecosystem_falls_back_to_audited_official_endpoint():
    decision = DEFAULT_REGISTRY_POLICY.evaluate(
        "unknown",
        "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
        "resolved_download",
    )

    assert decision.allowed is True
    assert decision.classification is RegistryClassification.OFFICIAL
    assert decision.reason == "matched"


def test_unknown_ecosystem_fallback_remains_path_and_usage_scoped():
    wrong_path = DEFAULT_REGISTRY_POLICY.evaluate(
        "unknown", "https://pypi.org/project/requests/", "registry_api"
    )
    wrong_usage = DEFAULT_REGISTRY_POLICY.evaluate(
        "unknown",
        "https://pypi.org/simple/requests/",
        "resolved_download",
    )

    assert wrong_path.allowed is False
    assert wrong_path.reason == "unknown_host"
    assert wrong_usage.allowed is False
    assert wrong_usage.reason == "usage_not_allowed"


def test_private_registry_approvals_are_server_parsed_and_auditable():
    raw = json.dumps([
        {
            "ecosystem": "npm",
            "exact_host": "npm.corp.example",
            "evidence_url": "https://security.corp.example/registries/npm",
            "allow_as_resolved_download": True,
            "note": "Company-managed npm proxy.",
            "reviewed_at": "2026-09-20",
        }
    ])

    entries = parse_approved_private_registries(raw)
    decision = build_registry_policy(entries).evaluate(
        "npm",
        "https://npm.corp.example/@scope/pkg/-/pkg-1.0.0.tgz",
        "resolved_download",
    )

    assert len(entries) == 1
    assert decision.allowed is True
    assert decision.classification is RegistryClassification.APPROVED_PRIVATE

    inferred_decision = build_registry_policy(entries).evaluate(
        "unknown",
        "https://npm.corp.example/@scope/pkg/-/pkg-1.0.0.tgz",
        "resolved_download",
    )
    assert inferred_decision.allowed is True
    assert (
        inferred_decision.classification
        is RegistryClassification.APPROVED_PRIVATE
    )


def test_standalone_scanner_builds_registry_policy_from_environment(monkeypatch):
    from scanners.risk_scanner.scanner import _registry_policy_from_environment

    monkeypatch.setenv(
        "TAH_APPROVED_PRIVATE_REGISTRIES_JSON",
        json.dumps([{
            "ecosystem": "pypi",
            "exact_host": "python.corp.example",
            "evidence_url": "https://security.corp.example/registries/pypi",
            "note": "Company-managed Python registry.",
            "reviewed_at": "2026-09-22",
        }]),
    )

    policy = _registry_policy_from_environment()
    decision = policy.evaluate(
        "pypi",
        "https://python.corp.example/simple",
        "registry_api",
    )

    assert decision.allowed is True
    assert decision.classification is RegistryClassification.APPROVED_PRIVATE


def test_custom_authoritative_mirror_classification_is_supported():
    official = next(
        entry for entry in DEFAULT_REGISTRY_POLICY.entries
        if entry.exact_host == "registry.npmjs.org"
    )
    mirror = RegistryEntry(
        ecosystem="npm",
        exact_host="mirror.example",
        classification=RegistryClassification.AUTHORITATIVE_MIRROR,
        evidence_url="https://mirror.example/evidence",
        allow_as_resolved_download=True,
        note="Test-only evidence-backed mirror.",
        reviewed_at=official.reviewed_at,
    )
    decision = RegistryPolicy([mirror]).evaluate(
        "npm", "https://mirror.example/pkg.tgz", "resolved_download"
    )

    assert decision.allowed is True
    assert decision.classification is RegistryClassification.AUTHORITATIVE_MIRROR


@pytest.mark.parametrize(
    "payload",
    [
        {"ecosystem": "npm", "exact_host": "*.example.com"},
        {"ecosystem": "npm", "canonical_url": "http://npm.example.com/"},
        {"ecosystem": "unknown", "exact_host": "packages.example.com"},
    ],
)
def test_private_registry_configuration_rejects_unsafe_targets(payload):
    payload.update({
        "evidence_url": "https://security.example.com/evidence",
        "note": "Reviewed private source.",
        "reviewed_at": "2026-09-20",
    })

    with pytest.raises(ValueError):
        parse_approved_private_registries(json.dumps([payload]))


@pytest.mark.parametrize(
    ("reviewed_at", "message"),
    [
        ("not-a-date", "reviewed_at must use YYYY-MM-DD"),
        ("2999-01-01", "reviewed_at must not be in the future"),
    ],
)
def test_private_registry_configuration_rejects_invalid_review_dates(
    reviewed_at, message
):
    payload = {
        "ecosystem": "npm",
        "exact_host": "npm.example.com",
        "evidence_url": "https://security.example.com/evidence",
        "note": "Reviewed private source.",
        "reviewed_at": reviewed_at,
    }

    with pytest.raises(ValueError, match=message):
        parse_approved_private_registries(json.dumps([payload]))


def test_private_registry_configuration_rejects_unknown_fields():
    with pytest.raises(ValueError, match="unsupported fields"):
        parse_approved_private_registries(json.dumps([{
            "ecosystem": "npm",
            "exact_host": "npm.example.com",
            "classification": "official",
            "evidence_url": "https://security.example.com/evidence",
            "note": "Attempted client-side elevation.",
            "reviewed_at": "2026-09-20",
        }]))
