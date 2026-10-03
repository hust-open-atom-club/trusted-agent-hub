"""Offline regression for a pinned real-world npm package snapshot.

The fixture is pinned to xiedada05/nodemw-mcp@1a2081e.  These tests never
contact GitHub, npm, or OSV; provenance and byte digests live beside the
fixture so an intentional refresh is reviewable.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from scanners.risk_scanner.dependency_parsers.osv_client import OSVQueryResult
from scanners.risk_scanner.scanner import RiskScanner
from src.routers import trust


_FIXTURE_ROOT = (
    Path(__file__).parent / "fixtures" / "real_world_nodemw_mcp"
)
_EXPECTED_REPOSITORY = "https://github.com/xiedada05/nodemw-mcp"
_EXPECTED_COMMIT = "1a2081ea3ede1e45175832f633ea92376ece68ab"


class _OfflinePartialOSVClient:
    """Exercise partial OSV coverage without making a network request."""

    max_queries = 1_000

    def __init__(self) -> None:
        self.queried = 0

    def query(self, _dependency: object) -> OSVQueryResult:
        self.queried += 1
        if self.queried == 1:
            return OSVQueryResult(
                [], status="failed", failure_reason="fixture_offline"
            )
        return OSVQueryResult([])


@pytest.fixture(scope="module")
def nodemw_scan() -> tuple[RiskScanner, dict[str, Any]]:
    scanner = RiskScanner(
        _FIXTURE_ROOT,
        source_commit_hash=_EXPECTED_COMMIT,
    )
    scanner.osv_client = _OfflinePartialOSVClient()
    return scanner, scanner.scan()


def _load_provenance() -> dict[str, Any]:
    return json.loads(
        (_FIXTURE_ROOT / "provenance.json").read_text(encoding="utf-8")
    )


def test_nodemw_fixture_is_pinned_and_byte_verified() -> None:
    provenance = _load_provenance()

    assert provenance["source"] == {
        "repository": _EXPECTED_REPOSITORY,
        "commit": _EXPECTED_COMMIT,
        "license": "BSD-2-Clause",
    }
    assert set(provenance["files"]) == {
        "LICENSE",
        ".npmrc",
        "package-lock.json",
        "package.json",
        "src/tools/__tests__/fakeNodemwBot.ts",
        "src/tools/__tests__/smoke.test.ts",
    }
    for relative_path, expected in provenance["files"].items():
        fixture_bytes = (_FIXTURE_ROOT / relative_path).read_bytes()
        assert hashlib.sha256(fixture_bytes).hexdigest() == expected["fixture_sha256"]
        assert len(expected["upstream_sha256"]) == 64
        assert len(expected["git_blob_sha1"]) == 40

    package_lock = json.loads(
        (_FIXTURE_ROOT / "package-lock.json").read_text(encoding="utf-8")
    )
    assert len(package_lock["packages"]) == provenance["expected"]["package_count"]
    resolved = [
        entry["resolved"]
        for entry in package_lock["packages"].values()
        if isinstance(entry, dict) and isinstance(entry.get("resolved"), str)
    ]
    assert sum("registry.npmmirror.com" in url for url in resolved) == 293
    assert sum("registry.npmjs.org" in url for url in resolved) == 111


def test_nodemw_lockfile_is_aggregated_without_hiding_other_checks(
    nodemw_scan: tuple[RiskScanner, dict[str, Any]],
) -> None:
    _scanner, report = nodemw_scan
    policy_advisories = [
        advisory
        for advisory in report["review_advisories"]
        if advisory.get("code") == "dependency_registry_policy"
    ]
    mirror_advisories = [
        advisory
        for advisory in policy_advisories
        if advisory.get("registry_policy", {}).get("registry_host")
        == "registry.npmmirror.com"
    ]

    assert len(mirror_advisories) == 1
    mirror_policy = mirror_advisories[0]["registry_policy"]
    assert mirror_policy["ecosystem"] == "npm"
    assert mirror_policy["source_file"] == "package-lock.json"
    assert mirror_policy["occurrence_count"] == 293
    assert mirror_policy["truncated"] is True
    assert mirror_policy["occurrences"]
    assert all(item.get("dependency_name") for item in mirror_policy["occurrences"])
    assert all(item.get("version") for item in mirror_policy["occurrences"])
    assert all(item.get("integrity") for item in mirror_policy["occurrences"])
    assert not any(
        "registry.npmmirror.com" in str(finding)
        for finding in report["findings"]
    )

    dependency_scan = report["dependency_scan"]
    assert dependency_scan["status"] == "partial"
    assert dependency_scan["dependencies_queried"] == dependency_scan[
        "dependencies_found"
    ]
    assert dependency_scan["query_failures"] == 1
    assert dependency_scan["integrity"]["claimed_count"] == 404
    assert dependency_scan["manifest_lock"]["status"] == "matched"


def test_nodemw_secret_locations_survive_registry_aggregation(
    nodemw_scan: tuple[RiskScanner, dict[str, Any]],
) -> None:
    _scanner, report = nodemw_scan
    secret_locations = {
        (
            finding.get("location", {}).get("file"),
            finding.get("location", {}).get("line"),
        )
        for finding in report["findings"]
        if finding.get("category") == "hardcoded_secret"
    }

    assert secret_locations == {
        ("src/tools/__tests__/fakeNodemwBot.ts", 110),
        ("src/tools/__tests__/smoke.test.ts", 97),
    }


def test_nodemw_llm_candidates_exclude_lock_metadata_and_have_context(
    nodemw_scan: tuple[RiskScanner, dict[str, Any]],
) -> None:
    scanner, report = nodemw_scan

    # Exercise the positive context path with a real fixture finding.  Secret
    # findings are deterministic by default; the copied marker models a source
    # finding that explicitly opted into semantic adjudication.
    source_finding = deepcopy(
        next(
            finding
            for finding in report["findings"]
            if finding.get("location", {}).get("file")
            == "src/tools/__tests__/smoke.test.ts"
            and finding.get("location", {}).get("line") == 97
        )
    )
    source_finding["id"] = "real-world-nodemw-source-candidate"
    source_finding["llm_adjudication_eligible"] = True
    source_finding["requires_llm_validation"] = True

    candidate_inputs = [*report["findings"], *report["review_advisories"]]
    candidate_inputs.append(source_finding)
    contexts, context_audit = trust._build_batched_llm_context_bundle(
        candidate_inputs,
        scanner._file_contents,
    )

    assert set(contexts) == {source_finding["id"]}
    assert context_audit["summary"]["candidates"] == 1
    assert context_audit["summary"]["missing"] == 0
    assert "package-lock.json" not in contexts[source_finding["id"]]
    assert "registry.npmmirror.com" not in contexts[source_finding["id"]]
    assert source_finding["location"]["file"] in scanner._file_contents
    assert 1 <= source_finding["location"]["line"] <= len(
        scanner._file_contents[source_finding["location"]["file"]].splitlines()
    )

    deterministic_inputs = candidate_inputs[:-1]
    assert not any(
        trust._is_llm_reviewable_finding(
            finding,
            file_contents=scanner._file_contents,
        )
        for finding in deterministic_inputs
    )
