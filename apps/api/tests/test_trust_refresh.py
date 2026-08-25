"""Tests for the trust-score refresh service (real-signal recomputation)."""

from __future__ import annotations

from schema.constants import HASH_SCOPE_SCANNED_SOURCE, TRUST_SCORE_MODEL_VERSION

from src.services.trust_refresh import (
    TrustScoreBackfillService,
    TrustScoreRefreshService,
    build_acquisition_facts,
    build_package_metadata,
    compute_signals_fingerprint,
)


class FakeProducerRepository:
    """Dict-shaped producer repository with in-memory writes."""

    def __init__(
        self,
        *,
        version: dict | None = None,
        package: dict | None = None,
        scan: dict | None = None,
        reviews: list[dict] | None = None,
        versions: list[dict] | None = None,
    ) -> None:
        self.version = version or {}
        self.package = package or {}
        self.scan = scan
        self.reviews = reviews or []
        self.versions = versions or []
        self.version_writes: list[dict] = []
        self.package_writes: list[dict] = []
        self.trust_level_writes: list[dict] = []

    def get_version(self, version_id: str) -> dict | None:
        return dict(self.version)

    def get_package(self, package_id: str) -> dict | None:
        return dict(self.package)

    def get_scan_report(self, version_id: str) -> dict | None:
        return dict(self.scan) if self.scan else None

    def list_review_records(self, version_id: str) -> list[dict]:
        return list(self.reviews)

    def list_versions_by_submitter(self, submitter_id: str) -> list[dict]:
        return list(self.versions)

    def update_version_data(self, version_id: str, updates: dict) -> None:
        self.version_writes.append(updates)
        merged = dict(self.version)
        merged.update(updates)
        self.version = merged

    def update_package_data(self, package_id: str, updates: dict) -> None:
        self.package_writes.append(updates)

    def upsert_trust_level(self, **kwargs) -> None:
        self.trust_level_writes.append(kwargs)

    def list_versions_by_status(
        self,
        *,
        status: str,
        limit: int,
        offset: int,
    ) -> list[dict]:
        if self.version.get("status") != status:
            return []
        rows = [{"version_id": self.version.get("id")}]
        return rows[offset:offset + limit]


class FakeConsumerRepository:
    def __init__(self) -> None:
        self.writes: list[dict] = []

    def upsert_trust_level(self, **kwargs) -> None:
        self.writes.append(kwargs)


def _published_version() -> dict:
    return {
        "id": "ver-1",
        "package_id": "pkg-1",
        "version": "1.0.0",
        "status": "published",
        "submitter_id": "user-1",
        "source": {"repository_url": "https://github.com/example/repo"},
        "integrity": {"sha256": "a" * 64},
        "acquisition_facts": {
            "source": {
                "type": "github",
                "repository_url": "https://github.com/example/repo",
                "ref_type": "commit",
                "ref": "a" * 40,
                "commit_hash": "a" * 40,
            },
            "integrity": {
                "sha256": "a" * 64,
                "hash_scope": HASH_SCOPE_SCANNED_SOURCE,
                "is_complete": True,
            },
            "verification": {
                "owner": False,
                "signature": False,
                "attestation": False,
                "sbom": False,
            },
        },
        "permissions": {"filesystem": {"read": [], "write": []}},
        "compatibility": ["claude-code"],
        "installation": {"method": "copy_directory", "targets": []},
    }


def _published_package() -> dict:
    return {
        "id": "pkg-1",
        "name": "demo-skill",
        "type": "skill",
        "description": "demo",
        "license": "MIT",
        "keywords": ["demo"],
        "install_count": 3,
        "avg_rating": None,
    }


def test_build_acquisition_facts_ignores_package_level_claims() -> None:
    assert build_acquisition_facts({}) == {}


def test_build_acquisition_facts_normalizes_legacy_hash_scope() -> None:
    facts = build_acquisition_facts(
        {"acquisition_facts": {"integrity": {"sha256": "f" * 64}}},
        {"scan_status": {"state": "complete", "complete": True}},
    )

    assert facts["integrity"] == {
        "sha256": "f" * 64,
        "hash_scope": HASH_SCOPE_SCANNED_SOURCE,
        "is_complete": True,
    }


def _fake_scorer(**kwargs):
    return {
        "score": 88,
        "package_name": kwargs.get("package_metadata", {}).get("name", "x"),
        "version": "1.0.0",
        "calculated_at": "2026-08-03T00:00:00Z",
        "model_version": TRUST_SCORE_MODEL_VERSION,
        "dimensions": {},
        "explanations": [],
        "risk_summary": {
            "level": "low_risk",
            "grade": "A",
            "top_risks": [],
            "install_recommendation": "safe",
        },
        "received": kwargs,
    }


def test_build_package_metadata_merges_package_and_version() -> None:
    meta = build_package_metadata(
        _published_package(),
        _published_version(),
    )
    assert meta["name"] == "demo-skill"
    assert meta["version"] == "1.0.0"
    assert meta["type"] == "skill"
    assert meta["permissions"] == {
        "filesystem": {"read": [], "write": []}
    }
    assert meta["source"]["repository_url"].startswith("https://github.com/")


def test_fingerprint_is_deterministic_and_order_insensitive() -> None:
    a = compute_signals_fingerprint({"x": [1, 2], "y": {"z": "v"}}, "published")
    b = compute_signals_fingerprint({"y": {"z": "v"}, "x": [1, 2]}, "published")
    c = compute_signals_fingerprint({"x": [1, 2], "y": {"z": "v"}}, "yanked")
    assert a == b
    assert a != c


def test_refresh_computes_and_persists_with_signals() -> None:
    repo = FakeProducerRepository(
        version=_published_version(),
        package=_published_package(),
        scan={"scan_json": {"package_name": "demo-skill", "summary": {"total": 0}}},
        reviews=[
            {
                "id": "rev-1",
                "conclusion": "approved",
                "created_at": "2026-08-03T00:00:00Z",
            }
        ],
    )
    consumer = FakeConsumerRepository()
    scorer_calls: list[dict] = []

    def recorder(**kwargs):
        scorer_calls.append(kwargs)
        return _fake_scorer(**kwargs)

    service = TrustScoreRefreshService(repo, consumer, scorer=recorder)
    result = service.refresh("ver-1")

    assert result is not None
    assert result["score"] == 88
    assert len(scorer_calls) == 1
    call = scorer_calls[0]
    assert call["scan_report"]["package_name"] == "demo-skill"
    assert call["review_records"]["status"] == "approved"
    assert call["feedback"]["total_installs"] == 3
    assert call["author_history"] is not None
    assert call["acquisition_facts"]["source"]["commit_hash"] == "a" * 40

    write = repo.version_writes[-1]
    assert write["trust_score"]["score"] == 88
    assert "trust_score_refresh" in write
    assert consumer.writes
    assert repo.package_writes[-1] == {
        "grade": "A",
        "risk_level": "trusted",
    }


def test_refresh_noop_when_signals_unchanged() -> None:
    repo = FakeProducerRepository(
        version=_published_version(),
        package=_published_package(),
        scan={"scan_json": {"summary": {"total": 0}}},
    )
    service = TrustScoreRefreshService(
        repo,
        None,
        scorer=_fake_scorer,
    )
    first = service.refresh("ver-1")
    assert first is not None
    writes_after_first = len(repo.version_writes)

    # 同一信号再次刷新：指纹相同，不应重算
    second = service.refresh("ver-1")
    assert second is None
    assert len(repo.version_writes) == writes_after_first


def test_refresh_does_not_rescore_only_for_model_version_mismatch() -> None:
    repo = FakeProducerRepository(
        version=_published_version(),
        package=_published_package(),
        scan={"scan_json": {"summary": {"total": 0}}},
    )
    service = TrustScoreRefreshService(
        repo,
        None,
        scorer=_fake_scorer,
    )

    service.refresh("ver-1")
    writes_after_first = len(repo.version_writes)
    repo.version["trust_score"]["model_version"] = "0.3.0"

    # A model upgrade is an explicit backfill concern, not a lazy read-path
    # trigger for every historical version.
    assert service.refresh("ver-1") is None
    assert len(repo.version_writes) == writes_after_first


def test_refresh_force_recomputes_even_when_unchanged() -> None:
    repo = FakeProducerRepository(
        version=_published_version(),
        package=_published_package(),
        scan={"scan_json": {"summary": {"total": 0}}},
    )
    service = TrustScoreRefreshService(
        repo,
        None,
        scorer=_fake_scorer,
    )
    service.refresh("ver-1")
    writes_after_first = len(repo.version_writes)

    forced = service.refresh("ver-1", force=True)
    assert forced is not None
    assert len(repo.version_writes) == writes_after_first + 1


def test_refresh_skips_non_published_versions() -> None:
    version = _published_version()
    version["status"] = "pending_review"
    repo = FakeProducerRepository(
        version=version,
        package=_published_package(),
    )
    service = TrustScoreRefreshService(repo, None, scorer=_fake_scorer)
    assert service.refresh("ver-1") is None
    assert repo.version_writes == []


def test_backfill_retries_and_is_idempotent() -> None:
    version = _published_version()
    version["trust_score"] = {"model_version": "0.3.0"}
    repo = FakeProducerRepository(
        version=version,
        package=_published_package(),
        scan={"scan_json": {"summary": {"total": 0}}},
    )
    attempts = 0

    def flaky_scorer(**kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("temporary scorer failure")
        return _fake_scorer(**kwargs)

    refresh = TrustScoreRefreshService(repo, None, scorer=flaky_scorer)
    backfill = TrustScoreBackfillService(refresh)

    first = backfill.run(batch_size=10, max_attempts=2)
    assert first == {
        "model_version": TRUST_SCORE_MODEL_VERSION,
        "scanned": 1,
        "updated": 1,
        "skipped": 0,
        "failed": [],
    }
    assert attempts == 2

    second = backfill.run(batch_size=10, max_attempts=2)
    assert second["updated"] == 0
    assert second["skipped"] == 1
    assert second["failed"] == []
    assert attempts == 2
