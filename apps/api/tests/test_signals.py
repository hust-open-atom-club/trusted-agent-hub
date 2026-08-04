"""Tests for platform signal collection feeding the trust-score engine."""

from __future__ import annotations

from src.services.signals import collect_platform_signals


class FakeProducerRepository:
    """Dict-shaped producer repository with controllable rows."""

    def __init__(
        self,
        *,
        version: dict | None = None,
        package: dict | None = None,
        reviews: list[dict] | None = None,
        versions_by_submitter: list[dict] | None = None,
    ) -> None:
        self._version = version or {}
        self._package = package or {}
        self._reviews = reviews or []
        self._versions = versions_by_submitter or []

    def get_version(self, version_id: str) -> dict | None:
        return self._version

    def get_package(self, package_id: str) -> dict | None:
        return self._package

    def list_review_records(self, version_id: str) -> list[dict]:
        return self._reviews

    def list_versions_by_submitter(self, submitter_id: str) -> list[dict]:
        return self._versions

    def get_feedback_level_counts(self, package_id: str) -> dict:
        return {
            "positive": self._package.get("fb_positive", 0) or 0,
            "neutral": self._package.get("fb_neutral", 0) or 0,
            "negative": self._package.get("fb_negative", 0) or 0,
        }


def _sample_version(*, status: str = "published", score: float = 90.0) -> dict:
    version = {
        "id": "ver-1",
        "package_id": "pkg-1",
        "version": "1.0.0",
        "status": status,
        "submitter_id": "user-1",
    }
    if score is not None:
        version["trust_score"] = {
            "score": score,
            "risk_summary": {"grade": "A"},
        }
    else:
        version["trust_score"] = {"risk_summary": {"grade": "E"}}
    return version


def _sample_version_in_package(
    *,
    package_id: str,
    status: str = "published",
    score: float = 90.0,
) -> dict:
    version = _sample_version(status=status, score=score)
    version["package_id"] = package_id
    version["id"] = f"ver-{package_id}"
    return version


def test_review_records_uses_latest_conclusion() -> None:
    repo = FakeProducerRepository(
        version=_sample_version(status="pending_review"),
        package={"id": "pkg-1", "install_count": 7, "avg_rating": None},
        reviews=[
            {
                "id": "rev-1",
                "conclusion": "approved",
                "comment": "ok",
                "created_at": "2026-08-01T00:00:00Z",
            }
        ],
        versions_by_submitter=[_sample_version()],
    )
    signals = collect_platform_signals(
        repo,
        version_id="ver-1",
        package_id="pkg-1",
        submitter_id="user-1",
    )
    assert signals["review_records"]["status"] == "approved"
    assert signals["review_records"]["reviewer_count"] == 1
    assert signals["review_records"]["last_reviewed_at"] == "2026-08-01T00:00:00Z"


def test_author_history_counts_published_scores_and_violations() -> None:
    repo = FakeProducerRepository(
        version=_sample_version(),
        package={"id": "pkg-1", "install_count": 0, "avg_rating": 4.0},
        reviews=[],
        versions_by_submitter=[
            _sample_version_in_package(package_id="pkg-a", status="published", score=90.0),
            _sample_version_in_package(package_id="pkg-b", status="published", score=70.0),
            _sample_version_in_package(package_id="pkg-c", status="rejected", score=None),
            _sample_version_in_package(package_id="pkg-d", status="published", score=80.0),
        ],
    )
    signals = collect_platform_signals(
        repo,
        version_id="ver-1",
        package_id="pkg-1",
        submitter_id="user-1",
    )
    history = signals["author_history"]
    assert history["packages_published"] == 3
    assert history["avg_historical_score"] == 80  # (90+70+80)/3
    assert history["violations_count"] == 1  # rejected row


def test_feedback_uses_package_install_count_and_rating() -> None:
    repo = FakeProducerRepository(
        version=_sample_version(),
        package={"id": "pkg-1", "install_count": 42, "avg_rating": 4.5},
        reviews=[],
        versions_by_submitter=[],
    )
    signals = collect_platform_signals(
        repo,
        version_id="ver-1",
        package_id="pkg-1",
        submitter_id="user-1",
    )
    feedback = signals["feedback"]
    assert feedback["total_installs"] == 42
    assert feedback["avg_rating"] == 4.5
    assert feedback["total_ratings"] == 1
    assert feedback["level_counts"] == {
        "positive": 0,
        "neutral": 0,
        "negative": 0,
    }


def test_feedback_collects_level_counts() -> None:
    repo = FakeProducerRepository(
        version=_sample_version(),
        package={
            "id": "pkg-1",
            "install_count": 42,
            "avg_rating": None,
            "fb_positive": 5,
            "fb_neutral": 2,
            "fb_negative": 1,
        },
        reviews=[],
        versions_by_submitter=[],
    )
    signals = collect_platform_signals(
        repo,
        version_id="ver-1",
        package_id="pkg-1",
        submitter_id="user-1",
    )
    feedback = signals["feedback"]
    assert feedback["level_counts"] == {
        "positive": 5,
        "neutral": 2,
        "negative": 1,
    }


def test_missing_repository_methods_fall_back_to_neutral() -> None:
    class BareRepo:
        def get_version(self, version_id: str) -> dict:
            return {"id": "ver-1", "status": "scanning", "submitter_id": "user-1"}

        def get_package(self, package_id: str) -> dict:
            return {"id": "pkg-1"}

    signals = collect_platform_signals(
        BareRepo(),
        version_id="ver-1",
        package_id="pkg-1",
        submitter_id="user-1",
    )
    assert signals["author_history"] == {
        "packages_published": 0,
        "avg_historical_score": 0,
        "violations_count": 0,
    }
    assert signals["review_records"]["status"] == "pending"
    assert signals["feedback"]["total_installs"] == 0
