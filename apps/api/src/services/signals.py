"""Platform signal collection for the trust-score engine.

The decision engine accepts author_history / review_records / feedback so the
Layer-3 (community) and user_feedback dimensions reflect real platform data
instead of neutral defaults.  This module gathers those signals from the
producer-side repository at scan-submit time.
"""

from __future__ import annotations

from typing import Any


_REVIEW_CONCLUSION_MAP: dict[str, str] = {
    "approved": "approved",
    "reject": "rejected",
    "rejected": "rejected",
    "changes_requested": "changes_requested",
    "request_changes": "changes_requested",
}


def _numeric_score(trust_score: Any) -> float | None:
    if not isinstance(trust_score, dict):
        return None
    raw = trust_score.get("score")
    if isinstance(raw, (int, float)):
        return float(raw)
    return None


def _collect_review_records(
    repository: Any,
    *,
    version_id: str,
    version: dict[str, Any],
) -> dict[str, Any]:
    reviews: list[dict[str, Any]] = []
    list_reviews = getattr(repository, "list_review_records", None)
    if callable(list_reviews):
        try:
            reviews = list(list_reviews(version_id)) or []
        except Exception:  # pragma: no cover - defensive for partial mocks
            reviews = []

    status = str(version.get("status", "pending"))
    status = _REVIEW_CONCLUSION_MAP.get(status.lower(), "pending")

    if reviews:
        latest = reviews[0]
        conclusion = str(latest.get("conclusion", "")).lower()
        mapped = _REVIEW_CONCLUSION_MAP.get(conclusion)
        if mapped:
            status = mapped
        return {
            "status": status,
            "reviewer_count": len(reviews),
            "last_reviewed_at": latest.get("created_at") or "",
        }

    if status == "approved" and version.get("published_at"):
        return {
            "status": status,
            "reviewer_count": 0,
            "last_reviewed_at": str(version.get("published_at", "")),
        }
    return {
        "status": status,
        "reviewer_count": 0,
        "last_reviewed_at": "",
    }


def _collect_author_history(
    repository: Any,
    *,
    submitter_id: str | None,
    exclude_version_id: str | None = None,
) -> dict[str, Any]:
    versions: list[dict[str, Any]] = []
    if submitter_id:
        list_by_submitter = getattr(repository, "list_versions_by_submitter", None)
        if callable(list_by_submitter):
            try:
                versions = list(list_by_submitter(submitter_id)) or []
            except Exception:  # pragma: no cover - defensive for partial mocks
                versions = []

    published_package_ids: set[str] = set()
    scores: list[float] = []
    violations = 0
    for version in versions:
        version_key = str(
            version.get("id") or version.get("version_id") or ""
        )
        if exclude_version_id and version_key == exclude_version_id:
            # 排除正在评分的版本自身，避免“评分→历史均分→再评分”自指循环
            continue
        status = str(version.get("status", "")).lower()
        package_id = str(version.get("package_id", ""))
        if status in ("published", "approved", "pending_review"):
            if package_id:
                published_package_ids.add(package_id)
        if status in ("rejected", "yanked"):
            violations += 1
            continue
        score = _numeric_score(version.get("trust_score"))
        if score is not None:
            scores.append(score)
        else:
            risk_summary = (
                (version.get("trust_score") or {}).get("risk_summary") or {}
            )
            if isinstance(risk_summary, dict) and risk_summary.get("grade") == "E":
                violations += 1

    return {
        "packages_published": len(published_package_ids),
        "avg_historical_score": round(sum(scores) / len(scores)) if scores else 0,
        "violations_count": violations,
    }


def _collect_feedback(package: dict[str, Any]) -> dict[str, Any]:
    avg_rating = package.get("avg_rating")
    return {
        "avg_rating": float(avg_rating) if isinstance(avg_rating, (int, float)) else 0.0,
        "total_ratings": 1 if isinstance(avg_rating, (int, float)) else 0,
        "total_installs": int(package.get("install_count") or 0),
        "reports_count": 0,
    }


def collect_platform_signals(
    repository: Any,
    *,
    version_id: str,
    package_id: str,
    submitter_id: str | None,
) -> dict[str, Any]:
    """Collect author history, review records, and feedback for one version.

    Args:
        repository: producer-side repository (dict-based API)
        version_id: version being scanned
        package_id: owning package
        submitter_id: package submitter (author)

    Returns:
        dict with author_history / review_records / feedback keys ready for
        ``trust_score.engine.rate``.
    """
    version: dict[str, Any] = {}
    get_version = getattr(repository, "get_version", None)
    if callable(get_version):
        try:
            version = get_version(version_id) or {}
        except Exception:  # pragma: no cover - defensive for partial mocks
            version = {}

    package: dict[str, Any] = {}
    get_package = getattr(repository, "get_package", None)
    if callable(get_package):
        try:
            package = get_package(package_id) or {}
        except Exception:  # pragma: no cover - defensive for partial mocks
            package = {}

    return {
        "author_history": _collect_author_history(
            repository,
            submitter_id=submitter_id or str(version.get("submitter_id") or ""),
            exclude_version_id=version_id,
        ),
        "review_records": _collect_review_records(
            repository,
            version_id=version_id,
            version=version,
        ),
        "feedback": _collect_feedback(package),
    }
