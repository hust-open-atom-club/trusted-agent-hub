"""Shared helpers for dependency vulnerability coverage reporting."""

from __future__ import annotations

from typing import Any, Literal


DEFAULT_OSV_QUERY_LIMIT = 5_000
MAX_OSV_QUERY_RESULTS = 1_000
MAX_OSV_QUERY_RESULT_OCCURRENCES = 1_000
MAX_OSV_QUERY_RESULTS_BYTES = 1024 * 1024


def normalize_query_limit(
    query_limit: object,
    *,
    fallback: int = DEFAULT_OSV_QUERY_LIMIT,
) -> int:
    """Return a positive query limit suitable for scan-report output."""
    try:
        return max(1, int(query_limit))
    except (TypeError, ValueError):
        return max(1, int(fallback))


def empty_dependency_scan(
    query_limit: object = DEFAULT_OSV_QUERY_LIMIT,
    *,
    status: Literal["not_queried", "complete"] = "not_queried",
) -> dict[str, Any]:
    """Initialize coverage without claiming the dependency rule has run."""
    return {
        "status": status,
        "data_source": "OSV",
        "dependencies_found": 0,
        "dependencies_queried": 0,
        "query_failures": 0,
        "query_limit": normalize_query_limit(query_limit),
        "total_dependencies": 0,
        "total_unique_dependencies": 0,
        "queryable": 0,
        "queried": 0,
        "succeeded": 0,
        "failed": 0,
        "skipped": 0,
        "unsupported": 0,
        "rate_limited": 0,
        "remaining": 0,
        "cache_hits": 0,
        "provider_requests": 0,
        "resumed_queries": 0,
        "known_vulnerabilities": 0 if status == "complete" else None,
        "vulnerability_status": "assessed" if status == "complete" else "not_assessed",
        "non_osv_manifest_dependencies": {
            "total": 0,
            "categories": {},
        },
        "query_results": [],
        "query_results_truncated": False,
        "query_results_omitted": 0,
        "failure_reasons": {},
    }
