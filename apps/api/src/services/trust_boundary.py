"""公开信任边界结论的单一实现：扫描写入与公开读取共用同一套派生。"""

from __future__ import annotations

from src.models.packages import PublicTrustBoundary


def capability_graph(scan_json: object) -> dict[str, object] | None:
    if not isinstance(scan_json, dict):
        return None
    structural = scan_json.get("structural_analysis")
    if not isinstance(structural, dict):
        return None
    graph = structural.get("capability_graph")
    return graph if isinstance(graph, dict) else None


def public_trust_boundary(
    scan_json: object,
    *,
    scanned_at: str | None = None,
) -> PublicTrustBoundary:
    graph = capability_graph(scan_json)
    if graph is None:
        return PublicTrustBoundary(scanned_at=scanned_at)
    undeclared = graph.get("undeclared_observed")
    if isinstance(undeclared, list) and any(
        isinstance(item, str) and item.strip() for item in undeclared
    ):
        return PublicTrustBoundary(
            verification="verified_undeclared", scanned_at=scanned_at
        )
    return PublicTrustBoundary(
        verification="verified_consistent", scanned_at=scanned_at
    )
