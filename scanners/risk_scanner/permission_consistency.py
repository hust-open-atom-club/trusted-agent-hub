"""Reconcile declared permissions with executable and documentation evidence."""

from __future__ import annotations

from typing import Any

from scanners.risk_scanner.reporting import refresh_report_summaries


def _authorization_capability(capability: str) -> str:
    parts = [part for part in capability.lower().split(".") if part]
    if not parts:
        return ""
    if parts[0] == "installation" and len(parts) > 1:
        parts = parts[1:]
    return ".".join(parts)


def _permission_root(capability: str) -> str:
    normalized = _authorization_capability(capability)
    return normalized.split(".", 1)[0] if normalized else ""


def _evidence_label(item: dict[str, Any]) -> str:
    capability = str(item.get("capability", "unknown"))
    file_path = str(item.get("file", "")).strip()
    return f"{capability} ({file_path})" if file_path else capability


def build_permission_advisories(
    permission_evidence: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Return one package-level advisory for each consistency class.

    Only high-confidence code/API evidence is treated as an actual capability.
    Documentation-only mentions remain a non-grading advisory.  This keeps
    repeated keywords from multiplying deductions or grade shifts.
    """
    evidence = [
        item for item in (permission_evidence or [])
        if isinstance(item, dict)
    ]
    declared_capabilities = {
        _authorization_capability(str(item.get("capability", "")))
        for item in evidence
        if item.get("status") == "declared"
        and item.get("source") in {"manifest", "frontmatter"}
    }
    declared_capabilities.discard("")

    observed_undeclared: list[dict[str, Any]] = []
    documented_undeclared: list[dict[str, Any]] = []
    for item in evidence:
        capability = _authorization_capability(
            str(item.get("capability", ""))
        )
        root = _permission_root(capability)
        # A legacy root declaration still covers all nested actions. New
        # extractor output is granular, so filesystem.read cannot silently
        # authorize filesystem.write or filesystem.delete.
        if (
            not root
            or capability in declared_capabilities
            or root in declared_capabilities
        ):
            continue
        try:
            confidence = float(item.get("confidence", 0))
        except (TypeError, ValueError):
            confidence = 0.0
        if (
            item.get("status") == "observed"
            and item.get("source") == "code"
            and confidence >= 0.75
        ):
            observed_undeclared.append(item)
        elif (
            item.get("status") in {"conditional", "mentioned", "inferred"}
            and item.get("source") == "docs"
            and confidence >= 0.5
        ):
            documented_undeclared.append(item)

    advisories: list[dict[str, Any]] = []
    if observed_undeclared:
        labels = sorted({_evidence_label(item) for item in observed_undeclared})
        advisories.append({
            "id": "advisory-undeclared-executable-capability",
            "code": "undeclared_executable_capability",
            "category": "permission_consistency",
            "level": "high",
            "title": "代码实际使用了未声明的权限",
            "description": (
                "结构化代码证据显示该包会使用能力，但 manifest/frontmatter "
                "没有对应权限声明。该问题按包最多固定降一级。"
            ),
            "deduction": 0,
            "affects_grade": True,
            "grade_downgrade_steps": 1,
            "requires_manual_review": True,
            "evidence": "; ".join(labels)[:1000],
        })

    if documented_undeclared:
        labels = sorted({_evidence_label(item) for item in documented_undeclared})
        advisories.append({
            "id": "advisory-documented-permission-mismatch",
            "code": "documented_permission_not_declared",
            "category": "permission_consistency",
            "level": "warning",
            "title": "文档流程与权限声明不完全一致",
            "description": (
                "文档描述了命令、网络或其他受限能力，但没有发现对应的显式"
                "权限声明。该项只扣审核分，不改变自动安全等级。"
            ),
            "deduction": 5,
            "affects_grade": False,
            "grade_downgrade_steps": 0,
            "requires_manual_review": False,
            "evidence": "; ".join(labels)[:1000],
        })

    return advisories


def reconcile_permission_advisories(
    report: dict[str, Any],
    permission_evidence: list[dict[str, Any]] | None,
) -> None:
    """Replace permission consistency advisories and refresh report summaries."""
    existing = report.get("review_advisories", [])
    retained = [
        item for item in (existing if isinstance(existing, list) else [])
        if isinstance(item, dict) and item.get("category") != "permission_consistency"
    ]
    report["review_advisories"] = retained + build_permission_advisories(
        permission_evidence
    )
    refresh_report_summaries(report)
