"""
Decision Engine: produces independent security and evidence assessments.

Pipeline (9 steps):
  1. Calculate P1, P2 (Layer 1 — Provenance)
  2. Calculate I1, I2, I3 (Layer 2 — Intent)
  3. Keep provenance independent from permission and scanner risk
  4. Calculate C1, C2 (Layer 3 — Community)
  5. Keep community reputation independent from security risk
  6. Security veto check
  7. Determine baseline level (three-color: red / yellow / green)
  8. Apply upgrade / downgrade rules
  9. Derive 0–100 score from final level

Security veto rules:
  V1: C1 = rejected        → untrusted
  V2: I2 = dangerous AND LLM 确认恶意 → untrusted
  V3: I3 = deceptive AND LLM 确认恶意 → untrusted
  V4: I3 = malicious AND LLM 确认恶意 → untrusted

All functions operate on plain dicts. Uses only the Python standard library.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .provenance import (
    assess_source_verifiability,
    assess_signature_chain,
    has_complete_scanned_hash,
)
from .intent import (
    assess_permission_reasonability,
    assess_prompt_safety,
    assess_behavior_consistency,
)
from .community import assess_manual_review, assess_author_history
from .derived_score import derive_score, get_recommendation
from .explainer import generate_explanations, extract_top_risks
from .model_identity import get_model_fingerprint, get_model_version
from scanners.risk_scanner.weights import SEVERITY_POINTS, LEVEL_TO_GRADE

# Level ordering for upgrade/downgrade (index 0 = best)
_LEVEL_ORDER: tuple[str, ...] = (
    "trusted",
    "low_risk",
    "medium_risk",
    "high_risk",
    "untrusted",
)


def _level_index(level: str) -> int:
    """Return the numeric index of a level in _LEVEL_ORDER."""
    try:
        return _LEVEL_ORDER.index(level)
    except ValueError:
        return 2  # default to medium_risk


def _shift_level(level: str, delta: int) -> str:
    """Shift a level up (delta < 0) or down (delta > 0) the ordering.

    Args:
        level: current level string
        delta: negative = upgrade (better), positive = downgrade (worse)

    Returns:
        new level string, clamped to valid range
    """
    idx = _level_index(level)
    new_idx = max(0, min(len(_LEVEL_ORDER) - 1, idx + delta))
    return _LEVEL_ORDER[new_idx]


def _apply_layer1_discount(
    i1_result: dict[str, Any],
    i2_result: dict[str, Any],
    p1_result: dict[str, Any],
    p2_result: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Step 3: Preserve security signals independently of provenance.

    Provenance measures evidence completeness, not whether a declared or
    observed capability is dangerous.  Both intent results therefore keep
    their original score and counts.

    Args:
        i1_result: I1 assessment result dict
        i2_result: I2 assessment result dict
        p1_result: P1 assessment result dict
        p2_result: P2 assessment result dict

    Returns:
        (discounted_i1, discounted_i2) — new dicts with adjusted scores and counts
    """
    i1_discounted = dict(i1_result)
    i2_discounted = dict(i2_result)
    i1_discounted["discount_applied"] = False
    i2_discounted["discount_applied"] = False
    return i1_discounted, i2_discounted


def _apply_layer_discount_c2(
    c2_result: dict[str, Any],
    p1_result: dict[str, Any],
) -> dict[str, Any]:
    """Step 5: Preserve author history as an independent evidence signal.

    Args:
        c2_result: C2 assessment result dict
        p1_result: P1 assessment result dict

    Returns:
        discounted C2 result dict
    """
    c2_discounted = dict(c2_result)
    c2_discounted["discount_applied"] = False
    return c2_discounted


def _check_veto(
    p1: dict[str, Any],
    i2: dict[str, Any],
    i3: dict[str, Any],
    c1: dict[str, Any],
    c2: dict[str, Any],
) -> str | None:
    """Step 6: Check security veto rules.

    V1: C1 = rejected        → untrusted
    V2: I2 = dangerous AND LLM 确认恶意 → untrusted
    V3: I3 = deceptive AND LLM 确认恶意 → untrusted
    V4: I3 = malicious AND LLM 确认恶意 → untrusted
    Source transparency and author reputation are deliberately not vetoes.

    LLM 不可用或结论不确定时进入人工安全审核，不自动触发 E 级否决。
    """
    i2_level = i2.get("level", "")
    i3_level = i3.get("level", "")
    c1_level = c1.get("level", "")

    if c1_level == "rejected":
        return "V1: manual review rejected"
    if i2_level == "dangerous" and i2.get("confirmed_malicious"):
        return "V2: LLM-confirmed malicious content"
    if i3_level == "deceptive" and i2.get("confirmed_malicious"):
        return "V3: deceptive behavior detected"
    if i3_level == "malicious" and i2.get("confirmed_malicious"):
        return "V4: malicious behavior detected"
    return None


def _determine_baseline(
    p1: dict[str, Any],
    p2: dict[str, Any],
    i1: dict[str, Any],
    i2: dict[str, Any],
    i3: dict[str, Any],
    c2: dict[str, Any],
) -> str:
    """Step 7: Determine the three-color baseline level.

    Counts security risk factors and maps to a baseline:
      green  (0 risk factors)  → low_risk baseline
      yellow (1-2 factors)     → medium_risk baseline
      red    (3+ factors)      → high_risk baseline

    Risk factors (each adds 1 unless noted):
      - I1 = excessive  (+1), I1 = dangerous (+2)
      - I2 = suspicious (+1)   [only for actual findings, not missing-scan default]
      - I2 = dangerous (+3)    [when not already caught by a confirmed-malicious veto]
      - I3 = overreaching (+1) [I3=deceptive/malicious caught by veto]
      P1/P2 provenance and C2 author reputation are evidence indicators only.
    """
    risk: int = 0

    i1_level = i1.get("level", "")
    i2_level = i2.get("level", "")
    i3_level = i3.get("level", "")
    if i1_level == "excessive":
        risk += 1
    elif i1_level == "dangerous":
        risk += 2
    # I2=suspicious only counts when due to actual findings from a real scan,
    # not when the scan report is missing entirely.
    if i2_level == "suspicious" and i2.get("scan_available", True) \
            and (i2.get("critical_count", 0) > 0 or i2.get("high_count", 0) > 0
                 or i2.get("medium_count", 0) > 2 or i2.get("low_count", 0) > 2):
        risk += 1
    elif i2_level == "dangerous":
        risk += 3
    if i3_level == "overreaching":
        risk += 1
    # I3=gap is "no data" — scan completeness is handled separately.

    if risk == 0:
        return "low_risk"  # green
    elif risk <= 2:
        return "medium_risk"  # yellow
    else:
        return "high_risk"  # red


def _apply_upgrade_downgrade(
    baseline: str,
    p1: dict[str, Any],
    i2: dict[str, Any],
    i3: dict[str, Any],
    c1: dict[str, Any],
    c2: dict[str, Any],
) -> tuple[str, bool, bool]:
    """Step 8: Apply upgrade and downgrade rules.

    Upgrade rule:
      C1 = approved AND I2 = safe AND I3 = consistent → +1 level (better)

    Provenance and author reputation do not upgrade or downgrade security.

    Args:
        baseline: the baseline level from Step 7
        p1, i2, i3, c1, c2: assessment result dicts

    Returns:
        (final_level, upgrade_applied, downgrade_applied)
    """
    level = baseline
    upgrade_applied = False
    downgrade_applied = False

    i2_level = i2.get("level", "")
    i3_level = i3.get("level", "")
    c1_level = c1.get("level", "")

    # A completed safe scan plus an approved security review can upgrade the
    # security conclusion regardless of evidence/reputation coverage.
    if c1_level == "approved" and i2_level == "safe" and i3_level == "consistent":
        upgrade_applied = True
        level = _shift_level(level, -1)  # move up (better)

    return level, upgrade_applied, downgrade_applied


def _build_dimensions(
    package_metadata: dict[str, Any],
    p1: dict[str, Any],
    p2: dict[str, Any],
    i1_disc: dict[str, Any],
    i2_disc: dict[str, Any],
    c1: dict[str, Any],
    c2_disc: dict[str, Any],
    fb_data: dict[str, Any] | None = None,
    scan_report: dict[str, Any] | None = None,
    acquisition_facts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the nine-dimension output object per trust-score.schema.json.

    Maps our internal assessments to the schema's nine dimension slots.
    fb_data may include avg_rating, total_ratings, total_installs, reports_count.
    """
    if fb_data is None:
        fb_data = {}
    raw_source = (
        acquisition_facts.get("source", {})
        if isinstance(acquisition_facts, dict)
        else {}
    ) or {}
    source = raw_source if isinstance(raw_source, dict) else {}
    raw_integrity = (
        acquisition_facts.get("integrity", {})
        if isinstance(acquisition_facts, dict)
        else {}
    ) or {}
    integrity = raw_integrity if isinstance(raw_integrity, dict) else {}
    raw_verification = (
        acquisition_facts.get("verification", {})
        if isinstance(acquisition_facts, dict)
        else {}
    ) or {}
    verification = raw_verification if isinstance(raw_verification, dict) else {}
    permissions = package_metadata.get("permissions", {}) or {}
    raw_permission_evidence = package_metadata.get("permission_evidence", [])
    permission_evidence = (
        raw_permission_evidence if isinstance(raw_permission_evidence, list) else []
    )
    name = package_metadata.get("name", "")
    version = package_metadata.get("version", "")
    description = package_metadata.get("description", "")
    license_val = package_metadata.get("license", "")
    keywords = package_metadata.get("keywords", []) or []
    metadata_validation = (
        scan_report.get("metadata_validation", {})
        if isinstance(scan_report, dict)
        else {}
    ) or {}
    metadata_error_fields = {
        str(item.get("field", ""))
        for item in metadata_validation.get("errors", [])
        if isinstance(item, dict)
    } if isinstance(metadata_validation, dict) else set()

    # source_trust (P1)
    source_trust = {
        "score": p1.get("score", 50),
        "weight": 0.25,
        "details": {
            "available": p1.get("available") is True,
            "is_verified_owner": verification.get("owner") is True,
            "source_type": source.get("type", "unknown"),
            "repo_age_days": 0,
            "has_commit_hash": bool(source.get("commit_hash", "")),
            "has_integrity_hash": has_complete_scanned_hash(integrity),
        },
    }

    # author_reputation (C2)
    author_reputation = {
        "score": c2_disc.get("score", 50),
        "weight": 0.10,
        "details": {
            "packages_published": c2_disc.get("packages_published", 0),
            "avg_historical_score": c2_disc.get("avg_historical_score", 0),
            "violations_count": c2_disc.get("violations_count", 0),
        },
    }

    # metadata_completeness
    missing: list[str] = []
    if not description:
        missing.append("description")
    if not license_val:
        missing.append("license")
    if not keywords:
        missing.append("keywords")
    missing_required = [f for f in ["name", "version", "type", "description",
                                     "author", "license", "source"] if f in missing]
    metadata_completeness = {
        "score": max(30, 100 - len(missing) * 20),
        "weight": 0.20,
        "details": {
            "missing_required_fields": missing_required if missing_required else [],
            "has_description": bool(description),
            "has_license": bool(license_val),
            "has_keywords": bool(keywords),
        },
    }

    # permission_minimization (I1)
    permission_minimization = {
        "score": i1_disc.get("score", 50),
        "weight": 0.35,
        "details": {
            "total_permissions": _count_permission_categories(permissions, permission_evidence),
            "high_risk_permissions": i1_disc.get("danger_count", 0),
            "unnecessary_permissions": [],
            "permission_evidence_count": i1_disc.get("permission_evidence_count", 0),
            "ignored_low_confidence_count": i1_disc.get("ignored_low_confidence_count", 0),
        },
    }

    # scan_results (I2)
    scan_results = {
        "score": i2_disc.get("score", 50),
        "weight": 0.65,
        "details": {
            "critical_findings": i2_disc.get("critical_count", 0),
            "high_findings": i2_disc.get("high_count", 0),
            "medium_findings": i2_disc.get("medium_count", 0),
            "low_findings": i2_disc.get("low_count", 0),
            "scan_pass_rate": _compute_pass_rate(i2_disc),
            "scan_state": (scan_report or {}).get("scan_status", {}).get("state", "failed"),
            "scan_conclusion": (scan_report or {}).get("scan_status", {}).get("conclusion", "inconclusive"),
            "scan_complete": bool(i2_disc.get("scan_complete", False)),
            "failed_rules": [
                r.get("rule_id") for r in ((scan_report or {}).get("rule_execution", {}).get("results", []) or [])
                if r.get("status") == "failed"
            ],
            "skipped_files": (scan_report or {}).get("scan_limits", {}).get("skipped", {}).get("count", 0),
        },
    }

    # manual_review (C1)
    review_status_map = {
        "approved": "approved",
        "pending": "unreviewed",
        "changes_requested": "changes_requested",
        "rejected": "rejected",
    }
    manual_review = {
        "score": c1.get("score", 50),
        "weight": 0.10,
        "details": {
            "review_status": review_status_map.get(c1.get("level", "pending"), "unreviewed"),
            "reviewer_count": c1.get("reviewer_count", 0),
            "last_reviewed_at": "",
        },
    }

    # version_stability
    version_missing = "version" in metadata_error_fields or "*" in metadata_error_fields
    is_stable = version_missing or not (
        "alpha" in version.lower() or "beta" in version.lower()
        or "rc" in version.lower() or version.startswith("0.")
    )
    version_stability = {
        "score": 80 if is_stable else 40,
        "weight": 0.05,
        "details": {
            "total_versions": 1,
            "is_stable": is_stable,
            "days_since_last_update": 0,
            "breaking_changes_count": 0,
        },
    }

    # user_feedback
    avg_rating = fb_data.get("avg_rating", 0) or 0
    total_ratings = fb_data.get("total_ratings", 0) or 0
    total_installs = fb_data.get("total_installs", 0) or 0
    reports_count = fb_data.get("reports_count", 0) or 0
    _raw_level_counts = fb_data.get("level_counts") or {}
    level_counts = {
        "positive": int(_raw_level_counts.get("positive", 0) or 0),
        "neutral": int(_raw_level_counts.get("neutral", 0) or 0),
        "negative": int(_raw_level_counts.get("negative", 0) or 0),
    }
    positive = level_counts["positive"]
    neutral = level_counts["neutral"]
    negative = level_counts["negative"]
    level_total = positive + neutral + negative

    if total_ratings > 0:
        feedback_score = round((avg_rating / 5.0) * 100)
    elif level_total > 0:
        # 无数值评分时用 level 反馈加权（positive=100, neutral=60, negative=20）
        feedback_score = round(
            (positive * 100 + neutral * 60 + negative * 20) / level_total
        )
    else:
        # 无评分数据时，用安装量体现现实采用度（封顶 80；
        # 一旦接入真实评分，评分将重新成为该维度主信号）。
        if total_installs >= 100:
            feedback_score = 80
        elif total_installs >= 20:
            feedback_score = 70
        elif total_installs >= 5:
            feedback_score = 60
        elif total_installs >= 1:
            feedback_score = 55
        else:
            feedback_score = 50

    user_feedback = {
        "score": feedback_score,
        "weight": 0.10,
        "details": {
            "avg_rating": avg_rating,
            "total_ratings": total_ratings,
            "total_installs": total_installs,
            "reports_count": reports_count,
            "level_counts": level_counts,
        },
    }

    # signature_verifiability (P2)
    signature_verifiability = {
        "score": p2.get("score", 50),
        "weight": 0.20,
        "details": {
            "available": p2.get("available") is True,
            "coverage": p2.get("coverage", 0.0),
            "has_signature": verification.get("signature") is True,
            "has_attestation": verification.get("attestation") is True,
            "has_sbom": verification.get("sbom") is True,
            "verification_statuses": p2.get("verification_statuses", {}),
        },
    }

    return {
        "source_trust": source_trust,
        "author_reputation": author_reputation,
        "metadata_completeness": metadata_completeness,
        "permission_minimization": permission_minimization,
        "scan_results": scan_results,
        "manual_review": manual_review,
        "version_stability": version_stability,
        "user_feedback": user_feedback,
        "signature_verifiability": signature_verifiability,
    }


def _count_permission_categories(
    permissions: dict[str, Any],
    permission_evidence: list[dict[str, Any]] | None = None,
) -> int:
    """Count meaningful high-confidence permission categories."""
    count = 0
    evidence = permission_evidence or []

    def supported(key: str) -> bool:
        if not evidence:
            return True
        for item in evidence:
            if not isinstance(item, dict):
                continue
            capability = str(item.get("capability", ""))
            try:
                confidence = float(item.get("confidence", 0))
            except (TypeError, ValueError):
                confidence = 0.0
            if (
                (capability == key or capability.startswith(key + "."))
                and item.get("status") in {"observed", "declared"}
                and confidence >= 0.75
            ):
                return True
        return False

    for key in ("filesystem", "shell", "network", "environment",
                "credentials", "database", "browser", "external_services"):
        val = permissions.get(key)
        if val and supported(key):
            if isinstance(val, dict) and any(v for v in val.values() if v):
                count += 1
            elif isinstance(val, list) and val:
                count += 1
    return count


def _compute_pass_rate(i2_disc: dict[str, Any]) -> float:
    critical = i2_disc.get("critical_count", 0)
    high = i2_disc.get("high_count", 0)
    medium = i2_disc.get("medium_count", 0)
    low = i2_disc.get("low_count", 0)
    total = critical + high + medium + low
    if total == 0:
        return 100.0
    penalty = (critical * SEVERITY_POINTS.get("critical", 25)
               + high * SEVERITY_POINTS.get("high", 15)
               + medium * SEVERITY_POINTS.get("medium", 8)
               + low * SEVERITY_POINTS.get("low", 3))
    return max(0.0, round(100.0 - penalty, 1))


def _build_evidence_assessment(
    dimensions: dict[str, Any],
    p1: dict[str, Any],
    p2: dict[str, Any],
    c2: dict[str, Any],
    package_metadata: dict[str, Any],
    author_history: dict[str, Any] | None,
    review_records: dict[str, Any] | None,
    feedback: dict[str, Any] | None,
) -> dict[str, Any]:
    """Score available evidence without treating missing signals as failures."""
    feedback_data = feedback if isinstance(feedback, dict) else {}
    feedback_available = any(
        bool(feedback_data.get(key))
        for key in (
            "avg_rating",
            "total_ratings",
            "total_installs",
            "reports_count",
            "level_counts",
        )
    )
    availability = {
        "source_trust": p1.get("available") is True,
        "signature_verifiability": p2.get("available") is True,
        "metadata_completeness": bool(package_metadata),
        "manual_review": bool(review_records),
        "version_stability": bool(package_metadata.get("version")),
        "author_reputation": bool(author_history),
        "user_feedback": feedback_available,
    }
    weights = {
        name: float(dimensions[name]["weight"])
        for name in availability
    }
    total_weight = sum(weights.values())
    effective_weights = {
        name: (
            weight * float(p2.get("coverage", 0.0))
            if name == "signature_verifiability" and availability[name]
            else weight if availability[name]
            else 0.0
        )
        for name, weight in weights.items()
    }
    available_weight = sum(effective_weights.values())
    weighted_score = sum(
        dimensions[name]["score"] * effective_weights[name]
        for name in availability
        if effective_weights[name] > 0
    )
    score = round(weighted_score / available_weight) if available_weight else 50
    coverage = round(available_weight / total_weight, 3) if total_weight else 0.0

    if not available_weight:
        level = "unavailable"
    elif coverage < 0.6:
        level = "limited"
    elif score >= 80 and coverage >= 0.8:
        level = "strong"
    elif score >= 60:
        level = "moderate"
    else:
        level = "limited"

    return {
        "score": score,
        "coverage": coverage,
        "level": level,
        "assessed_dimensions": [name for name in availability if availability[name]],
        "unavailable_dimensions": [
            name for name in availability if not availability[name]
        ],
        "verification_statuses": p2.get("verification_statuses", {}),
        "author_reputation": {
            "status": "assessed" if author_history else "unavailable",
            "level": c2.get("level", "newcomer") if author_history else "unavailable",
            "score": c2.get("score", 50) if author_history else None,
        },
    }


def _build_security_assessment(
    *,
    level: str,
    score: int,
    grade: str,
    i2: dict[str, Any],
    advisory_policy: dict[str, Any],
) -> dict[str, Any]:
    """Build the security-only result consumed by policy decisions."""
    if not i2.get("scan_complete", True):
        status = "inconclusive"
    elif advisory_policy["manual_required"]:
        status = "review_required"
    else:
        status = "conclusive"
    return {
        "score": score,
        "level": level,
        "grade": grade,
        "status": status,
        "input_dimensions": ["permission_minimization", "scan_results"],
        "unresolved_findings": sum(
            1
            for finding in advisory_policy.get("findings", [])
            if isinstance(finding, dict)
            and finding.get("requires_manual_review") is True
        ),
    }


def _review_advisories(scan_report: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(scan_report, dict):
        return []
    raw = scan_report.get("review_advisories", [])
    return [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []


def _advisory_policy(scan_report: dict[str, Any] | None) -> dict[str, Any]:
    advisories = _review_advisories(scan_report)
    deduction = 0
    downgrade_steps = 0
    manual_required = False
    high_priority = False
    semantic_review_pending = False
    finding_review_pending = False
    downgrade_reasons: list[str] = []
    for advisory in advisories:
        security_advisory = advisory.get("category") not in {
            "provenance",
            "metadata_quality",
        }
        try:
            deduction += max(0, int(advisory.get("deduction", 0)))
        except (TypeError, ValueError):
            pass
        try:
            steps = max(0, int(advisory.get("grade_downgrade_steps", 0)))
        except (TypeError, ValueError):
            steps = 0
        if advisory.get("affects_grade") is True and steps:
            downgrade_steps = max(downgrade_steps, steps)
            downgrade_reasons.append(str(advisory.get("title", advisory.get("code", ""))))
        manual_required = manual_required or (
            security_advisory
            and advisory.get("requires_manual_review") is True
        )
        high_priority = high_priority or (
            security_advisory and advisory.get("level") == "high"
        )

    findings = (
        scan_report.get("findings", [])
        if isinstance(scan_report, dict)
        else []
    )
    if isinstance(findings, list):
        finding_review_pending = any(
            isinstance(finding, dict)
            and finding.get("requires_manual_review") is True
            for finding in findings
        )
        semantic_review_pending = any(
            isinstance(finding, dict)
            and finding.get("requires_manual_review") is True
            and finding.get("requires_llm_validation") is True
            for finding in findings
        )
        manual_required = manual_required or finding_review_pending

    return {
        "deduction": min(100, deduction),
        "downgrade_steps": min(1, downgrade_steps),
        "manual_required": manual_required,
        "semantic_review_pending": semantic_review_pending,
        "finding_review_pending": finding_review_pending,
        "high_priority": high_priority,
        "downgrade_reasons": downgrade_reasons,
        "advisories": advisories,
        "findings": findings if isinstance(findings, list) else [],
    }


def rate(
    package_metadata: dict[str, Any],
    scan_report: dict[str, Any] | None = None,
    author_history: dict[str, Any] | None = None,
    review_records: dict[str, Any] | None = None,
    feedback: dict[str, Any] | None = None,
    acquisition_facts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Full 9-step decision engine for trust scoring.

    Args:
        package_metadata: dict conforming to agent-package.schema.json. Its
            source/integrity fields are treated as package claims.
        scan_report: dict conforming to scan-report.schema.json, or None
        author_history: dict with packages_published, avg_historical_score,
                        violations_count
        review_records: dict with status, reviewer_count, last_reviewed_at
        feedback: dict with avg_rating (0-5), total_ratings, total_installs,
                  reports_count — feeds the user_feedback dimension
        acquisition_facts: server-established source/integrity facts and
            independent verification flags. Omitting this argument is
            fail-closed and does not grant provenance credit from claims.

    Returns:
        dict with all fields required by trust-score.schema.json:
        score, package_name, version, calculated_at, model_fingerprint,
        model_version,
        dimensions, explanations, risk_summary
    """
    # --- Step 1: Layer 1 — Provenance ---
    p1 = assess_source_verifiability(package_metadata, acquisition_facts)
    p2 = assess_signature_chain(package_metadata, acquisition_facts)

    # --- Step 2: Layer 2 — Intent ---
    i1 = assess_permission_reasonability(package_metadata)
    i2 = assess_prompt_safety(package_metadata, scan_report)
    i3 = assess_behavior_consistency(i1, i2)

    # --- Step 3: provenance affects declared permissions, never static findings ---
    i1_disc, i2_disc = _apply_layer1_discount(i1, i2, p1, p2)

    # --- Step 3b: Re-compute I3 from discounted I1/I2 for baseline consistency ---
    # Raw I3 (from raw I1/I2) is preserved for veto and explainer trace;
    # discounted I3 feeds into baseline so it matches the discounted I1/I2 levels.
    i3_disc = assess_behavior_consistency(i1_disc, i2_disc)

    # --- Step 4: Layer 3 — Community ---
    c1 = assess_manual_review(review_records or {})
    c2 = assess_author_history(author_history or {})
    advisory_policy = _advisory_policy(scan_report)

    # --- Step 5: Layer discounts on Layer 3 ---
    c2_disc = _apply_layer_discount_c2(c2, p1)

    # --- Step 6: Veto check (uses raw values — veto must not miss real danger) ---
    veto = _check_veto(p1, i2, i3, c1, c2)

    if veto:
        final_level = "untrusted"
        applied_upgrade = False
        applied_downgrade = False
    else:
        # --- Step 7: security-only baseline level ---
        baseline = _determine_baseline(p1, p2, i1_disc, i2_disc, i3_disc, c2_disc)

        # --- Step 8: Upgrade / downgrade ---
        final_level, applied_upgrade, applied_downgrade = _apply_upgrade_downgrade(
            baseline, p1, i2, i3, c1, c2
        )

    # An incomplete scan cannot produce an automatic trusted result.
    if not i2.get("scan_complete", True) and final_level in ("trusted", "low_risk"):
        final_level = "medium_risk"

    # Any unresolved finding routed to a human is review-required, not
    # malicious. Cap the automatic result at C while avoiding a fail-closed E
    # veto. This also covers context-dependent code/network capabilities that
    # do not require an LLM pass.
    if (
        advisory_policy["finding_review_pending"]
        and final_level in ("trusted", "low_risk")
    ):
        final_level = "medium_risk"

    # --- Step 9: derive independent security and evidence indicators ---
    dimensions = _build_dimensions(
        package_metadata,
        p1,
        p2,
        i1_disc,
        i2_disc,
        c1,
        c2_disc,
        fb_data=feedback,
        scan_report=scan_report,
        acquisition_facts=acquisition_facts,
    )

    security_dimension_names = ("permission_minimization", "scan_results")
    dimension_scores = {
        name: dimensions[name]["score"] for name in security_dimension_names
    }
    dimension_weights = {
        name: dimensions[name]["weight"] for name in security_dimension_names
    }
    base_score = derive_score(
        final_level,
        dimension_scores,
        dimension_weights,
        provenance_factor=1.0,
    )
    score = base_score

    # --- Build trace for explainer ---
    trace: dict[str, Any] = {
        "p1": p1,
        "p2": p2,
        "i1": i1,
        "i2": i2,
        "i3": i3,
        "c1": c1,
        "c2": c2,
    }

    # --- Generate explanations ---
    explanations = generate_explanations(
        trace, final_level, veto, applied_upgrade, applied_downgrade
    )
    for advisory in advisory_policy["advisories"]:
        deduction = max(0, int(advisory.get("deduction", 0) or 0))
        if not deduction and advisory.get("affects_grade") is not True:
            continue
        explanations.append({
            "dimension": "review_advisory",
            "message": (
                str(advisory.get("title", advisory.get("code", "Review advisory")))
                + " (advisory only; does not change the security score)"
            ),
            "deduction": 0,
            "evidence": str(advisory.get("evidence", advisory.get("description", "")))[:1000],
        })

    # --- Top risks ---
    top_risks = extract_top_risks(trace)
    if top_risks == ["No significant risks identified"] and (
        advisory_policy["manual_required"] or advisory_policy["high_priority"]
    ):
        top_risks = []
    for advisory in advisory_policy["advisories"]:
        if (
            advisory.get("level") == "high"
            and advisory.get("category") not in {"provenance", "metadata_quality"}
        ):
            title = str(advisory.get("title", "High-priority review advisory"))
            if title not in top_risks:
                top_risks.insert(0, title)
    if advisory_policy["manual_required"]:
        marker = "Manual security review is required for unresolved or high-priority evidence"
        if marker not in top_risks:
            top_risks.insert(0, marker)
    top_risks = top_risks[:5]

    # --- Install recommendation ---
    recommendation = get_recommendation(final_level)
    scan_findings = (
        scan_report.get("findings", [])
        if isinstance(scan_report, dict)
        else []
    )
    requires_confirmation = any(
        isinstance(finding, dict) and finding.get("requires_confirmation") is True
        for finding in scan_findings
    ) or any(
        advisory.get("level") == "high"
        and advisory.get("category") not in {"provenance", "metadata_quality"}
        for advisory in advisory_policy["advisories"]
    )

    grade = LEVEL_TO_GRADE.get(final_level, "C")
    evidence_assessment = _build_evidence_assessment(
        dimensions,
        p1,
        p2,
        c2,
        package_metadata,
        author_history,
        review_records,
        feedback,
    )
    security_assessment = _build_security_assessment(
        level=final_level,
        score=score,
        grade=grade,
        i2=i2,
        advisory_policy=advisory_policy,
    )
    return {
        "score": score,
        "package_name": package_metadata.get("name", "unknown"),
        "version": package_metadata.get("version", "0.0.0"),
        "calculated_at": datetime.now(timezone.utc).isoformat(),
        "model_fingerprint": get_model_fingerprint(),
        "model_version": get_model_version(),
        "score_breakdown": {
            "base_score": base_score,
            "advisory_deduction": 0,
            "final_score": score,
            "grade_is_security_policy": True,
            "evidence_score": evidence_assessment["score"],
            "evidence_coverage": evidence_assessment["coverage"],
            "unapplied_advisory_points": int(advisory_policy["deduction"]),
        },
        "security_assessment": security_assessment,
        "evidence_assessment": evidence_assessment,
        "dimensions": dimensions,
        "explanations": explanations,
        "risk_summary": {
            "level": final_level,
            "grade": grade,
            "top_risks": top_risks,
            "install_recommendation": recommendation,
            "requires_confirmation": requires_confirmation,
            "manual_security_review_required": advisory_policy["manual_required"],
            "review_priority": "high" if advisory_policy["high_priority"] else (
                "manual" if advisory_policy["manual_required"] else "normal"
            ),
            "advisory_grade_downgrade_applied": False,
            "advisory_grade_downgrade_reasons": [],
        },
    }
