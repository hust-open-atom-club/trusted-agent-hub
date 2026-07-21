"""
Decision Engine: orchestrates the three-layer trust assessment funnel.

Pipeline (9 steps):
  1. Calculate P1, P2 (Layer 1 — Provenance)
  2. Calculate I1, I2, I3 (Layer 2 — Intent)
  3. Apply Layer 1 discount to Layer 2 results
  4. Calculate C1, C2 (Layer 3 — Community)
  5. Apply layer discounts to Layer 3
  6. Veto check (V1–V6)
  7. Determine baseline level (three-color: red / yellow / green)
  8. Apply upgrade / downgrade rules
  9. Derive 0–100 score from final level

Six veto rules:
  V1: C1 = rejected        → untrusted
  V2: I2 = dangerous       → untrusted
  V3: I3 = deceptive       → untrusted
  V4: I3 = malicious       → untrusted
  V5: P1 = opaque & I2 = dangerous → untrusted
  V6: P1 = opaque & C2 = tainted   → untrusted

All functions operate on plain dicts. Uses only the Python standard library.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .provenance import assess_source_verifiability, assess_signature_chain
from .intent import (
    assess_permission_reasonability,
    assess_prompt_safety,
    assess_behavior_consistency,
)
from .community import assess_manual_review, assess_author_history
from .derived_score import derive_score, get_recommendation
from .explainer import generate_explanations, extract_top_risks

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
    """Step 3: Apply Layer 1 provenance discount to Layer 2 intent scores.

    When source is opaque or signature chain is broken, the intent assessments
    carry less weight — both their numeric scores AND their severity counts
    are discounted, because we have less confidence in the signal.

    Args:
        i1_result: I1 assessment result dict
        i2_result: I2 assessment result dict
        p1_result: P1 assessment result dict
        p2_result: P2 assessment result dict

    Returns:
        (discounted_i1, discounted_i2) — new dicts with adjusted scores and counts
    """
    p1_level = p1_result.get("level", "opaque")
    p2_level = p2_result.get("level", "none")

    # Discount factors
    factor = 1.0
    if p1_level == "opaque":
        factor *= 0.7
    elif p1_level == "traceable":
        factor *= 0.85
    if p2_level == "none":
        factor *= 0.8
    elif p2_level == "partial":
        factor *= 0.9

    i1_discounted = dict(i1_result)
    i2_discounted = dict(i2_result)
    i1_discounted["score"] = max(5, round(i1_result.get("score", 50) * factor))
    i2_discounted["score"] = max(5, round(i2_result.get("score", 50) * factor))
    i1_discounted["discount_applied"] = factor < 1.0
    i2_discounted["discount_applied"] = factor < 1.0

    # Also discount count fields so baseline risk assessment sees weaker signals
    if factor < 1.0:
        i1_discounted["danger_count"] = max(0, round(i1_result.get("danger_count", 0) * factor))
        i2_discounted["critical_count"] = max(0, round(i2_result.get("critical_count", 0) * factor))
        i2_discounted["high_count"] = max(0, round(i2_result.get("high_count", 0) * factor))
        i2_discounted["medium_count"] = max(0, round(i2_result.get("medium_count", 0) * factor))
        i2_discounted["low_count"] = max(0, round(i2_result.get("low_count", 0) * factor))

        # Re-evaluate I1 level from discounted danger_count so baseline uses
        # the discounted severity consistently.
        dc = i1_discounted["danger_count"]
        if dc == 0:
            i1_discounted["level"] = "minimal"
        elif dc <= 2:
            i1_discounted["level"] = "acceptable"
        elif dc <= 7:
            i1_discounted["level"] = "excessive"
        else:
            i1_discounted["level"] = "dangerous"

        # Re-evaluate I2 level from discounted counts (downgrade only).
        # Without the original findings list we cannot distinguish between
        # dangerous-category and non-dangerous-category findings, so we
        # conservatively only downgrade when counts drop below thresholds.
        old_i2_level = i2_result.get("level", "safe")
        i2_dc = i2_discounted.get("critical_count", 0)
        i2_dh = i2_discounted.get("high_count", 0)
        i2_dm = i2_discounted.get("medium_count", 0)
        i2_dl = i2_discounted.get("low_count", 0)

        # dangerous → suspicious when no more critical/high (count only)
        if old_i2_level == "dangerous" and i2_dc == 0 and i2_dh == 0:
            i2_discounted["level"] = "suspicious"
        # suspicious → safe when all counts are below thresholds
        if old_i2_level in ("dangerous", "suspicious") \
                and i2_dc == 0 and i2_dh == 0 and i2_dm <= 2 and i2_dl <= 5:
            i2_discounted["level"] = "safe"

    return i1_discounted, i2_discounted


def _apply_layer_discount_c2(
    c2_result: dict[str, Any],
    p1_result: dict[str, Any],
) -> dict[str, Any]:
    """Step 5: Apply Layer 1 discount to C2 (author history).

    An opaque source weakens the reliability of author history claims.

    Args:
        c2_result: C2 assessment result dict
        p1_result: P1 assessment result dict

    Returns:
        discounted C2 result dict
    """
    p1_level = p1_result.get("level", "opaque")
    factor = 0.7 if p1_level == "opaque" else 0.9 if p1_level == "traceable" else 1.0

    c2_discounted = dict(c2_result)
    c2_discounted["score"] = max(5, round(c2_result.get("score", 50) * factor))
    c2_discounted["discount_applied"] = factor < 1.0
    return c2_discounted


def _check_veto(
    p1: dict[str, Any],
    i2: dict[str, Any],
    i3: dict[str, Any],
    c1: dict[str, Any],
    c2: dict[str, Any],
) -> str | None:
    """Step 6: Check all six veto rules.  Returns the triggered veto name or None.

    V1: C1 = rejected        → untrusted
    V2: I2 = dangerous       → untrusted
    V3: I3 = deceptive       → untrusted
    V4: I3 = malicious       → untrusted
    V5: P1 = opaque & I2 = dangerous → untrusted
    V6: P1 = opaque & C2 = tainted   → untrusted
    """
    p1_level = p1.get("level", "")
    i2_level = i2.get("level", "")
    i3_level = i3.get("level", "")
    c1_level = c1.get("level", "")
    c2_level = c2.get("level", "")

    if c1_level == "rejected":
        return "V1: manual review rejected"
    if i2_level == "dangerous":
        return "V2: scan found dangerous content"
    if i3_level == "deceptive":
        return "V3: deceptive behavior detected"
    if i3_level == "malicious":
        return "V4: malicious behavior detected"
    if p1_level == "opaque" and i2_level == "dangerous":
        return "V5: opaque source with dangerous scan findings"
    if p1_level == "opaque" and c2_level == "tainted":
        return "V6: opaque source with tainted author history"

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

    Counts risk factors from all layers and maps to a baseline:
      green  (0 risk factors)  → low_risk baseline
      yellow (1-2 factors)     → medium_risk baseline
      red    (3+ factors)      → high_risk baseline

    Risk factors (each adds 1 unless noted):
      - P1 = opaque
      - P2 = none (only when P1 is NOT opaque — expected otherwise)
      - I1 = excessive  (+1), I1 = dangerous (+2)
      - I2 = suspicious (+1)   [only for actual findings, not missing-scan default]
                                [I2=dangerous already caught by veto]
      - I3 = overreaching (+1) [I3=deceptive/malicious caught by veto]
      - C2 = inconsistent (+1), C2 = tainted (+2)
    """
    risk: int = 0

    p1_level = p1.get("level", "")
    p2_level = p2.get("level", "")
    i1_level = i1.get("level", "")
    i2_level = i2.get("level", "")
    i3_level = i3.get("level", "")
    c2_level = c2.get("level", "")

    if p1_level == "opaque":
        risk += 1
    # P2=none only counts when source is otherwise verifiable; opaque source
    # already captures the concern, and missing signature is expected.
    if p2_level == "none" and p1_level != "opaque":
        risk += 1
    if i1_level == "excessive":
        risk += 1
    elif i1_level == "dangerous":
        risk += 2
    # I2=suspicious only counts when due to actual findings from a real scan,
    # not when the scan report is missing entirely.
    if i2_level == "suspicious" and i2.get("scan_available", True) \
            and (i2.get("critical_count", 0) > 0 or i2.get("high_count", 0) > 0
                 or i2.get("medium_count", 0) > 2):
        risk += 1
    if i3_level == "overreaching":
        risk += 1
    # I3=gap is "no data" — does not count as a risk factor
    if c2_level == "inconsistent":
        risk += 1
    elif c2_level == "tainted":
        risk += 2

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

    Downgrade rule:
      P1 = opaque AND C2 = newcomer → -1 level (worse)

    Args:
        baseline: the baseline level from Step 7
        p1, i2, i3, c1, c2: assessment result dicts

    Returns:
        (final_level, upgrade_applied, downgrade_applied)
    """
    level = baseline
    upgrade_applied = False
    downgrade_applied = False

    p1_level = p1.get("level", "")
    i2_level = i2.get("level", "")
    i3_level = i3.get("level", "")
    c1_level = c1.get("level", "")
    c2_level = c2.get("level", "")

    # Upgrade: approved + safe + consistent + verifiable provenance
    # P1=opaque blocks the upgrade — an unverifiable source cannot be
    # "washed clean" by a human review alone.
    if c1_level == "approved" and i2_level == "safe" and i3_level == "consistent" \
            and p1_level != "opaque":
        upgrade_applied = True
        level = _shift_level(level, -1)  # move up (better)

    # Downgrade: opaque + newcomer — only applies when source concern
    # is not already priced into the baseline (i.e., baseline is low_risk
    # or trusted).  If baseline is already medium_risk or worse, the opaque
    # source risk is already accounted for.
    if p1_level == "opaque" and c2_level == "newcomer" \
            and baseline in ("low_risk", "trusted"):
        downgrade_applied = True
        level = _shift_level(level, 1)  # move down (worse)

    return level, upgrade_applied, downgrade_applied


def _build_dimensions(
    package_metadata: dict[str, Any],
    p1: dict[str, Any],
    p2: dict[str, Any],
    i1_disc: dict[str, Any],
    i2_disc: dict[str, Any],
    c1: dict[str, Any],
    c2_disc: dict[str, Any],
) -> dict[str, Any]:
    """Build the nine-dimension output object per trust-score.schema.json.

    Maps our internal assessments to the schema's nine dimension slots.
    """
    source = package_metadata.get("source", {}) or {}
    integrity = package_metadata.get("integrity", {}) or {}
    permissions = package_metadata.get("permissions", {}) or {}
    name = package_metadata.get("name", "")
    version = package_metadata.get("version", "")
    description = package_metadata.get("description", "")
    license_val = package_metadata.get("license", "")
    keywords = package_metadata.get("keywords", []) or []

    # source_trust (P1)
    source_trust = {
        "score": p1.get("score", 50),
        "weight": 0.15,
        "details": {
            "is_verified_owner": source.get("verified_owner", False),
            "source_type": source.get("type", "unknown"),
            "repo_age_days": 0,
            "has_commit_hash": bool(source.get("commit_hash", "")),
            "has_integrity_hash": bool(integrity.get("sha256", "")),
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
        "weight": 0.10,
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
        "weight": 0.15,
        "details": {
            "total_permissions": _count_permission_categories(permissions),
            "high_risk_permissions": i1_disc.get("danger_count", 0),
            "unnecessary_permissions": [],
        },
    }

    # scan_results (I2)
    scan_results = {
        "score": i2_disc.get("score", 50),
        "weight": 0.20,
        "details": {
            "critical_findings": i2_disc.get("critical_count", 0),
            "high_findings": i2_disc.get("high_count", 0),
            "medium_findings": i2_disc.get("medium_count", 0),
            "low_findings": i2_disc.get("low_count", 0),
            "scan_pass_rate": _compute_pass_rate(i2_disc),
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
    is_stable = not ("alpha" in version.lower() or "beta" in version.lower()
                     or "rc" in version.lower() or version.startswith("0."))
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

    # user_feedback (no data in scope — neutral)
    user_feedback = {
        "score": 50,
        "weight": 0.10,
        "details": {
            "avg_rating": 0,
            "total_ratings": 0,
            "total_installs": 0,
            "reports_count": 0,
        },
    }

    # signature_verifiability (P2)
    signature_verifiability = {
        "score": p2.get("score", 50),
        "weight": 0.05,
        "details": {
            "has_signature": bool(integrity.get("signature", "")),
            "has_attestation": bool(integrity.get("attestation_url", "")),
            "has_sbom": bool(integrity.get("sbom_url", "")),
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


def _count_permission_categories(permissions: dict[str, Any]) -> int:
    """Count how many permission categories have meaningful content."""
    count = 0
    for key in ("filesystem", "shell", "network", "environment",
                "credentials", "database", "browser", "external_services"):
        val = permissions.get(key)
        if val:
            if isinstance(val, dict) and any(v for v in val.values() if v):
                count += 1
            elif isinstance(val, list) and val:
                count += 1
    return count


def _compute_pass_rate(i2_disc: dict[str, Any]) -> float:
    """Compute a rough scan pass rate 0-100."""
    critical = i2_disc.get("critical_count", 0)
    high = i2_disc.get("high_count", 0)
    medium = i2_disc.get("medium_count", 0)
    low = i2_disc.get("low_count", 0)
    total = critical + high + medium + low
    if total == 0:
        return 100.0
    penalty = critical * 20 + high * 10 + medium * 5 + low * 2
    return max(0.0, round(100.0 - penalty, 1))


def _compute_provenance_factor(
    p1: dict[str, Any],
    p2: dict[str, Any],
) -> float:
    """Compute a provenance multiplier (0.0–1.0) applied to the final score.

    When source provenance is weak, the entire trust score is penalised
    because the package's origin cannot be independently verified.
    The factor is multiplicative so it scales proportionally with the score.

    Returns:
        float between 0.0 and 1.0 representing the provenance confidence.
    """
    factor = 1.0

    p1_level = p1.get("level", "opaque")
    if p1_level == "opaque":
        factor *= 0.85
    elif p1_level == "traceable":
        factor *= 0.95
    # verified → no penalty

    p2_level = p2.get("level", "none")
    if p2_level == "none":
        factor *= 0.92
    elif p2_level == "partial":
        factor *= 0.97

    return factor


def rate(
    package_metadata: dict[str, Any],
    scan_report: dict[str, Any] | None = None,
    author_history: dict[str, Any] | None = None,
    review_records: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Full 9-step decision engine for trust scoring.

    Args:
        package_metadata: dict conforming to agent-package.schema.json
        scan_report: dict conforming to scan-report.schema.json, or None
        author_history: dict with packages_published, avg_historical_score,
                        violations_count
        review_records: dict with status, reviewer_count, last_reviewed_at

    Returns:
        dict with all fields required by trust-score.schema.json:
        score, package_name, version, calculated_at, model_version,
        dimensions, explanations, risk_summary
    """
    # --- Step 1: Layer 1 — Provenance ---
    p1 = assess_source_verifiability(package_metadata)
    p2 = assess_signature_chain(package_metadata)

    # --- Step 2: Layer 2 — Intent ---
    i1 = assess_permission_reasonability(package_metadata)
    i2 = assess_prompt_safety(package_metadata, scan_report)
    i3 = assess_behavior_consistency(i1, i2)

    # --- Step 3: Layer 1 discount on Layer 2 ---
    i1_disc, i2_disc = _apply_layer1_discount(i1, i2, p1, p2)

    # --- Step 3b: Re-compute I3 from discounted I1/I2 for baseline consistency ---
    # Raw I3 (from raw I1/I2) is preserved for veto and explainer trace;
    # discounted I3 feeds into baseline so it matches the discounted I1/I2 levels.
    i3_disc = assess_behavior_consistency(i1_disc, i2_disc)

    # --- Step 4: Layer 3 — Community ---
    c1 = assess_manual_review(review_records or {})
    c2 = assess_author_history(author_history or {})

    # --- Step 5: Layer discounts on Layer 3 ---
    c2_disc = _apply_layer_discount_c2(c2, p1)

    # --- Step 6: Veto check (uses raw values — veto must not miss real danger) ---
    veto = _check_veto(p1, i2, i3, c1, c2)

    if veto:
        final_level = "untrusted"
        applied_upgrade = False
        applied_downgrade = False
    else:
        # --- Step 7: Baseline level (uses discounted I1/I2/I3/C2) ---
        baseline = _determine_baseline(p1, p2, i1_disc, i2_disc, i3_disc, c2_disc)

        # --- Step 8: Upgrade / downgrade ---
        final_level, applied_upgrade, applied_downgrade = _apply_upgrade_downgrade(
            baseline, p1, i2, i3, c1, c2
        )

    # --- Step 9: Derive 0-100 score (weighted by declared dimension weights) ---
    dimensions = _build_dimensions(package_metadata, p1, p2, i1_disc, i2_disc, c1, c2_disc)

    dimension_scores: dict[str, int] = {
        name: dim["score"] for name, dim in dimensions.items()
    }
    dimension_weights: dict[str, float] = {
        name: dim["weight"] for name, dim in dimensions.items()
    }
    score = derive_score(final_level, dimension_scores, dimension_weights,
                         provenance_factor=_compute_provenance_factor(p1, p2))

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

    # --- Top risks ---
    top_risks = extract_top_risks(trace)

    # --- Install recommendation ---
    recommendation = get_recommendation(final_level)

    grade = _to_grade(final_level)
    return {
        "score": score,
        "package_name": package_metadata.get("name", "unknown"),
        "version": package_metadata.get("version", "0.0.0"),
        "calculated_at": datetime.now(timezone.utc).isoformat(),
        "model_version": "0.2.0",
        "dimensions": dimensions,
        "explanations": explanations,
        "risk_summary": {
            "level": final_level,
            "grade": grade,
            "top_risks": top_risks,
            "install_recommendation": recommendation,
        },
    }


_LEVEL_TO_GRADE: dict[str, str] = {
    "trusted": "A",
    "low_risk": "B",
    "medium_risk": "C",
    "high_risk": "D",
    "untrusted": "E",
}


def _to_grade(level: str) -> str:
    return _LEVEL_TO_GRADE.get(level, "C")
