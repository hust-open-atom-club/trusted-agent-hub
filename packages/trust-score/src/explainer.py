"""
Explainer: generates human-readable explanations from the decision trace.

Produces the "explanations" array required by trust-score.schema.json:
each entry has dimension, message, deduction (int), and optional evidence.

Uses only the Python standard library.
"""

from __future__ import annotations

from typing import Any


def generate_explanations(
    trace: dict[str, Any],
    final_level: str,
    applied_veto: str | None,
    applied_upgrade: bool,
    applied_downgrade: bool,
) -> list[dict[str, Any]]:
    """Generate human-readable explanations from the engine decision trace.

    Args:
        trace: dict containing all layer assessment results:
            p1, p2 — Layer 1 results
            i1, i2, i3 — Layer 2 results
            c1, c2 — Layer 3 results
        final_level: the final trust level after all rules
        applied_veto: veto rule name if one was triggered, else None
        applied_upgrade: whether an upgrade rule was applied
        applied_downgrade: whether a downgrade rule was applied

    Returns:
        list of explanation dicts, each with dimension, message, deduction, evidence
    """
    explanations: list[dict[str, Any]] = []

    # --- Source verifiability (P1 → source_trust) ---
    p1: dict[str, Any] = trace.get("p1", {})
    _explain_dimension(explanations, "source_trust", 100,
                       p1.get("level", "opaque"),
                       p1.get("evidence", []),
                       {"verified": 0, "traceable": -15, "opaque": -30})

    # Signature/SBOM/attestation gaps are emitted as explicit -2 review
    # advisories by the scanner. Do not manufacture a second nominal P2
    # deduction here.

    # --- Permission reasonability (I1 → permission_minimization) ---
    i1: dict[str, Any] = trace.get("i1", {})
    _explain_dimension(explanations, "permission_minimization", 100,
                       i1.get("level", "acceptable"),
                       i1.get("evidence", []),
                       {"minimal": 0, "acceptable": -5, "excessive": -20, "dangerous": -50})

    # --- Prompt safety (I2 → scan_results) ---
    i2: dict[str, Any] = trace.get("i2", {})
    _explain_dimension(explanations, "scan_results", 100,
                       i2.get("level", "safe"),
                       i2.get("evidence", []),
                       {"safe": 0, "suspicious": -20, "dangerous": -60})

    # --- Behavior consistency (I3 — informational, not a schema dimension) ---
    i3: dict[str, Any] = trace.get("i3", {})
    i3_level = i3.get("level", "consistent")
    if i3_level != "consistent":
        deduction_map = {"gap": -10, "overreaching": -20, "deceptive": -60, "malicious": -80}
        explanations.append({
            "dimension": "permission_minimization",
            "message": f"Behavior consistency check: {i3_level}",
            "deduction": deduction_map.get(i3_level, 0),
            "evidence": "; ".join(i3.get("evidence", [])),
        })

    # --- Manual review (C1 → manual_review) ---
    c1: dict[str, Any] = trace.get("c1", {})
    _explain_dimension(explanations, "manual_review", 100,
                       c1.get("level", "pending"),
                       c1.get("evidence", []),
                       {"approved": 0, "pending": -10, "changes_requested": -25, "rejected": -80})

    # --- Author history (C2 → author_reputation) ---
    c2: dict[str, Any] = trace.get("c2", {})
    _explain_dimension(explanations, "author_reputation", 100,
                       c2.get("level", "newcomer"),
                       c2.get("evidence", []),
                       {"consistent_good": 0, "newcomer": -15, "inconsistent": -30, "tainted": -60})

    # --- Veto ---
    if applied_veto:
        explanations.append({
            "dimension": "scan_results",
            "message": f"Veto triggered: {applied_veto} — package forced to untrusted",
            "deduction": -100,
            "evidence": applied_veto,
        })

    # --- Upgrade / Downgrade ---
    if applied_upgrade:
        explanations.append({
            "dimension": "manual_review",
            "message": "Upgrade applied: approved review + safe scan + consistent behavior",
            "deduction": 15,
            "evidence": "upgrade_rule_1",
        })
    if applied_downgrade:
        explanations.append({
            "dimension": "source_trust",
            "message": "Downgrade applied: opaque source + newcomer author",
            "deduction": -15,
            "evidence": "downgrade_rule_1",
        })

    return explanations


def _explain_dimension(
    explanations: list[dict[str, Any]],
    dimension: str,
    base_score: int,
    level: str,
    evidence_list: list[str],
    deduction_map: dict[str, int],
) -> None:
    """Add an explanation entry for a scored dimension.

    Args:
        explanations: the list being built
        dimension: schema dimension name (e.g. "source_trust")
        base_score: starting score before deduction (typically 100)
        level: the assessed level for this dimension
        evidence_list: evidence strings from the assessment
        deduction_map: mapping of level string to deduction amount (negative)
    """
    deduction = deduction_map.get(level, 0)
    if deduction == 0:
        return  # no deduction means nothing to explain

    message = f"{dimension}: assessed as '{level}'"
    explanations.append({
        "dimension": dimension,
        "message": message,
        "deduction": deduction,
        "evidence": "; ".join(evidence_list[:3]),  # cap at 3 evidence items
    })


def extract_top_risks(trace: dict[str, Any]) -> list[str]:
    """Extract the top risk descriptions from the decision trace.

    Args:
        trace: the full decision trace with all layer results

    Returns:
        list of up to 5 risk description strings
    """
    risks: list[str] = []

    # Check each layer for concerning signals
    p1 = trace.get("p1", {})
    if p1.get("level") == "opaque":
        risks.append("Source provenance is opaque — origin cannot be verified")

    p2 = trace.get("p2", {})
    if p2.get("level") == "none":
        risks.append("No content integrity hash or signature")

    i1 = trace.get("i1", {})
    i1_level = i1.get("level", "")
    if i1_level == "dangerous":
        risks.append("Dangerous permission combination declared")
    elif i1_level == "excessive":
        risks.append("Permissions are excessive for package type")

    i2 = trace.get("i2", {})
    i2_level = i2.get("level", "")
    if i2_level == "dangerous":
        risks.append("Scan found critical/high-severity dangerous findings")
    elif i2_level == "suspicious":
        risks.append("Scan results are suspicious or unavailable")

    i3 = trace.get("i3", {})
    i3_level = i3.get("level", "")
    if i3_level in ("deceptive", "malicious"):
        risks.append("Behavior inconsistency indicates deception or malicious intent")
    elif i3_level == "overreaching":
        risks.append("Declared permissions exceed what scan findings suggest is needed")

    c1 = trace.get("c1", {})
    c1_level = c1.get("level", "")
    if c1_level == "rejected":
        risks.append("Package was rejected during manual review")

    c2 = trace.get("c2", {})
    c2_level = c2.get("level", "")
    if c2_level == "tainted":
        risks.append("Author has a tainted history with serious violations")
    elif c2_level == "inconsistent":
        risks.append("Author has an inconsistent publishing record")

    # If no risks found, add a positive note
    if not risks:
        risks.append("No significant risks identified")

    return risks[:5]
