"""
Derived Score: maps final trust level to a concrete 0-100 integer score.

Level ranges:
    trusted     85–100
    low_risk    65–84
    medium_risk 45–64
    high_risk   25–44
    untrusted    0–24

Within each range, the exact score is influenced by the dimension sub-scores.
Uses only the Python standard library.
"""

from __future__ import annotations

from typing import Any

# Level-to-range mapping: (min, max) inclusive
LEVEL_RANGES: dict[str, tuple[int, int]] = {
    "trusted": (85, 100),
    "low_risk": (65, 84),
    "medium_risk": (45, 64),
    "high_risk": (25, 44),
    "untrusted": (0, 24),
}


def level_to_score_range(level: str) -> tuple[int, int]:
    """Return the (min, max) score range for a given trust level.

    Args:
        level: one of "trusted", "low_risk", "medium_risk", "high_risk", "untrusted"

    Returns:
        (min_score, max_score) inclusive tuple. Defaults to (45, 64) for unknown levels.
    """
    return LEVEL_RANGES.get(level, (45, 64))


def derive_score(
    level: str,
    dimension_scores: dict[str, int],
    dimension_weights: dict[str, float] | None = None,
    provenance_factor: float = 1.0,
) -> int:
    """Map a final trust level to a concrete 0-100 score.

    The score is positioned within the level's range based on how well the
    package performed across all dimensions. When dimension_weights is
    provided, higher-weight dimensions influence the score more heavily;
    otherwise a simple arithmetic mean is used.

    The provenance_factor (0.0–1.0) penalises the dimension average *before*
    positioning within the level range, so weaker provenance naturally pulls
    the score toward the bottom of the level band without breaking the
    level–score contract.

    Args:
        level: final trust level string
        dimension_scores: mapping of dimension name to 0-100 sub-score
        dimension_weights: optional mapping of dimension name to weight (0-1).
            Weights are normalised internally so they do not need to sum to 1.
        provenance_factor: multiplier (0.0–1.0) applied to the weighted average
            to reflect provenance confidence. 1.0 = no penalty.

    Returns:
        integer score between 0 and 100, guaranteed within the level's range
    """
    min_score, max_score = level_to_score_range(level)

    if not dimension_scores:
        # No dimension data — place in middle of range
        return (min_score + max_score) // 2

    # Calculate weighted average dimension score (0-100)
    if dimension_weights:
        total_weight = 0.0
        weighted_sum = 0.0
        for name, score in dimension_scores.items():
            w = dimension_weights.get(name, 0.0)
            weighted_sum += score * w
            total_weight += w
        if total_weight > 0:
            avg_dim = weighted_sum / total_weight
        else:
            scores = list(dimension_scores.values())
            avg_dim = sum(scores) / len(scores)
    else:
        scores = list(dimension_scores.values())
        avg_dim = sum(scores) / len(scores)

    # Apply provenance penalty to the averaged dimension signal before
    # positioning.  Weaker provenance → lower effective quality → score
    # slides toward the bottom of the level's range.
    penalised_avg = avg_dim * provenance_factor

    # Map penalised average dimension score (0-100) to position within level range
    # penalised_avg=0   → min_score
    # penalised_avg=100 → max_score
    range_size = max_score - min_score
    position = round(min_score + (penalised_avg / 100.0) * range_size)

    # Clamp to ensure it stays within the level's range
    return max(min_score, min(max_score, position))


GRADE_RECOMMENDATION: dict[str, str] = {
    "A": "自动安装",
    "B": "安装前展示权限声明",
    "C": "展示扫描摘要 + 权限，用户确认",
    "D": "强烈建议不安装，需双重确认",
    "E": "禁止安装",
}

LEVEL_TO_GRADE: dict[str, str] = {
    "trusted": "A",
    "low_risk": "B",
    "medium_risk": "C",
    "high_risk": "D",
    "untrusted": "E",
}


def level_to_grade(level: str) -> str:
    return LEVEL_TO_GRADE.get(level, "C")


def get_recommendation(level: str) -> str:
    """Map trust level to an install recommendation.

    Args:
        level: trust level string

    Returns:
        recommendation string: "safe", "review_recommended", "caution",
        "not_recommended", or "blocked"
    """
    mapping: dict[str, str] = {
        "trusted": "safe",
        "low_risk": "review_recommended",
        "medium_risk": "caution",
        "high_risk": "not_recommended",
        "untrusted": "blocked",
    }
    return mapping.get(level, "caution")
