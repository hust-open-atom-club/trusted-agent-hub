"""
Weight and threshold configuration for the risk scanner and trust score engine.

Edit this file to adjust scoring behavior. No admin UI needed.
All values are loaded at import time.

Usage:
    from scanners.risk_scanner.weights import SEVERITY_POINTS, GRADE_THRESHOLDS
"""

from __future__ import annotations

SEVERITY_POINTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}

GRADE_THRESHOLDS: dict[str, int] = {
    "A": 80,
    "B": 60,
    "C": 40,
    "D": 20,
}

LLM_TRIGGER_MIN_FINDINGS = 1

LAYER_DISCOUNT = {
    "p1_opaque_to_intent": 0.7,
    "p2_unsigned_to_intent": 0.85,
    "intent_to_community": 0.8,
}

RISK_SEVERITY_BANDS: list[tuple[int, str]] = [
    (81, "CRITICAL"),
    (51, "HIGH"),
    (21, "MEDIUM"),
    (0, "LOW"),
]

RECOMMENDATION_BY_SEVERITY: dict[str, str] = {
    "LOW": "SAFE",
    "MEDIUM": "CAUTION",
    "HIGH": "DO_NOT_INSTALL",
    "CRITICAL": "DO_NOT_INSTALL",
}

GRADE_TO_LEVEL: dict[str, str] = {
    "A": "trusted",
    "B": "low_risk",
    "C": "medium_risk",
    "D": "high_risk",
    "E": "untrusted",
}

LEVEL_TO_GRADE: dict[str, str] = {
    "trusted": "A",
    "low_risk": "B",
    "medium_risk": "C",
    "high_risk": "D",
    "untrusted": "E",
}

GRADE_RECOMMENDATION: dict[str, str] = {
    "A": "自动安装",
    "B": "安装前展示权限声明",
    "C": "展示扫描摘要 + 权限，用户确认",
    "D": "强烈建议不安装，需双重确认",
    "E": "禁止安装",
}

LLM_REVIEW_LABELS = {
    "malicious": "llm:suspected-malicious",
    "negligent": "llm:suspected-negligent",
    "benign": "llm:likely-benign",
}
