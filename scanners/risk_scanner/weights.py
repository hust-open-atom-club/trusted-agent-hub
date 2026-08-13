"""
Weight and threshold configuration for the risk scanner and trust score engine.

Edit this file to adjust scoring behavior. No admin UI needed.
All values are loaded at import time.

Usage:
    from scanners.risk_scanner.weights import SEVERITY_POINTS, SEVERITY_ORDER

Used by:
    - intent.py (I2 prompt safety scoring)
    - engine.py (_compute_pass_rate)
"""

from __future__ import annotations

SEVERITY_POINTS: dict[str, int] = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
    "info": 0,
}

SEVERITY_ORDER: list[str] = ["info", "low", "medium", "high", "critical"]

LLM_LABEL_SEVERITY_ADJUST: dict[str, int] = {
    "llm:likely-benign": -1,
    "llm:suspected-malicious": +1,
    "llm:suspected-negligent": 0,
    "llm:uncertain": 0,
    "llm:unavailable": 0,
}

GRADE_THRESHOLDS_REF: dict[str, int] = {
    "A": 80,
    "B": 60,
    "C": 40,
    "D": 20,
}

LLM_TRIGGER_MIN_FINDINGS = 1

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

LLM_REVIEW_LABELS: dict[str, str] = {
    "malicious": "llm:suspected-malicious",
    "negligent": "llm:suspected-negligent",
    "benign": "llm:likely-benign",
}

# =============================================================================
# SR-017: MCP tool description poisoning detection
# =============================================================================

# ② 语义漂移阈值: description 与 permissions 声明的余弦相似度低于该值 → low 提示
# 标定于 2026-07-31：0.4 会误报正常短功能描述（如 list_tables 0.379），下调至 0.35
TOOL_POISONING_DESC_PERM_THRESHOLD: float = 0.35

# ① 确定性投毒严重度（高危词 + 权限声明矛盾）
TOOL_POISONING_KEYWORD_SEVERITY: str = "high"

# ① 命中 ≥2 个工具 → 升级为 critical
TOOL_POISONING_MULTI_COUNT: int = 2
TOOL_POISONING_MULTI_SEVERITY: str = "critical"

# ② 语义漂移提示严重度
TOOL_POISONING_DRIFT_SEVERITY: str = "low"

# 无权限声明时，高危词命中 → 提示级（无法判定矛盾，仅提醒人工审核）
TOOL_POISONING_NO_PERM_SEVERITY: str = "low"
