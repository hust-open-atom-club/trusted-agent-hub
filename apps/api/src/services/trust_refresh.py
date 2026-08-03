"""Trust-score refresh service — recompute stored scores with real platform signals.

评分在提交扫描时固化，但审核结论、安装量和用户反馈都发生在发布之后。
本服务在发布时和 ``trust-score`` 读取时，用 ``collect_platform_signals()``
重新采集真实信号并调用评分引擎重算，使 ``manual_review`` 与
``user_feedback`` 维度反映实际平台数据，而不是扫描时刻的默认值。

重算结果写回 ``package_versions.data.trust_score``，同时保存一份信号指纹
（``data.trust_score_refresh``）用于判断信号是否变化，避免读取路径重复计算。
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)


def build_package_metadata(
    package: dict[str, Any],
    version: dict[str, Any],
) -> dict[str, Any]:
    """从库中已保存的 package/version 记录重建评分引擎所需元数据。"""
    return {
        "name": package.get("name") or version.get("name") or "unknown",
        "version": version.get("version") or "0.0.0",
        "type": package.get("type") or version.get("type") or "unknown",
        "description": package.get("description")
        or version.get("description")
        or "",
        "author": package.get("author") or version.get("author"),
        "license": package.get("license")
        or version.get("license")
        or "",
        "keywords": package.get("keywords") or version.get("keywords") or [],
        "source": version.get("source") or package.get("source") or {},
        "integrity": version.get("integrity") or {},
        "compatibility": version.get("compatibility")
        or package.get("compatibility")
        or [],
        "permissions": version.get("permissions") or {},
        "installation": version.get("installation") or {},
    }


def compute_signals_fingerprint(
    signals: dict[str, Any],
    version_status: str,
) -> str:
    """对平台信号做确定性指纹，用于判断是否需要重算。"""
    raw = json.dumps(
        {"status": version_status, "signals": signals},
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


class TrustScoreRefreshService:
    """重算并持久化版本信任评分。"""

    def __init__(
        self,
        producer_repository: Any,
        consumer_repository: Any | None = None,
        scorer: Callable[..., dict[str, Any]] | None = None,
    ) -> None:
        self.producer_repo = producer_repository
        self.consumer_repo = consumer_repository
        self._scorer = scorer

    def _load_scorer(self) -> Callable[..., dict[str, Any]]:
        if self._scorer is not None:
            return self._scorer
        # 延迟导入，避免模块加载期循环依赖
        from src.routers.trust import _load_scorer

        return _load_scorer()

    def refresh(
        self,
        version_id: str,
        *,
        force: bool = False,
    ) -> dict[str, Any] | None:
        """按最新平台信号重算 trust_score；信号未变化时返回 None。"""
        from src.services.signals import collect_platform_signals

        version = self.producer_repo.get_version(version_id)
        if version is None:
            return None
        if version.get("status") != "published":
            return None

        package_id = str(version.get("package_id") or "")
        package = self.producer_repo.get_package(package_id) or {}
        signals = collect_platform_signals(
            self.producer_repo,
            version_id=version_id,
            package_id=package_id,
            submitter_id=(
                str(version.get("submitter_id") or "")
                or str(package.get("submitter_id") or "")
                or None
            ),
        )
        fingerprint = compute_signals_fingerprint(
            signals,
            str(version.get("status", "")),
        )
        stored = version.get("trust_score_refresh")
        if not force and stored == fingerprint:
            return None

        scan_report: dict[str, Any] | None = None
        try:
            scan_row = self.producer_repo.get_scan_report(version_id)
        except Exception:  # pragma: no cover - defensive
            scan_row = None
        if scan_row and isinstance(scan_row.get("scan_json"), dict):
            scan_report = scan_row["scan_json"]

        metadata = build_package_metadata(package, version)
        new_ts = self._load_scorer()(
            package_metadata=metadata,
            scan_report=scan_report,
            author_history=signals.get("author_history"),
            review_records=signals.get("review_records"),
            feedback=signals.get("feedback"),
        )
        new_ts["calculated_at"] = datetime.now(timezone.utc).isoformat()

        self.producer_repo.update_version_data(
            version_id,
            {
                "trust_score": new_ts,
                "trust_score_refresh": fingerprint,
            },
        )
        self._sync_grade_and_trust_level(
            version_id,
            version,
            new_ts,
            package_id,
        )
        logger.info(
            "trust score refreshed for %s: score=%s grade=%s",
            version_id,
            new_ts.get("score"),
            (new_ts.get("risk_summary") or {}).get("grade"),
        )
        return new_ts

    def _sync_grade_and_trust_level(
        self,
        version_id: str,
        version: dict[str, Any],
        new_ts: dict[str, Any],
        package_id: str,
    ) -> None:
        """同步 consumer 侧等级投影与包级 grade/risk_level。"""
        from schema.constants import (
            GRADE_TO_RECOMMENDATION,
            GRADE_TO_RISK_LEVEL,
        )

        risk_summary = new_ts.get("risk_summary") or {}
        auto_grade = risk_summary.get("grade")
        manual_grade = version.get("manual_grade")
        effective = manual_grade or auto_grade
        if effective:
            level = GRADE_TO_RISK_LEVEL.get(str(effective), "medium_risk")
            recommendation = GRADE_TO_RECOMMENDATION.get(
                str(effective), "caution"
            )
        else:
            level = "medium_risk"
            recommendation = "caution"

        if self.consumer_repo is not None:
            try:
                self.consumer_repo.upsert_trust_level(
                    version_id=version_id,
                    level=level,
                    install_recommendation=recommendation,
                    top_risks=risk_summary.get("top_risks") or [],
                    explanation="; ".join(
                        e.get("message", "")
                        for e in (new_ts.get("explanations") or [])
                    )
                    or None,
                    model_version=new_ts.get("model_version") or "0.2.0",
                )
            except Exception:
                logger.exception(
                    "consumer trust_level upsert failed for %s",
                    version_id,
                )
        else:
            try:
                self.producer_repo.upsert_trust_level(
                    version_id=version_id,
                    level=level,
                    recommendation=recommendation,
                )
            except Exception:
                logger.exception(
                    "producer trust_level upsert failed for %s",
                    version_id,
                )

        if package_id:
            try:
                self.producer_repo.update_package_data(
                    package_id,
                    {
                        "grade": effective,
                        "risk_level": level,
                    },
                )
            except Exception:
                logger.exception(
                    "package grade sync failed for %s",
                    package_id,
                )
