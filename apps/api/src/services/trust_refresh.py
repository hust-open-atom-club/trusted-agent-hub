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
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Callable

from schema.constants import HASH_SCOPE_SCANNED_SOURCE

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


def build_acquisition_facts(
    version: dict[str, Any],
    scan_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Load server-owned provenance facts for a stored version.

    Legacy records without this namespace intentionally return an empty
    mapping so the scorer fails closed instead of reviving manifest claims.
    """
    candidates: list[Any] = [
        version.get("acquisition_facts"),
    ]
    if isinstance(scan_report, dict):
        provenance = scan_report.get("provenance")
        if isinstance(provenance, dict):
            candidates.append(provenance.get("acquisition_facts"))
    for candidate in candidates:
        if isinstance(candidate, dict):
            facts = deepcopy(candidate)
            integrity = facts.get("integrity")
            if isinstance(integrity, dict):
                # Facts written before hash scope markers existed are still
                # server-owned scan hashes.  Recover their scope, but infer
                # completeness only from the persisted scan status; never
                # assume a bounded hash is complete when that evidence is
                # unavailable.
                if "hash_scope" not in integrity:
                    integrity["hash_scope"] = HASH_SCOPE_SCANNED_SOURCE
                if "is_complete" not in integrity:
                    scan_status = (
                        scan_report.get("scan_status")
                        if isinstance(scan_report, dict)
                        else None
                    )
                    integrity["is_complete"] = (
                        isinstance(scan_status, dict)
                        and scan_status.get("state") == "complete"
                        and scan_status.get("complete") is True
                    )
                facts["integrity"] = integrity
            return facts
    return {}


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
        model_fingerprint: str | None = None,
    ) -> None:
        self.producer_repo = producer_repository
        self.consumer_repo = consumer_repository
        self._scorer = scorer
        self._model_fingerprint = model_fingerprint
        self._model_version = (
            f"auto-{model_fingerprint[:12]}"
            if model_fingerprint
            else None
        )

    def _load_scorer(self) -> Callable[..., dict[str, Any]]:
        if self._scorer is not None:
            return self._scorer
        # 延迟导入，避免模块加载期循环依赖
        from src.routers.trust import _load_scorer

        return _load_scorer()

    def _load_model_identity(self) -> tuple[str, str]:
        """Resolve the scorer identity once for this refresh service."""
        if self._model_fingerprint is not None:
            return self._model_fingerprint, self._model_version or (
                f"auto-{self._model_fingerprint[:12]}"
            )

        # Keep the dynamic import here so API startup and test doubles do not
        # need to import the trust-score package eagerly.
        from src.routers.trust import _load_score_model

        _, fingerprint, version = _load_score_model()
        self._model_fingerprint = fingerprint
        self._model_version = version
        return fingerprint, version

    @property
    def model_fingerprint(self) -> str:
        """Return the identity used by this service's scorer."""
        return self._load_model_identity()[0]

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
        # A model-identity change is deliberately not a lazy-refresh trigger.
        # The read path can be called for every published version, so treating
        # a historical version mismatch as a reason to refresh would cause a
        # deployment-wide rescore (and potentially a deployment-wide score
        # drop) in one request wave.  Model upgrades must use ``force=True``
        # through an explicit, observable backfill job.
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
        acquisition_facts = build_acquisition_facts(
            version,
            scan_report,
        )
        model_fingerprint, model_version = self._load_model_identity()
        new_ts = self._load_scorer()(
            package_metadata=metadata,
            scan_report=scan_report,
            author_history=signals.get("author_history"),
            review_records=signals.get("review_records"),
            feedback=signals.get("feedback"),
            acquisition_facts=acquisition_facts,
        )
        if not isinstance(new_ts, dict):
            raise TypeError("trust-score scorer must return a dictionary")
        reported_fingerprint = new_ts.get("model_fingerprint")
        if (
            reported_fingerprint is not None
            and reported_fingerprint != model_fingerprint
        ):
            raise ValueError(
                "trust-score scorer returned a model fingerprint that does "
                "not match the loaded model"
            )
        # The refresh service is the persistence boundary.  Stamp both fields
        # centrally so test doubles and legacy callers cannot write a stale
        # manually-maintained version identifier.
        new_ts["model_fingerprint"] = model_fingerprint
        new_ts["model_version"] = model_version
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
                    model_version=(
                        new_ts.get("model_version")
                    ),
                    model_fingerprint=new_ts.get("model_fingerprint"),
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
                    model_version=new_ts.get("model_version"),
                    model_fingerprint=new_ts.get("model_fingerprint"),
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


class TrustScoreBackfillService:
    """Idempotently migrate every published version to the active model.

    A rerun skips versions already written with ``target_model_fingerprint``.
    Individual failures are retried and retained in the returned summary so
    operators can monitor progress and safely rerun only unfinished work.
    """

    def __init__(
        self,
        refresh_service: TrustScoreRefreshService,
        *,
        target_model_fingerprint: str | None = None,
    ) -> None:
        self.refresh_service = refresh_service
        self.producer_repo = refresh_service.producer_repo
        self.target_model_fingerprint = (
            target_model_fingerprint or refresh_service.model_fingerprint
        )
        self.target_model_version = f"auto-{self.target_model_fingerprint[:12]}"

    def run(
        self,
        *,
        batch_size: int = 100,
        max_attempts: int = 3,
    ) -> dict[str, Any]:
        if batch_size < 1:
            raise ValueError("batch_size must be positive")
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")

        summary: dict[str, Any] = {
            "model_fingerprint": self.target_model_fingerprint,
            "model_version": self.target_model_version,
            "scanned": 0,
            "updated": 0,
            "skipped": 0,
            "failed": [],
        }
        offset = 0
        while True:
            rows = self.producer_repo.list_versions_by_status(
                status="published",
                limit=batch_size,
                offset=offset,
            )
            if not rows:
                break

            for row in rows:
                version_id = str(row.get("version_id") or row.get("id") or "")
                if not version_id:
                    summary["failed"].append({
                        "version_id": "",
                        "attempts": 0,
                        "error": "published version row has no id",
                    })
                    continue

                summary["scanned"] += 1
                version = self.producer_repo.get_version(version_id) or {}
                trust_score = version.get("trust_score")
                if (
                    isinstance(trust_score, dict)
                    and trust_score.get("model_fingerprint")
                    == self.target_model_fingerprint
                ):
                    summary["skipped"] += 1
                    continue

                for attempt in range(1, max_attempts + 1):
                    try:
                        refreshed = self.refresh_service.refresh(
                            version_id,
                            force=True,
                        )
                    except Exception as exc:  # continue the batch; retry below
                        logger.warning(
                            "trust-score backfill attempt %s/%s failed for %s",
                            attempt,
                            max_attempts,
                            version_id,
                            exc_info=True,
                        )
                        if attempt == max_attempts:
                            summary["failed"].append({
                                "version_id": version_id,
                                "attempts": attempt,
                                "error": f"{type(exc).__name__}: {exc}",
                            })
                        continue

                    if refreshed is None:
                        # The version may have changed status between listing
                        # and refresh. It no longer belongs to this backfill.
                        summary["skipped"] += 1
                    else:
                        summary["updated"] += 1
                    break

            logger.info(
                "trust-score backfill progress model=%s scanned=%s updated=%s "
                "skipped=%s failed=%s",
                self.target_model_fingerprint,
                summary["scanned"],
                summary["updated"],
                summary["skipped"],
                len(summary["failed"]),
            )
            offset += len(rows)
            if len(rows) < batch_size:
                break

        return summary
