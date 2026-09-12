"""Trust Scan Router — URL 识别、代码拉取、扫描调度与结果获取。

端点:
    POST /scan              — 提交扫描任务（URL 或文件上传）
    GET  /scan/{scan_id}    — 查询扫描状态
"""

from __future__ import annotations

import hashlib
import http.client
import importlib.util
import io
import json
import logging
import math
import os
import re
import socket
import stat
import struct
import sys
import tempfile
import threading
import time as _time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Callable, Dict, List, Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile, status
from pydantic import BaseModel, Field

from src.auth import require_role, verify_resource_access
from src.dependencies import CurrentUser
from src.models.common import require_safe_source_subdirectory
from src.services.artifacts import force_rmtree
from src.services.source_snapshots import SourceSnapshotStore
from src.settings import get_settings

router = APIRouter(tags=["trust-scan"])

# ---------------------------------------------------------------------------
# 项目路径推导
# ---------------------------------------------------------------------------
_API_SRC_DIR = Path(__file__).resolve().parent.parent  # apps/api/src/
_PROJECT_ROOT = _API_SRC_DIR.parent.parent.parent  # repo root
_SCANNER_PATH = _PROJECT_ROOT / "scanners" / "risk_scanner" / "scanner.py"
_EXTRACTOR_PATH = _PROJECT_ROOT / "packages" / "schema" / "extract_skills.py"
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
from scanners.risk_scanner.redaction import (
    build_finding_context_bundle,
    redact_report,
    redact_value,
)
from scanners.risk_scanner.llm_reviewer import validate_supporting_evidence
from scanners.risk_scanner.provenance import (
    build_verification_capabilities,
    build_verification_facts,
)
from scanners.risk_scanner.inventory import (
    ScanInventory,
    build_inventory,
    load_text_files,
)
from scanners.risk_scanner.policy import ScanPolicy
from scanners.risk_scanner.permission_consistency import (
    reconcile_permission_advisories,
)
from scanners.risk_scanner.reporting import refresh_report_summaries
from packages.schema.frontmatter import parse_frontmatter
from schema.constants import HASH_SCOPE_SCANNED_SOURCE

# ---------------------------------------------------------------------------
# 内存状态存储（scans 字典）
# ---------------------------------------------------------------------------
# key: scan_id, value: {status, package_name, created_at, finished_at, report_path, error, expires_at}
_scans: Dict[str, Dict[str, Any]] = {}
_SOURCE_SNAPSHOT_STORE = SourceSnapshotStore()

_SCAN_TTL_SECONDS = 3600  # 临时扫描结果保留 1 小时
_LLM_REVIEW_DEADLINE_SECONDS = 15 * 60
_LLM_PROGRESS_HEARTBEAT_SECONDS = 5.0
_SOURCE_POLICY = ScanPolicy()
_ZIP_READ_CHUNK_BYTES = 64 * 1024
_GITHUB_API_TIMEOUT_SECONDS = 30
_GITHUB_API_MAX_ATTEMPTS = 3
_GITHUB_BLOB_WORKERS = 8
_GITHUB_GLOBAL_MAX_CONCURRENT_REQUESTS = 8
# Preserve headroom for repository metadata and other server activity instead
# of allowing one scan to consume an entire GitHub rate-limit window.
_GITHUB_AUTHENTICATED_REQUEST_BUDGET = 1_000
_GITHUB_MAX_RATE_LIMIT_WAIT_SECONDS = 60.0
_GITHUB_RATE_LIMIT_RESET_GRACE_SECONDS = 1.0
_GITHUB_TREE_RESPONSE_MAX_BYTES = 8 * 1024 * 1024
_GITHUB_MAX_TREE_ENTRIES = 100_000
_GITHUB_MAX_TREE_REQUESTS = 10_000
_GITHUB_TRANSIENT_STATUS_CODES = frozenset({408, 429, 500, 502, 503, 504})
_MAX_MANIFEST_JSON_NESTING = 128
_SCAN_PROGRESS_LOCK = threading.RLock()
_GITHUB_API_CONCURRENCY_GATE = threading.BoundedSemaphore(
    _GITHUB_GLOBAL_MAX_CONCURRENT_REQUESTS
)
_GITHUB_RATE_LIMIT_LOCK = threading.Lock()
_GITHUB_RATE_LIMIT_UNTIL = 0.0

_PUBLIC_LLM_PROGRESS_FIELDS = frozenset({
    "status",
    "phase",
    "attempt",
    "max_attempts",
    "findings_total",
    "findings_reviewed",
    "findings_pending",
    "started_at",
    "last_update_at",
    "deadline_at",
    "fallback",
})
_LLM_PROGRESS_STATUSES = frozenset({"running", "completed", "degraded", "timeout"})
_LLM_PROGRESS_PHASES = frozenset({"judge_a", "judge_b", "arbitration", "complete"})
_LLM_PROGRESS_FALLBACKS = frozenset({
    "manual_review_required",
    "manual_review_for_unresolved",
    "manual_review_for_incomplete_context",
})


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _nonnegative_int(value: Any, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def _initial_llm_progress(findings_total: int) -> tuple[dict[str, Any], float]:
    started = datetime.now(timezone.utc)
    deadline = started + timedelta(seconds=_LLM_REVIEW_DEADLINE_SECONDS)
    return ({
        "status": "running",
        "phase": "judge_a",
        "attempt": 1,
        "max_attempts": 3,
        "findings_total": max(0, findings_total),
        "findings_reviewed": 0,
        "findings_pending": max(0, findings_total),
        "started_at": started.isoformat(),
        "last_update_at": started.isoformat(),
        "deadline_at": deadline.isoformat(),
    }, _time.monotonic() + _LLM_REVIEW_DEADLINE_SECONDS)


def _update_llm_progress(scan_id: str, update: dict[str, Any]) -> None:
    """Atomically publish only the safe, user-facing LLM progress fields."""
    with _SCAN_PROGRESS_LOCK:
        info = _scans.get(scan_id)
        if info is None:
            return
        current = info.get("llm_review")
        if not isinstance(current, dict):
            return
        next_progress = dict(current)
        status_value = update.get("status")
        if status_value in _LLM_PROGRESS_STATUSES:
            next_progress["status"] = status_value
        phase_value = update.get("phase")
        if phase_value in _LLM_PROGRESS_PHASES:
            next_progress["phase"] = phase_value
        for key in (
            "attempt",
            "max_attempts",
            "findings_total",
            "findings_reviewed",
            "findings_pending",
        ):
            if key not in update:
                continue
            numeric_value = _nonnegative_int(update[key], default=-1)
            if numeric_value < 0:
                continue
            if key == "max_attempts":
                numeric_value = max(1, min(10, numeric_value))
            next_progress[key] = numeric_value
        fallback_value = update.get("fallback")
        if fallback_value in _LLM_PROGRESS_FALLBACKS:
            next_progress["fallback"] = fallback_value
        next_progress["last_update_at"] = _utc_now_iso()
        info["llm_review"] = next_progress


def _heartbeat_llm_progress(scan_id: str, stop_event: threading.Event) -> None:
    """Keep last_update_at fresh while a bounded provider call is in flight."""
    while not stop_event.wait(_LLM_PROGRESS_HEARTBEAT_SECONDS):
        with _SCAN_PROGRESS_LOCK:
            info = _scans.get(scan_id)
            if info is None:
                return
            current = info.get("llm_review")
            if not isinstance(current, dict) or current.get("status") != "running":
                return
            next_progress = dict(current)
            next_progress["last_update_at"] = _utc_now_iso()
            info["llm_review"] = next_progress


class _DeterministicAcquisitionError(ValueError):
    """A source validation or budget failure that must not be retried."""


class _GitHubAcquisitionError(RuntimeError):
    """A GitHub API failure after all safe retry attempts are exhausted."""


class _GitHubRateLimitError(_GitHubAcquisitionError):
    """A GitHub cooldown is longer than this scan may safely wait."""


class _GitHubRequestBudget:
    """Thread-safe cap on actual GitHub HTTP attempts for one acquisition."""

    def __init__(self, limit: int) -> None:
        if limit < 1:
            raise ValueError("GitHub request budget must be positive")
        self.limit = limit
        self._used = 0
        self._lock = threading.Lock()

    @property
    def used(self) -> int:
        with self._lock:
            return self._used

    @property
    def remaining(self) -> int:
        with self._lock:
            return self.limit - self._used

    def require_available(self, requests: int) -> None:
        if requests < 0:
            raise ValueError("Required GitHub request count must not be negative")
        with self._lock:
            if self._used + requests > self.limit:
                raise _DeterministicAcquisitionError(
                    "Selected source exceeds the per-scan GitHub API request "
                    f"budget ({self.limit}); submit a /tree/... URL for the "
                    "specific capability directory"
                )

    def consume(self) -> None:
        with self._lock:
            if self._used >= self.limit:
                raise _DeterministicAcquisitionError(
                    "GitHub API request retries exhausted the per-scan request "
                    f"budget ({self.limit})"
                )
            self._used += 1


@dataclass(frozen=True)
class _GitTreeEntry:
    path: str
    mode: str
    type: str
    sha: str
    size: int | None = None

    @property
    def is_regular_blob(self) -> bool:
        return self.type == "blob" and self.mode in {"100644", "100755"}


@dataclass(frozen=True)
class _GitTreeSnapshot:
    sha: str
    entries: tuple[_GitTreeEntry, ...]
    truncated: bool


def _cleanup_expired_scans() -> None:
    """清理超过 TTL 的临时扫描结果，避免字典无限增长。"""
    now = _time.time()
    expired = [sid for sid, info in _scans.items() if info.get("expires_at", 0) < now]
    for sid in expired:
        info = _scans[sid]
        local_dir = (info.get("full_report") or {}).get("local_source_dir")
        if local_dir:
            force_rmtree(local_dir)
        del _scans[sid]


def _scan_not_found_detail(scan_id: str) -> str:
    return f"Scan '{scan_id}' not found or expired (scans are kept for 1 hour). Please re-scan."

# ---------------------------------------------------------------------------
# Pydantic 模型
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """扫描提交请求。"""
    repo_url: Optional[str] = Field(default=None, description="GitHub 仓库 HTTPS URL")


class ScanResponse(BaseModel):
    """扫描任务创建响应。"""
    scan_id: str
    status: str
    package_name: Optional[str] = None
    created_at: str


class LLMReviewProgressResponse(BaseModel):
    """Safe progress projection returned by the scan-status endpoint."""
    status: str
    phase: Optional[str] = None
    attempt: int = Field(default=0, ge=0)
    max_attempts: int = Field(default=3, ge=1)
    findings_total: int = Field(default=0, ge=0)
    findings_reviewed: int = Field(default=0, ge=0)
    findings_pending: int = Field(default=0, ge=0)
    started_at: Optional[str] = None
    last_update_at: Optional[str] = None
    deadline_at: Optional[str] = None
    fallback: Optional[str] = None


class ScanStatusResponse(BaseModel):
    """扫描状态查询响应。"""
    scan_id: str
    status: str
    package_name: Optional[str] = None
    created_at: str
    finished_at: Optional[str] = None
    summary: Optional[Dict[str, Any]] = None
    trust_score: Optional[Dict[str, Any]] = None
    llm_review: Optional[LLMReviewProgressResponse] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# 扫描器加载（通过 importlib 动态加载）
# ---------------------------------------------------------------------------

def _load_scanner():
    """动态加载 RiskScanner 类。"""
    spec = importlib.util.spec_from_file_location(
        "risk_scanner", str(_SCANNER_PATH)
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load scanner from {_SCANNER_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["risk_scanner"] = mod
    spec.loader.exec_module(mod)
    return mod.RiskScanner


_LLM_REVIEWED_SEVERITIES = frozenset({"critical", "high"})
_LLM_SEMANTIC_REVIEWED_SEVERITIES = frozenset({"critical", "high", "medium"})
_LLM_SEVERITY_RANK = {
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


def _is_llm_reviewable_finding(finding: dict[str, Any]) -> bool:
    severity = str(
        finding.get("candidate_severity")
        or finding.get("static_severity")
        or finding.get("severity", "")
    ).lower()
    return severity in _LLM_REVIEWED_SEVERITIES or (
        (
            finding.get("requires_llm_validation") is True
            or finding.get("llm_adjudication_eligible") is True
        )
        and severity in _LLM_SEMANTIC_REVIEWED_SEVERITIES
    )


def _load_llm_reviewer() -> Any:
    """动态加载 LLM 审查器模块。"""
    llm_reviewer_path = _PROJECT_ROOT / "scanners" / "risk_scanner" / "llm_reviewer.py"
    spec = importlib.util.spec_from_file_location(
        "llm_reviewer", str(llm_reviewer_path)
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load LLM reviewer from {llm_reviewer_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _mark_llm_review_unavailable(
    findings: list[dict[str, Any]],
    error: Exception,
) -> dict[str, Any]:
    """Preserve unresolved severities and require manual review."""
    labels: dict[str, str] = {}
    decisions: dict[str, dict[str, object]] = {}
    reviewed_count = 0
    skipped_count = 0

    for finding in findings:
        if not isinstance(finding, dict):
            skipped_count += 1
            continue

        if not _is_llm_reviewable_finding(finding):
            skipped_count += 1
            continue

        finding["llm_label"] = "llm:unavailable"
        finding["llm_review_state"] = "unavailable"
        finding["llm_impact"] = "unknown"
        finding["llm_confidence"] = 0.0
        finding["llm_explanation"] = "LLM semantic review unavailable"
        finding["llm_review_rounds"] = 0
        finding["llm_evidence_sufficient"] = False
        finding["llm_missing_context"] = ["LLM semantic review unavailable"]
        finding["llm_supporting_evidence"] = []
        finding["llm_context_status"] = "missing"
        finding["llm_adjudication_action"] = "manual_review"
        finding["requires_manual_review"] = True
        finding_id = str(finding.get("id", ""))
        if finding_id:
            labels[finding_id] = "llm:unavailable"
            decisions[finding_id] = {
                "verdict": "unavailable",
                "impact": "unknown",
                "intent": "benign",
                "confidence": 0.0,
                "context_role": "unknown",
                "evidence_sufficient": False,
                "missing_context": ["LLM semantic review unavailable"],
                "supporting_evidence": [],
                "explanation": "LLM semantic review unavailable",
                "rounds": 0,
            }
        reviewed_count += 1

    return {
        "triggered": True,
        "findings_reviewed": reviewed_count,
        "findings_skipped": skipped_count,
        "findings_pending": reviewed_count,
        "status": "call_failed",
        "attempts": 0,
        "review_rounds": 0,
        "arbitrated": 0,
        "findings_context_incomplete": reviewed_count,
        "labels": labels,
        "decisions": decisions,
        "labels_summary": {
            "suspected_malicious": 0,
            "suspected_negligent": 0,
            "likely_benign": 0,
            "uncertain": 0,
            "unavailable": reviewed_count,
        },
        "policy_version": "llm-adjudication-v2",
        "decision_policy": {
            "independent_reviews": 2,
            "arbitration_on_disagreement": True,
            "benign_downgrade_confidence": 0.85,
            "requires_complete_context": True,
            "requires_cited_evidence": True,
            "confirmed_vulnerability_downgrade_allowed": False,
        },
        "prompt_audit": {
            "template_version": "unavailable",
            "response_schema_version": "2.1",
            "system_prompt_sha256": "unavailable",
            "payload_sha256s": [],
            "payload_count": 0,
        },
        "review_configuration": {
            "provider": "unavailable",
            "model": "unavailable",
            "batch_size": 0,
            "temperature": 0.0,
            "max_output_tokens": 1024,
        },
        "context_coverage": {
            "candidates": reviewed_count,
            "complete": 0,
            "partial": 0,
            "missing": reviewed_count,
            "total_context_bytes": 0,
        },
        "error": f"{type(error).__name__}: {error}",
        "fallback": "manual_review_required",
    }


def _apply_llm_decisions(
    findings: list[dict[str, Any]],
    result: dict[str, Any],
    finding_contexts: dict[str, str] | None = None,
) -> None:
    """Apply guarded two-way adjudication without overwriting static evidence."""
    labels = result.get("labels", {})
    decisions = result.get("decisions", {})
    if not isinstance(labels, dict) or not isinstance(decisions, dict):
        raise ValueError("LLM review labels and decisions must be objects")
    decision_policy = result.get("decision_policy") or {}
    try:
        benign_confidence = max(
            0.0,
            min(1.0, float(decision_policy.get("benign_downgrade_confidence", 0.85))),
        )
    except (TypeError, ValueError):
        benign_confidence = 0.85

    def severity(value: object, fallback: str = "info") -> str:
        normalized = str(value or fallback).lower()
        return normalized if normalized in _LLM_SEVERITY_RANK else fallback

    def higher(left: str, right: str) -> str:
        return (
            left
            if _LLM_SEVERITY_RANK[left] >= _LLM_SEVERITY_RANK[right]
            else right
        )

    for finding in findings:
        finding_id = str(finding.get("id", ""))
        if finding_id in labels:
            finding["llm_label"] = labels[finding_id]
        decision = decisions.get(finding_id)
        if not isinstance(decision, dict):
            continue

        verdict = str(decision.get("verdict", "uncertain"))
        impact = str(decision.get("impact", "unknown"))
        try:
            confidence = max(0.0, min(1.0, float(decision.get("confidence", 0))))
        except (TypeError, ValueError):
            confidence = 0.0
        try:
            rounds = min(3, max(0, int(decision.get("rounds", 0))))
        except (TypeError, ValueError):
            rounds = 0

        finding["llm_review_state"] = verdict
        finding["llm_impact"] = impact if impact in {
            "none", "low", "medium", "high", "critical", "unknown"
        } else "unknown"
        finding["llm_confidence"] = confidence
        finding["llm_explanation"] = str(decision.get("explanation", ""))[:1000]
        finding["llm_review_rounds"] = rounds
        context_audit = decision.get("context_audit") or {}
        context_status = str(context_audit.get("delivery_status", "missing"))
        if context_status not in {"complete", "partial", "missing"}:
            context_status = "missing"
        evidence_sufficient = decision.get("evidence_sufficient") is True
        missing_context = [
            str(item)[:500]
            for item in (decision.get("missing_context") or [])[:10]
            if str(item).strip()
        ] if isinstance(decision.get("missing_context"), list) else []
        supporting_evidence = validate_supporting_evidence(
            decision.get("supporting_evidence"),
            context_audit,
            (finding_contexts or {}).get(finding_id, ""),
        )
        if evidence_sufficient and context_status != "complete":
            evidence_sufficient = False
            missing_context.append("scanner context delivery was incomplete")
        if evidence_sufficient and not supporting_evidence:
            evidence_sufficient = False
            missing_context.append("no server-verified source citation")
        finding["llm_evidence_sufficient"] = evidence_sufficient
        finding["llm_missing_context"] = list(dict.fromkeys(missing_context))
        finding["llm_supporting_evidence"] = supporting_evidence
        finding["llm_context_status"] = context_status
        finding["llm_policy_version"] = str(
            result.get("policy_version") or "unknown"
        )

        static_severity = severity(
            finding.get("static_severity")
            or finding.get("candidate_severity")
            or finding.get("severity")
        )
        effective_before = severity(
            finding.get("effective_severity") or finding.get("severity"),
            static_severity,
        )
        finding["static_severity"] = static_severity
        finding["llm_effective_severity_before"] = effective_before
        effective_after = effective_before

        eligible = (
            finding.get("llm_adjudication_eligible") is True
            or finding.get("requires_llm_validation") is True
        )
        protected = (
            finding.get("kind") == "vulnerability"
            and finding.get("disposition") == "confirmed_vulnerability"
        )
        benign_guard_passed = (
            verdict == "likely_benign"
            and eligible
            and not protected
            and confidence >= benign_confidence
            and rounds >= 2
            and evidence_sufficient
            and context_status == "complete"
            and bool(supporting_evidence)
        )

        if benign_guard_passed:
            effective_after = "info"
            finding["disposition"] = "false_positive"
            finding["downgraded"] = "llm_consensus"
            finding["llm_adjudication_action"] = "downgraded"
            finding["requires_manual_review"] = False
        elif verdict in {"confirmed_harmful", "confirmed_risky"}:
            target = severity(
                impact,
                "high" if verdict == "confirmed_harmful" else "medium",
            )
            if verdict == "confirmed_harmful" and target in {"info", "low", "medium"}:
                target = "high"
            if verdict == "confirmed_risky" and target in {"info", "low"}:
                target = "medium"
            effective_after = higher(effective_before, target)
            finding["llm_adjudication_action"] = (
                "escalated" if effective_after != effective_before else "preserved"
            )
            finding["requires_manual_review"] = False
        else:
            if verdict == "likely_benign" and protected:
                action = "blocked_confirmed_vulnerability"
            elif verdict == "likely_benign" and not eligible:
                action = "not_eligible"
            elif verdict == "likely_benign":
                action = "blocked_insufficient_evidence"
            else:
                action = "manual_review"
            finding["llm_adjudication_action"] = action
            finding["requires_manual_review"] = True

        finding["effective_severity"] = effective_after
        finding["severity"] = effective_after


def _run_llm_review_with_fallback(
    findings: list[dict[str, Any]],
    scanner: Any,
    manifest: dict[str, Any] | None = None,
    *,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    """Run multi-judge review and attach structured verdicts to findings."""
    try:
        if (
            deadline_monotonic is not None
            and _time.monotonic() >= deadline_monotonic
        ):
            raise TimeoutError("LLM review deadline exceeded")
        reviewer = _load_llm_reviewer()
        finding_contexts, context_audit = build_finding_context_bundle(
            findings,
            scanner._file_contents,
        )
        if (
            deadline_monotonic is not None
            and _time.monotonic() >= deadline_monotonic
        ):
            raise TimeoutError("LLM review deadline exceeded")
        result = reviewer.run_llm_review(
            findings=findings,
            finding_contexts=finding_contexts,
            manifest=manifest if manifest is not None else scanner._package_metadata,
            context_audit=context_audit,
            progress_callback=progress_callback,
            deadline_monotonic=deadline_monotonic,
        )
        labels = result.get("labels", {})
        if not isinstance(labels, dict):
            raise ValueError("LLM review labels must be an object")
        decisions = result.get("decisions", {})
        if not isinstance(decisions, dict):
            raise ValueError("LLM review decisions must be an object")
        _apply_llm_decisions(findings, result, finding_contexts)

        labels_summary = result.get("labels_summary")
        if not isinstance(labels_summary, dict):
            raise ValueError("LLM review result is missing labels_summary")
        print(
            f"[TAH-trust]     LLM 审查完成: "
            f"malicious={labels_summary['suspected_malicious']}, "
            f"negligent={labels_summary['suspected_negligent']}, "
            f"benign={labels_summary['likely_benign']}, "
            f"uncertain={labels_summary['uncertain']}, "
            f"unavailable={labels_summary['unavailable']}"
        )
        return result
    except Exception as exc:
        print(f"[TAH-trust]     LLM 审查跳过（{exc}）")
        result = _mark_llm_review_unavailable(findings, exc)
        if isinstance(exc, TimeoutError) or type(exc).__name__ == "LLMReviewDeadlineExceeded":
            result["status"] = "timeout"
            result["findings_reviewed"] = 0
            result["fallback"] = "manual_review_for_unresolved"
        return result


# ---------------------------------------------------------------------------
# 评分引擎加载
# ---------------------------------------------------------------------------

def _load_scorer():
    """加载评分引擎（虚拟包方式处理相对导入）。"""
    import types as _types
    ts_src = _PROJECT_ROOT / "packages" / "trust-score" / "src"
    if "src" not in sys.modules or not getattr(sys.modules["src"], "__path__", None):
        src_pkg = _types.ModuleType("src")
        src_pkg.__path__ = [str(ts_src)]
        src_pkg.__package__ = "src"
        sys.modules["src"] = src_pkg
    for name in [
        "model_identity",
        "provenance",
        "intent",
        "community",
        "derived_score",
        "explainer",
    ]:
        key = f"src.{name}"
        if key not in sys.modules:
            s = importlib.util.spec_from_file_location(key, str(ts_src / f"{name}.py"))
            m = importlib.util.module_from_spec(s)
            m.__package__ = "src"
            sys.modules[key] = m
            s.loader.exec_module(m)
    ek = "src.engine"
    if ek in sys.modules:
        return sys.modules[ek].rate
    es = importlib.util.spec_from_file_location(ek, str(ts_src / "engine.py"))
    em = importlib.util.module_from_spec(es)
    em.__package__ = "src"
    sys.modules[ek] = em
    es.loader.exec_module(em)
    return em.rate


def _load_score_model() -> tuple[Callable[..., dict[str, Any]], str, str]:
    """Load the scorer together with its deterministic model identity."""
    scorer = _load_scorer()
    identity = sys.modules.get("src.model_identity")
    if identity is None:  # pragma: no cover - guarded by _load_scorer
        raise RuntimeError("trust-score model identity was not loaded")
    return (
        scorer,
        identity.get_model_fingerprint(),
        identity.get_model_version(),
    )


# ---------------------------------------------------------------------------
# 远程仓库获取：固定 commit + 认证 Trees/Blobs 或匿名受限 ZIP
# ---------------------------------------------------------------------------


def _github_api_headers() -> dict[str, str]:
    """Return the shared, optional-token headers for GitHub API requests."""
    headers: dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = get_settings().github_token or ""
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _new_github_request_budget() -> _GitHubRequestBudget:
    """Return the per-scan budget for authenticated Trees/Blobs acquisition."""
    return _GitHubRequestBudget(_GITHUB_AUTHENTICATED_REQUEST_BUDGET)


def _github_header_value(headers: Any, name: str) -> str | None:
    if headers is None:
        return None
    try:
        value = headers.get(name)
    except (AttributeError, TypeError):
        value = None
    if value is not None:
        return str(value).strip()
    try:
        for key, candidate in headers.items():
            if str(key).casefold() == name.casefold():
                return str(candidate).strip()
    except (AttributeError, TypeError):
        pass
    return None


def _github_rate_limit_deadline(
    headers: Any,
    status_code: int | None,
    *,
    now: float | None = None,
) -> float | None:
    """Derive GitHub's next safe request time from documented headers."""
    current_time = _time.time() if now is None else now
    retry_after_raw = _github_header_value(headers, "Retry-After")
    remaining = _github_header_value(headers, "X-RateLimit-Remaining")
    reset_raw = _github_header_value(headers, "X-RateLimit-Reset")

    if status_code is None and remaining != "0":
        return None
    is_rate_limited = (
        status_code == 429
        or retry_after_raw is not None
        or remaining == "0"
    )
    if not is_rate_limited:
        return None

    if retry_after_raw is not None:
        try:
            retry_after = float(retry_after_raw)
        except ValueError:
            retry_after = -1.0
        if math.isfinite(retry_after) and retry_after >= 0:
            return current_time + retry_after

    if remaining == "0" and reset_raw is not None:
        try:
            reset_at = float(reset_raw)
        except ValueError:
            reset_at = -1.0
        if math.isfinite(reset_at) and reset_at >= 0:
            return max(
                current_time,
                reset_at + _GITHUB_RATE_LIMIT_RESET_GRACE_SECONDS,
            )

    # GitHub recommends waiting at least one minute for a secondary limit
    # response that does not provide a usable retry timestamp.
    return current_time + 60.0


def _defer_github_requests_until(deadline: float) -> None:
    global _GITHUB_RATE_LIMIT_UNTIL
    with _GITHUB_RATE_LIMIT_LOCK:
        _GITHUB_RATE_LIMIT_UNTIL = max(_GITHUB_RATE_LIMIT_UNTIL, deadline)


def _observe_github_rate_limit_headers(
    headers: Any,
    status_code: int | None = None,
) -> bool:
    deadline = _github_rate_limit_deadline(headers, status_code)
    if deadline is None:
        return False
    _defer_github_requests_until(deadline)
    return True


def _wait_for_github_rate_limit() -> None:
    global _GITHUB_RATE_LIMIT_UNTIL
    now = _time.time()
    with _GITHUB_RATE_LIMIT_LOCK:
        deadline = _GITHUB_RATE_LIMIT_UNTIL
        if deadline <= now:
            _GITHUB_RATE_LIMIT_UNTIL = 0.0
            return
    delay = max(deadline - now, 0.0)
    if delay > _GITHUB_MAX_RATE_LIMIT_WAIT_SECONDS:
        raise _GitHubRateLimitError(
            "GitHub API rate limit will not reset within the allowed wait "
            f"window ({math.ceil(delay)} seconds remaining)"
        )
    if delay:
        _time.sleep(delay)


def _fetch_repository_default_branch(parsed: dict[str, Any]) -> str:
    """Resolve a repository's GitHub default branch before acquiring source."""
    api_url = (
        f"https://api.github.com/repos/{parsed['owner']}/{parsed['repo']}"
    )
    try:
        raw = _github_request_bytes(
            api_url,
            max_bytes=_SOURCE_POLICY.max_file_bytes,
            timeout=20,
            preserve_http_errors=True,
        )
        payload = json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="GitHub repository was not found or is not accessible.",
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to resolve the repository default branch from GitHub.",
        ) from exc
    except (
        urllib.error.URLError,
        _GitHubAcquisitionError,
        http.client.IncompleteRead,
        TimeoutError,
        OSError,
        UnicodeDecodeError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to resolve the repository default branch from GitHub.",
        ) from exc

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="GitHub did not return a valid repository metadata object.",
        )

    expected_full_name = f"{parsed['owner']}/{parsed['repo']}".casefold()
    actual_full_name = payload.get("full_name")
    if (
        not isinstance(actual_full_name, str)
        or actual_full_name.casefold() != expected_full_name
    ):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="GitHub repository identity did not match the requested source.",
        )

    default_branch = payload.get("default_branch")
    if not isinstance(default_branch, str) or not default_branch.strip():
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="GitHub did not return a valid repository default branch.",
        )
    return default_branch


def _resolve_default_branch_source(parsed: dict[str, Any]) -> dict[str, Any]:
    """Allow only a repository's default branch and an optional path within it."""
    default_branch = _fetch_repository_default_branch(parsed)
    tree_path = parsed.get("tree_path")
    subdir: str | None = None

    if tree_path:
        if tree_path == default_branch:
            pass
        elif tree_path.startswith(default_branch + "/"):
            subdir = tree_path[len(default_branch) + 1:]
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Only the repository default branch is supported. "
                    f"Use '{default_branch}' instead of another branch or tag."
                ),
            )

    return {
        **parsed,
        # This marker is written only after the server validates the GitHub
        # repository response against the requested owner/repo.
        "repository_verified": True,
        "ref": default_branch,
        "subdir": subdir,
        # This proves only that the canonical repository endpoint resolved.
        # Repository ownership is a separate claim and remains unverified
        # until an independent server-side verifier establishes it.
        "repository_resolved": True,
    }


def _is_full_commit_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{40}", value))


def _fetch_repository_commit_hash(
    parsed: dict[str, Any],
    *,
    request_budget: _GitHubRequestBudget | None = None,
) -> str:
    """Resolve the default branch to an immutable full commit hash."""
    encoded_ref = urllib.parse.quote(parsed["ref"], safe="")
    api_url = (
        f"https://api.github.com/repos/{parsed['owner']}/{parsed['repo']}"
        f"/commits/{encoded_ref}"
    )
    payload = _github_json_payload(
        api_url,
        max_bytes=_SOURCE_POLICY.max_file_bytes,
        timeout=20,
        request_budget=request_budget,
    )
    commit_hash = payload.get("sha") if isinstance(payload, dict) else None
    if not isinstance(commit_hash, str) or not _is_full_commit_hash(commit_hash):
        raise ValueError("GitHub did not return a valid full commit hash")
    return commit_hash


def _copy_response_bounded(response: Any, destination: Any, max_bytes: int) -> int:
    """Stream an HTTP body into a seekable file without exceeding max_bytes."""
    if max_bytes < 0:
        raise _DeterministicAcquisitionError(
            "HTTP response byte limit must not be negative"
        )
    headers = getattr(response, "headers", None)
    content_length = headers.get("Content-Length") if headers else None
    declared_length: int | None = None
    if content_length:
        try:
            declared_length = int(content_length)
        except (TypeError, ValueError):
            pass
    if declared_length is not None and declared_length > max_bytes:
        raise _DeterministicAcquisitionError(
            f"HTTP response exceeds {max_bytes} byte limit"
        )

    total = 0
    while True:
        chunk = response.read(min(_ZIP_READ_CHUNK_BYTES, max_bytes - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise _DeterministicAcquisitionError(
                f"HTTP response exceeds {max_bytes} byte limit"
            )
        destination.write(chunk)
    if declared_length is not None and total < declared_length:
        raise http.client.IncompleteRead(b"", declared_length - total)
    if declared_length is not None and total > declared_length:
        raise _DeterministicAcquisitionError(
            "HTTP response exceeded its declared Content-Length"
        )
    destination.seek(0)
    return total


def _github_request_bytes(
    api_url: str,
    *,
    max_bytes: int,
    expected_bytes: int | None = None,
    accept: str = "application/vnd.github+json",
    timeout: int = _GITHUB_API_TIMEOUT_SECONDS,
    max_attempts: int = _GITHUB_API_MAX_ATTEMPTS,
    request_budget: _GitHubRequestBudget | None = None,
    preserve_http_errors: bool = False,
) -> bytes:
    """Read a bounded GitHub API response with retries for interrupted streams."""
    if expected_bytes is not None and not 0 <= expected_bytes <= max_bytes:
        raise _DeterministicAcquisitionError(
            "Expected GitHub response size is outside the byte limit"
        )
    attempts = max(1, max_attempts)
    last_error: BaseException | None = None
    for attempt in range(1, attempts + 1):
        rate_limited = False
        _wait_for_github_rate_limit()
        if request_budget is not None:
            request_budget.consume()
        headers = _github_api_headers()
        headers["Accept"] = accept
        request = urllib.request.Request(api_url, headers=headers)
        try:
            with _GITHUB_API_CONCURRENCY_GATE:
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    _observe_github_rate_limit_headers(
                        getattr(response, "headers", None)
                    )
                    buffer = io.BytesIO()
                    _copy_response_bounded(response, buffer, max_bytes)
                    data = buffer.getvalue()
                    if expected_bytes is None or len(data) == expected_bytes:
                        return data
                    last_error = http.client.IncompleteRead(
                        data,
                        max(expected_bytes - len(data), 0),
                    )
        except _DeterministicAcquisitionError:
            raise
        except urllib.error.HTTPError as exc:
            last_error = exc
            rate_limited = _observe_github_rate_limit_headers(
                getattr(exc, "headers", None),
                exc.code,
            )
            try:
                exc.close()
            except OSError:
                pass
            if not rate_limited and exc.code not in _GITHUB_TRANSIENT_STATUS_CODES:
                if preserve_http_errors:
                    raise
                raise _GitHubAcquisitionError(
                    f"GitHub API returned HTTP {exc.code}"
                ) from exc
        except (
            urllib.error.URLError,
            http.client.IncompleteRead,
            http.client.RemoteDisconnected,
            OSError,
        ) as exc:
            last_error = exc

        logging.warning(
            "GitHub API request attempt %d/%d failed for %s: %s",
            attempt,
            attempts,
            urllib.parse.urlsplit(api_url).path,
            last_error,
        )
        if attempt < attempts and not rate_limited:
            _time.sleep(min(0.25 * (2 ** (attempt - 1)), 2.0))

    raise _GitHubAcquisitionError(
        f"GitHub API request failed after {attempts} attempts"
    ) from last_error


def _github_json_payload(
    api_url: str,
    *,
    max_bytes: int,
    timeout: int = _GITHUB_API_TIMEOUT_SECONDS,
    max_attempts: int = _GITHUB_API_MAX_ATTEMPTS,
    request_budget: _GitHubRequestBudget | None = None,
) -> Any:
    raw = _github_request_bytes(
        api_url,
        max_bytes=max_bytes,
        timeout=timeout,
        max_attempts=max_attempts,
        request_budget=request_budget,
    )
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise _GitHubAcquisitionError(
            "GitHub API returned malformed JSON"
        ) from exc


def _validated_git_tree_entry(
    raw_entry: Any,
    *,
    prefix: str = "",
) -> _GitTreeEntry:
    if not isinstance(raw_entry, dict):
        raise _DeterministicAcquisitionError(
            "GitHub tree contains a non-object entry"
        )

    relative_path = raw_entry.get("path")
    if not isinstance(relative_path, str):
        raise _DeterministicAcquisitionError(
            "GitHub tree contains an invalid entry path"
        )
    try:
        relative_path = require_safe_source_subdirectory(relative_path)
    except ValueError as exc:
        raise _DeterministicAcquisitionError(
            f"GitHub tree contains an unsafe entry path: {relative_path!r}"
        ) from exc
    if relative_path == ".":
        raise _DeterministicAcquisitionError(
            "GitHub tree contains an invalid dot entry"
        )

    full_path = f"{prefix}/{relative_path}" if prefix else relative_path
    try:
        full_path = require_safe_source_subdirectory(full_path)
    except ValueError as exc:
        raise _DeterministicAcquisitionError(
            f"GitHub tree contains an unsafe entry path: {full_path!r}"
        ) from exc

    entry_type = raw_entry.get("type")
    mode = raw_entry.get("mode")
    valid_modes = {
        "tree": {"040000", "40000"},
        "blob": {"100644", "100755", "120000"},
        "commit": {"160000"},
    }
    if (
        not isinstance(entry_type, str)
        or entry_type not in valid_modes
        or not isinstance(mode, str)
        or mode not in valid_modes[entry_type]
    ):
        raise _DeterministicAcquisitionError(
            f"GitHub tree contains an unsupported entry: {full_path!r}"
        )

    sha = raw_entry.get("sha")
    if not isinstance(sha, str) or not _is_full_commit_hash(sha):
        raise _DeterministicAcquisitionError(
            f"GitHub tree contains an invalid object hash: {full_path!r}"
        )

    size = raw_entry.get("size")
    if entry_type == "blob":
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise _DeterministicAcquisitionError(
                f"GitHub tree contains an invalid blob size: {full_path!r}"
            )
    else:
        size = None

    return _GitTreeEntry(
        path=full_path,
        mode=mode,
        type=entry_type,
        sha=sha,
        size=size,
    )


def _parse_git_tree_snapshot(
    payload: Any,
    *,
    prefix: str = "",
) -> _GitTreeSnapshot:
    if not isinstance(payload, dict):
        raise _GitHubAcquisitionError(
            "GitHub did not return a tree object"
        )
    tree_sha = payload.get("sha")
    if not isinstance(tree_sha, str) or not _is_full_commit_hash(tree_sha):
        raise _GitHubAcquisitionError(
            "GitHub did not return a valid tree hash"
        )
    raw_entries = payload.get("tree")
    if not isinstance(raw_entries, list):
        raise _GitHubAcquisitionError(
            "GitHub did not return a tree entry list"
        )
    if len(raw_entries) > _GITHUB_MAX_TREE_ENTRIES:
        raise _DeterministicAcquisitionError(
            "GitHub tree metadata exceeds the entry limit"
        )
    truncated = payload.get("truncated", False)
    if not isinstance(truncated, bool):
        raise _GitHubAcquisitionError(
            "GitHub returned an invalid tree truncation marker"
        )

    entries: list[_GitTreeEntry] = []
    seen_paths: set[str] = set()
    for raw_entry in raw_entries:
        entry = _validated_git_tree_entry(raw_entry, prefix=prefix)
        if entry.path in seen_paths:
            raise _DeterministicAcquisitionError(
                f"GitHub tree contains a duplicate entry: {entry.path!r}"
            )
        seen_paths.add(entry.path)
        entries.append(entry)
    entries.sort(key=lambda entry: entry.path)
    return _GitTreeSnapshot(
        sha=tree_sha,
        entries=tuple(entries),
        truncated=truncated,
    )


def _fetch_git_tree(
    parsed: dict[str, Any],
    treeish: str,
    *,
    recursive: bool,
    prefix: str = "",
    expected_tree_sha: str | None = None,
    max_attempts: int = _GITHUB_API_MAX_ATTEMPTS,
    request_budget: _GitHubRequestBudget | None = None,
) -> _GitTreeSnapshot:
    encoded_treeish = urllib.parse.quote(treeish, safe="")
    api_url = (
        f"https://api.github.com/repos/{parsed['owner']}/{parsed['repo']}"
        f"/git/trees/{encoded_treeish}"
    )
    if recursive:
        api_url += "?recursive=1"
    payload = _github_json_payload(
        api_url,
        max_bytes=_GITHUB_TREE_RESPONSE_MAX_BYTES,
        max_attempts=max_attempts,
        request_budget=request_budget,
    )
    snapshot = _parse_git_tree_snapshot(payload, prefix=prefix)
    if expected_tree_sha is not None and snapshot.sha != expected_tree_sha:
        raise _DeterministicAcquisitionError(
            "GitHub returned a tree that does not match the pinned object"
        )
    return snapshot


def _git_blob_sha(data: bytes) -> str:
    try:
        digest = hashlib.sha1(usedforsecurity=False)
    except TypeError:  # pragma: no cover - compatibility with non-OpenSSL builds
        digest = hashlib.sha1()
    digest.update(f"blob {len(data)}\0".encode("ascii"))
    digest.update(data)
    return digest.hexdigest()


def _fetch_git_blob(
    parsed: dict[str, Any],
    entry: _GitTreeEntry,
    *,
    max_attempts: int = _GITHUB_API_MAX_ATTEMPTS,
    request_budget: _GitHubRequestBudget | None = None,
) -> bytes:
    if not entry.is_regular_blob or entry.size is None:
        raise _DeterministicAcquisitionError(
            f"GitHub tree entry is not a regular blob: {entry.path!r}"
        )
    encoded_sha = urllib.parse.quote(entry.sha, safe="")
    api_url = (
        f"https://api.github.com/repos/{parsed['owner']}/{parsed['repo']}"
        f"/git/blobs/{encoded_sha}"
    )
    data = _github_request_bytes(
        api_url,
        max_bytes=entry.size,
        expected_bytes=entry.size,
        accept="application/vnd.github.raw+json",
        max_attempts=max_attempts,
        request_budget=request_budget,
    )
    if len(data) != entry.size:
        raise _DeterministicAcquisitionError(
            f"GitHub blob size changed while downloading: {entry.path!r}"
        )
    if _git_blob_sha(data) != entry.sha:
        raise _DeterministicAcquisitionError(
            f"GitHub blob hash mismatch: {entry.path!r}"
        )
    return data


def _unique_git_tree_entries(
    entries: list[_GitTreeEntry] | tuple[_GitTreeEntry, ...],
) -> tuple[_GitTreeEntry, ...]:
    by_path: dict[str, _GitTreeEntry] = {}
    for entry in entries:
        existing = by_path.get(entry.path)
        if existing is not None and existing != entry:
            raise _DeterministicAcquisitionError(
                f"GitHub tree contains conflicting entries: {entry.path!r}"
            )
        by_path[entry.path] = entry
        if len(by_path) > _GITHUB_MAX_TREE_ENTRIES:
            raise _DeterministicAcquisitionError(
                "GitHub tree metadata exceeds the entry limit"
            )
    return tuple(by_path[path] for path in sorted(by_path))


def _walk_git_tree_nonrecursive(
    parsed: dict[str, Any],
    tree_sha: str,
    *,
    prefix: str = "",
    initial_snapshot: _GitTreeSnapshot | None = None,
    max_attempts: int = _GITHUB_API_MAX_ATTEMPTS,
    request_budget: _GitHubRequestBudget | None = None,
) -> tuple[_GitTreeEntry, ...]:
    """Walk a tree without recursive responses when GitHub reports truncation."""
    pending: list[tuple[str, str, _GitTreeSnapshot | None]] = [
        (tree_sha, prefix, initial_snapshot)
    ]
    collected: list[_GitTreeEntry] = []
    requests = 0
    while pending:
        current_sha, current_prefix, supplied_snapshot = pending.pop()
        if supplied_snapshot is None:
            requests += 1
            if requests > _GITHUB_MAX_TREE_REQUESTS:
                raise _DeterministicAcquisitionError(
                    "GitHub tree traversal exceeds the request limit"
                )
            snapshot = _fetch_git_tree(
                parsed,
                current_sha,
                recursive=False,
                prefix=current_prefix,
                expected_tree_sha=current_sha,
                max_attempts=max_attempts,
                request_budget=request_budget,
            )
        else:
            snapshot = supplied_snapshot
            if snapshot.sha != current_sha:
                raise _DeterministicAcquisitionError(
                    "GitHub tree traversal received a mismatched root"
                )
        if snapshot.truncated:
            raise _DeterministicAcquisitionError(
                "GitHub truncated a non-recursive tree response"
            )
        collected.extend(snapshot.entries)
        if len(collected) > _GITHUB_MAX_TREE_ENTRIES:
            raise _DeterministicAcquisitionError(
                "GitHub tree metadata exceeds the entry limit"
            )
        for entry in reversed(snapshot.entries):
            if entry.type == "tree":
                pending.append((entry.sha, entry.path, None))
    return _unique_git_tree_entries(collected)


def _root_manifest_selection(
    parsed: dict[str, Any],
    entries: tuple[_GitTreeEntry, ...],
    prefetched: dict[str, bytes],
    *,
    max_attempts: int = _GITHUB_API_MAX_ATTEMPTS,
    request_budget: _GitHubRequestBudget | None = None,
) -> str | None:
    """Return an explicit or root-manifest source directory at the pinned tree."""
    requested = parsed.get("subdir")
    if requested is not None:
        try:
            return require_safe_source_subdirectory(requested)
        except ValueError as exc:
            raise _DeterministicAcquisitionError(
                f"Invalid source subdirectory: {requested!r}"
            ) from exc

    manifest_entry = next(
        (
            entry
            for entry in entries
            if entry.path == "manifest.json" and entry.is_regular_blob
        ),
        None,
    )
    if (
        manifest_entry is None
        or manifest_entry.size is None
        or manifest_entry.size > _SOURCE_POLICY.max_file_bytes
    ):
        return None
    manifest_bytes = _fetch_git_blob(
        parsed,
        manifest_entry,
        max_attempts=max_attempts,
        request_budget=request_budget,
    )
    prefetched[manifest_entry.path] = manifest_bytes
    try:
        manifest_text = manifest_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None
    try:
        return _root_manifest_subdirectory(manifest_text)
    except ValueError as exc:
        raise _DeterministicAcquisitionError(str(exc)) from exc


def _entries_for_truncated_tree(
    parsed: dict[str, Any],
    root_tree_sha: str,
    subdirectory: str | None,
    *,
    root_snapshot: _GitTreeSnapshot | None = None,
    max_attempts: int = _GITHUB_API_MAX_ATTEMPTS,
    request_budget: _GitHubRequestBudget | None = None,
) -> tuple[_GitTreeEntry, ...]:
    if root_snapshot is None:
        root_snapshot = _fetch_git_tree(
            parsed,
            root_tree_sha,
            recursive=False,
            expected_tree_sha=root_tree_sha,
            max_attempts=max_attempts,
            request_budget=request_budget,
        )
    elif root_snapshot.sha != root_tree_sha:
        raise _DeterministicAcquisitionError(
            "GitHub truncated-tree fallback received a mismatched root"
        )
    if root_snapshot.truncated:
        raise _DeterministicAcquisitionError(
            "GitHub truncated a non-recursive root tree response"
        )
    if not subdirectory or subdirectory == ".":
        return _walk_git_tree_nonrecursive(
            parsed,
            root_tree_sha,
            initial_snapshot=root_snapshot,
            max_attempts=max_attempts,
            request_budget=request_budget,
        )

    collected: list[_GitTreeEntry] = list(root_snapshot.entries)
    current_snapshot = root_snapshot
    current_prefix = ""
    target_entry: _GitTreeEntry | None = None
    for segment in PurePosixPath(subdirectory).parts:
        next_path = f"{current_prefix}/{segment}" if current_prefix else segment
        target_entry = next(
            (entry for entry in current_snapshot.entries if entry.path == next_path),
            None,
        )
        if target_entry is None:
            raise _DeterministicAcquisitionError(
                f"Source subdirectory does not exist: {subdirectory!r}"
            )
        if target_entry.type != "tree":
            raise _DeterministicAcquisitionError(
                f"Source subdirectory is not a directory: {subdirectory!r}"
            )
        current_prefix = next_path
        if current_prefix == subdirectory:
            break
        current_snapshot = _fetch_git_tree(
            parsed,
            target_entry.sha,
            recursive=False,
            prefix=current_prefix,
            expected_tree_sha=target_entry.sha,
            max_attempts=max_attempts,
            request_budget=request_budget,
        )
        if current_snapshot.truncated:
            raise _DeterministicAcquisitionError(
                "GitHub truncated a non-recursive ancestor tree response"
            )
        collected.extend(current_snapshot.entries)

    if target_entry is None:
        raise _DeterministicAcquisitionError(
            f"Source subdirectory does not exist: {subdirectory!r}"
        )
    target_snapshot = _fetch_git_tree(
        parsed,
        target_entry.sha,
        recursive=True,
        prefix=subdirectory,
        expected_tree_sha=target_entry.sha,
        max_attempts=max_attempts,
        request_budget=request_budget,
    )
    if target_snapshot.truncated:
        target_entries = _walk_git_tree_nonrecursive(
            parsed,
            target_entry.sha,
            prefix=subdirectory,
            max_attempts=max_attempts,
            request_budget=request_budget,
        )
    else:
        target_entries = target_snapshot.entries
    collected.extend(target_entries)
    return _unique_git_tree_entries(collected)


_LEGAL_FILE_PREFIXES = ("license", "licence", "copying", "notice")


def _select_repository_entries(
    entries: tuple[_GitTreeEntry, ...],
    subdirectory: str | None,
    *,
    policy: ScanPolicy = _SOURCE_POLICY,
) -> tuple[_GitTreeEntry, ...]:
    """Select file blobs for the requested scope plus required ancestor metadata."""
    entries = _unique_git_tree_entries(entries)
    by_path = {entry.path: entry for entry in entries}
    regular_files = {
        entry.path: entry for entry in entries if entry.is_regular_blob
    }

    selected: dict[str, _GitTreeEntry]
    if not subdirectory or subdirectory == ".":
        selected = dict(regular_files)
    else:
        target = by_path.get(subdirectory)
        target_prefix = subdirectory.rstrip("/") + "/"
        has_descendant = any(path.startswith(target_prefix) for path in by_path)
        if target is not None and target.type != "tree":
            raise _DeterministicAcquisitionError(
                f"Source subdirectory is not a directory: {subdirectory!r}"
            )
        if target is None and not has_descendant:
            raise _DeterministicAcquisitionError(
                f"Source subdirectory does not exist: {subdirectory!r}"
            )
        selected = {
            path: entry
            for path, entry in regular_files.items()
            if path.startswith(target_prefix)
        }

        required_paths = set(_parent_package_json_candidates(subdirectory))
        required_paths.add("manifest.json")
        for path in required_paths:
            entry = regular_files.get(path)
            if entry is not None:
                selected[path] = entry

        parts = PurePosixPath(subdirectory).parts
        ancestor_directories = {""}
        ancestor_directories.update(
            PurePosixPath(*parts[:depth]).as_posix()
            for depth in range(1, len(parts))
        )
        for path, entry in regular_files.items():
            file_path = PurePosixPath(path)
            parent = file_path.parent.as_posix()
            if parent == ".":
                parent = ""
            if (
                parent in ancestor_directories
                and file_path.name.casefold().startswith(_LEGAL_FILE_PREFIXES)
            ):
                selected[path] = entry

    if len(selected) > max(policy.max_files, 0):
        raise _DeterministicAcquisitionError(
            f"Selected source contains more than {policy.max_files} files"
        )
    total_size = sum(entry.size or 0 for entry in selected.values())
    if total_size > max(policy.max_total_bytes, 0):
        raise _DeterministicAcquisitionError(
            f"Selected source exceeds {policy.max_total_bytes} byte limit"
        )

    selected_paths = set(selected)
    normalized_paths: set[str] = set()
    for path in sorted(selected_paths):
        parts = PurePosixPath(path).parts
        if len(parts) - 1 > policy.max_depth:
            raise _DeterministicAcquisitionError(
                f"Selected source entry exceeds depth limit: {path!r}"
            )
        normalized = os.path.normcase(str(Path(*parts)))
        if normalized in normalized_paths:
            raise _DeterministicAcquisitionError(
                f"Selected source contains a platform path collision: {path!r}"
            )
        normalized_paths.add(normalized)
        for depth in range(1, len(parts)):
            ancestor = PurePosixPath(*parts[:depth]).as_posix()
            if ancestor in selected_paths:
                raise _DeterministicAcquisitionError(
                    f"Selected source contains a file/directory collision: {path!r}"
                )

    return tuple(selected[path] for path in sorted(selected))


def _repository_target_path(root: Path, relative_path: str) -> Path:
    parts = PurePosixPath(relative_path).parts
    target = root.joinpath(*parts).resolve()
    if target == root or root not in target.parents:
        raise _DeterministicAcquisitionError(
            f"Selected source entry escapes the repository root: {relative_path!r}"
        )
    return target


def _materialize_repository_entries(
    parsed: dict[str, Any],
    destination: str | Path,
    entries: tuple[_GitTreeEntry, ...],
    prefetched: dict[str, bytes],
    *,
    subdirectory: str | None,
    max_attempts: int = _GITHUB_API_MAX_ATTEMPTS,
    request_budget: _GitHubRequestBudget | None = None,
) -> None:
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)

    representative_by_sha: dict[str, _GitTreeEntry] = {}
    downloaded_by_sha: dict[str, bytes] = {}
    for entry in entries:
        existing = representative_by_sha.get(entry.sha)
        if existing is not None and existing.size != entry.size:
            raise _DeterministicAcquisitionError(
                f"GitHub tree reports conflicting blob sizes: {entry.path!r}"
            )
        representative_by_sha.setdefault(entry.sha, entry)
        if entry.path in prefetched:
            downloaded_by_sha[entry.sha] = prefetched[entry.path]

    remaining = [
        entry
        for sha, entry in representative_by_sha.items()
        if sha not in downloaded_by_sha
    ]
    if request_budget is not None:
        request_budget.require_available(len(remaining))
    if remaining:
        worker_count = min(_GITHUB_BLOB_WORKERS, len(remaining))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(
                    _fetch_git_blob,
                    parsed,
                    entry,
                    max_attempts=max_attempts,
                    request_budget=request_budget,
                ): entry
                for entry in remaining
            }
            try:
                for future in as_completed(futures):
                    entry = futures[future]
                    downloaded_by_sha[entry.sha] = future.result()
            except Exception:
                for future in futures:
                    future.cancel()
                raise

    for entry in entries:
        data = downloaded_by_sha.get(entry.sha)
        if data is None:
            raise _DeterministicAcquisitionError(
                f"Selected source blob was not downloaded: {entry.path!r}"
            )
        if (
            entry.size is None
            or len(data) != entry.size
            or _git_blob_sha(data) != entry.sha
        ):
            raise _DeterministicAcquisitionError(
                f"Selected source blob failed integrity verification: {entry.path!r}"
            )
        target = _repository_target_path(root, entry.path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as target_handle:
            target_handle.write(data)

    if subdirectory and subdirectory != ".":
        target_directory = _repository_target_path(root, subdirectory)
        target_directory.mkdir(parents=True, exist_ok=True)


def _download_github_repository_files(
    parsed: dict[str, Any],
    tmp_dir: str,
    *,
    max_attempts: int = _GITHUB_API_MAX_ATTEMPTS,
    request_budget: _GitHubRequestBudget | None = None,
) -> bool:
    """Acquire the pinned repository scope through Git Trees and Git Blobs."""
    budget = request_budget or _new_github_request_budget()
    try:
        recursive_snapshot = _fetch_git_tree(
            parsed,
            parsed["ref"],
            recursive=True,
            max_attempts=max_attempts,
            request_budget=budget,
        )
        prefetched: dict[str, bytes] = {}
        if recursive_snapshot.truncated:
            root_snapshot = _fetch_git_tree(
                parsed,
                recursive_snapshot.sha,
                recursive=False,
                expected_tree_sha=recursive_snapshot.sha,
                max_attempts=max_attempts,
                request_budget=budget,
            )
            subdirectory = _root_manifest_selection(
                parsed,
                root_snapshot.entries,
                prefetched,
                max_attempts=max_attempts,
                request_budget=budget,
            )
            entries = _entries_for_truncated_tree(
                parsed,
                recursive_snapshot.sha,
                subdirectory,
                root_snapshot=root_snapshot,
                max_attempts=max_attempts,
                request_budget=budget,
            )
        else:
            entries = recursive_snapshot.entries
            subdirectory = _root_manifest_selection(
                parsed,
                entries,
                prefetched,
                max_attempts=max_attempts,
                request_budget=budget,
            )

        selected = _select_repository_entries(
            entries,
            subdirectory,
            policy=_SOURCE_POLICY,
        )
        _materialize_repository_entries(
            parsed,
            tmp_dir,
            selected,
            prefetched,
            subdirectory=subdirectory,
            max_attempts=max_attempts,
            request_budget=budget,
        )
        print(
            "[TAH-trust]     GitHub API acquisition OK: "
            f"{len(selected)} files, {budget.used} requests, "
            f"scope={subdirectory or '.'}"
        )
        return True
    except _DeterministicAcquisitionError:
        raise
    except (_GitHubAcquisitionError, OSError) as exc:
        print(f"[TAH-trust]     GitHub API acquisition failed: {exc}")
        return False


def _preflight_zip_entry_count(archive_file: Any, max_entries: int) -> None:
    """Reject oversized ZIP central directories before ZipFile parses them."""
    eocd_struct = "<4s4H2LH"
    zip64_eocd_struct = "<4sQ2H2L4Q"
    eocd_size = struct.calcsize(eocd_struct)
    max_comment_size = 0xFFFF
    signature = b"PK\x05\x06"
    archive_file.seek(0, 2)
    archive_size = archive_file.tell()
    tail_size = min(archive_size, eocd_size + max_comment_size)
    archive_file.seek(archive_size - tail_size)
    tail = archive_file.read(tail_size)
    archive_file.seek(0)

    eocd_offset = tail.rfind(signature)
    if eocd_offset < 0 or eocd_offset + eocd_size > len(tail):
        return

    fields = struct.unpack_from(eocd_struct, tail, eocd_offset)
    total_entries = fields[4]
    if total_entries == 0xFFFF:
        zip64_signature = b"PK\x06\x06"
        zip64_offset = tail.rfind(zip64_signature, 0, eocd_offset)
        zip64_size = struct.calcsize(zip64_eocd_struct)
        if zip64_offset < 0 or zip64_offset + zip64_size > len(tail):
            raise _DeterministicAcquisitionError(
                "ZIP64 entry count cannot be bounded before archive parsing"
            )
        zip64_fields = struct.unpack_from(zip64_eocd_struct, tail, zip64_offset)
        total_entries = zip64_fields[7]
    if total_entries > max_entries:
        raise _DeterministicAcquisitionError(
            f"ZIP contains more than {max_entries} entries"
        )


def _parent_package_json_candidates(subdirectory: str | None) -> list[str]:
    """Return enclosing package.json paths from nearest parent to repo root."""
    if not subdirectory or subdirectory == ".":
        return []

    parts = PurePosixPath(subdirectory).parts
    candidates = [
        (PurePosixPath(*parts[:depth]) / "package.json").as_posix()
        for depth in range(len(parts) - 1, 0, -1)
    ]
    candidates.append("package.json")
    return candidates


_AUTHOR_PLACEHOLDER_NAMES = frozenset({
    "unknown",
    "unknown@unknown.org",
    "unknown@unknown.com",
})


def _normalized_author_name(value: Any) -> str | None:
    """Return a usable package author name, or None for invalid metadata."""
    if isinstance(value, str):
        name = value.strip()
    elif isinstance(value, dict):
        name = value.get("name")
        if isinstance(name, str):
            name = name.strip()
        else:
            return None
    else:
        return None
    if not name or name.casefold() in _AUTHOR_PLACEHOLDER_NAMES:
        return None
    return name


def _normalized_author_url(value: Any) -> str | None:
    """Return a usable author homepage from object metadata."""
    if not isinstance(value, dict):
        return None
    url = value.get("url")
    if not isinstance(url, str) or not url.strip():
        return None
    normalized = url.strip()
    if normalized.casefold() in _AUTHOR_PLACEHOLDER_NAMES:
        return None
    if "github.com/unknown/" in normalized.casefold():
        return None
    return normalized


def _validate_manifest_json_nesting(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False

    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > _MAX_MANIFEST_JSON_NESTING:
                raise ValueError(
                    "无法扫描：manifest.json 的 JSON 嵌套层级超过支持上限"
                )
        elif char in "]}" and depth:
            depth -= 1


def _root_manifest_subdirectory(text: str) -> str | None:
    _validate_manifest_json_nesting(text)
    try:
        root_data = json.loads(text)
    except RecursionError as exc:
        raise ValueError(
            "无法扫描：manifest.json 的 JSON 嵌套层级超过支持上限"
        ) from exc
    except ValueError as exc:
        logging.warning("Ignoring invalid root manifest source: %s", exc)
        return None

    if not isinstance(root_data, dict):
        logging.warning("Ignoring invalid root manifest source: root must be an object")
        return None
    source_data = root_data.get("source") or {}
    if not isinstance(source_data, dict):
        logging.warning("Ignoring invalid root manifest source: source must be an object")
        return None
    declared = source_data.get("subdirectory")
    if declared is None:
        return None
    try:
        return require_safe_source_subdirectory(declared)
    except ValueError as exc:
        logging.warning("Ignoring invalid root manifest source: %s", exc)
        return None


def _select_parent_package_json(
    subdirectory: str | None,
    repository_file_contents: dict[str, str],
) -> tuple[dict[str, Any] | None, str | None]:
    """Select inherited author metadata only from a bounded repo snapshot."""
    for relative_path in _parent_package_json_candidates(subdirectory):
        text = repository_file_contents.get(relative_path)
        if text is None:
            continue
        try:
            value = json.loads(text)
        except (ValueError, RecursionError) as exc:
            logging.warning(
                "Ignoring invalid parent package metadata %s: %s",
                relative_path,
                exc,
            )
            continue
        if not isinstance(value, dict):
            logging.warning(
                "Ignoring non-object parent package metadata: %s",
                relative_path,
            )
            continue
        author = value.get("author")
        if (
            _normalized_author_name(author) is not None
            or _normalized_author_url(author) is not None
        ):
            return value, relative_path
        if author:
            logging.warning(
                "Ignoring invalid parent package author in %s",
                relative_path,
            )
    return None, None


def _build_repository_snapshot(
    repo_path: Path,
    subdirectory: str | None,
    *,
    policy: ScanPolicy = _SOURCE_POLICY,
    only_manifest: bool = False,
) -> tuple[ScanInventory, dict[str, str]]:
    priority_order = _parent_package_json_candidates(subdirectory)
    priority_paths = set(priority_order)
    priority_paths.add("manifest.json")
    priority_order.append("manifest.json")
    inventory = build_inventory(
        repo_path,
        policy,
        priority_paths=priority_paths,
        priority_order=priority_order,
    )
    contents = load_text_files(
        inventory,
        policy=policy,
        priority_paths=priority_paths,
        priority_order=priority_order,
        only_paths={"manifest.json"} if only_manifest else None,
    )
    return inventory, contents


def _safe_extract_zip(
    archive: zipfile.ZipFile,
    destination: str | Path,
    policy: ScanPolicy = _SOURCE_POLICY,
) -> None:
    """Extract regular ZIP entries safely and ignore symbolic links.

    GitHub zipballs preserve repository symlinks as Unix-mode ZIP entries. The
    scanner must never materialize or follow those links, but an unrelated
    symlink should not make every regular file in an otherwise valid repository
    unscannable. Other special files remain unsupported.
    """
    destination_path = Path(destination).resolve()
    infos = archive.infolist()
    if len(infos) > policy.max_files:
        raise _DeterministicAcquisitionError(
            f"ZIP contains more than {policy.max_files} entries"
        )

    declared_total = 0
    normalized_targets: set[str] = set()
    validated: list[tuple[zipfile.ZipInfo, Path, bool, bool]] = []
    for info in infos:
        name = info.filename
        if not name or "\x00" in name or "\\" in name:
            raise _DeterministicAcquisitionError("ZIP contains an invalid entry name")
        path = Path(name)
        if path.is_absolute() or re.match(r"^[A-Za-z]:", name):
            raise _DeterministicAcquisitionError(f"ZIP entry is absolute: {name!r}")
        parts = tuple(part for part in path.parts if part not in {"", "."})
        if not parts or any(part == ".." for part in parts):
            raise _DeterministicAcquisitionError(
                f"ZIP entry escapes extraction root: {name!r}"
            )
        # Account for GitHub's wrapper directory, which acquisition removes
        # after the complete archive has passed validation.
        if len(parts) - 1 > policy.max_depth + 1:
            raise _DeterministicAcquisitionError(
                f"ZIP entry exceeds depth limit: {name!r}"
            )
        if info.flag_bits & 0x1:
            raise _DeterministicAcquisitionError(
                f"encrypted ZIP entry is not supported: {name!r}"
            )

        unix_mode = info.external_attr >> 16
        unix_file_type = stat.S_IFMT(unix_mode)
        is_directory = info.is_dir()
        is_symlink = bool(unix_file_type and stat.S_ISLNK(unix_mode))
        if unix_file_type and not (
            is_symlink
            or (
                stat.S_ISDIR(unix_mode)
                if is_directory
                else stat.S_ISREG(unix_mode)
            )
        ):
            raise _DeterministicAcquisitionError(
                f"ZIP contains a special file: {name!r}"
            )

        target = destination_path.joinpath(*parts)
        resolved_target = target.resolve()
        if (
            resolved_target != destination_path
            and destination_path not in resolved_target.parents
        ):
            raise _DeterministicAcquisitionError(
                f"ZIP entry escapes extraction root: {name!r}"
            )
        target_key = os.path.normcase(str(resolved_target))
        if target_key in normalized_targets:
            raise _DeterministicAcquisitionError(
                f"ZIP contains a duplicate entry: {name!r}"
            )
        normalized_targets.add(target_key)

        if not is_directory and not is_symlink:
            declared_total += info.file_size
            if declared_total > policy.max_total_bytes:
                raise _DeterministicAcquisitionError(
                    f"ZIP expands beyond {policy.max_total_bytes} byte limit"
                )
        validated.append((info, resolved_target, is_directory, is_symlink))

    actual_total = 0
    for info, target, is_directory, is_symlink in validated:
        if is_symlink:
            logging.info("Skipping symbolic-link ZIP entry: %s", info.filename)
            continue
        if is_directory:
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with (
            archive.open(info, "r") as source_handle,
            target.open("xb") as target_handle,
        ):
            while True:
                remaining = policy.max_total_bytes - actual_total
                chunk = source_handle.read(min(_ZIP_READ_CHUNK_BYTES, remaining + 1))
                if not chunk:
                    break
                actual_total += len(chunk)
                written += len(chunk)
                if actual_total > policy.max_total_bytes:
                    raise _DeterministicAcquisitionError(
                        f"ZIP expands beyond {policy.max_total_bytes} byte limit"
                    )
                target_handle.write(chunk)
        if written != info.file_size:
            raise _DeterministicAcquisitionError(
                f"ZIP entry size changed while extracting: {info.filename!r}"
            )


def _download_zipball(parsed: dict[str, Any], tmp_dir: str, max_attempts: int = 3) -> bool:
    """下载固定 ref 的 ZIP 包，并在资源预算内解压到 tmp_dir。"""
    token = get_settings().github_token or ""
    api_url = (
        f"https://api.github.com/repos/{parsed['owner']}/{parsed['repo']}"
        f"/zipball/{parsed['ref']}"
    )
    headers = _github_api_headers()
    if token:
        print(f"[TAH-trust]     ZIP 下载使用 Token 认证")
    else:
        print(f"[TAH-trust]     ZIP 下载无 Token（匿名）")

    for attempt in range(1, max_attempts + 1):
        print(f"[TAH-trust]     ZIP download (attempt {attempt}/{max_attempts}) {api_url}")
        rate_limited = False
        try:
            _wait_for_github_rate_limit()
            req = urllib.request.Request(api_url, headers=headers)
            with tempfile.TemporaryFile() as archive_file:
                with _GITHUB_API_CONCURRENCY_GATE:
                    with urllib.request.urlopen(req, timeout=120) as resp:
                        _observe_github_rate_limit_headers(
                            getattr(resp, "headers", None)
                        )
                        _copy_response_bounded(
                            resp,
                            archive_file,
                            _SOURCE_POLICY.max_total_bytes,
                        )
                _preflight_zip_entry_count(
                    archive_file,
                    _SOURCE_POLICY.max_files,
                )
                with zipfile.ZipFile(archive_file) as zf:
                    _safe_extract_zip(zf, tmp_dir, _SOURCE_POLICY)
            print(f"[TAH-trust]     ZIP download OK (attempt {attempt})")
            return True
        except _DeterministicAcquisitionError as exc:
            print(f"[TAH-trust]     ZIP attempt {attempt} failed: {exc}")
            raise
        except urllib.error.HTTPError as exc:
            print(f"[TAH-trust]     ZIP attempt {attempt} failed: {exc}")
            rate_limited = _observe_github_rate_limit_headers(
                getattr(exc, "headers", None),
                exc.code,
            )
            try:
                exc.close()
            except OSError:
                pass
            if not rate_limited and exc.code not in _GITHUB_TRANSIENT_STATUS_CODES:
                return False
            if attempt < max_attempts:
                if not rate_limited:
                    _time.sleep(3)
                force_rmtree(tmp_dir)
                os.makedirs(tmp_dir, exist_ok=True)
        except (
            urllib.error.URLError,
            TimeoutError,
            ConnectionError,
            http.client.IncompleteRead,
            http.client.RemoteDisconnected,
            socket.timeout,
        ) as exc:
            print(f"[TAH-trust]     ZIP attempt {attempt} failed: {exc}")
            if attempt < max_attempts:
                _time.sleep(3)
                force_rmtree(tmp_dir)
                os.makedirs(tmp_dir, exist_ok=True)
        except Exception as exc:
            print(f"[TAH-trust]     ZIP attempt {attempt} failed: {exc}")
            return False
    return False


def _flatten_zipball_root(tmp_dir: str) -> bool:
    """Move a validated GitHub zipball's single wrapper into the scan root."""
    root = Path(tmp_dir).resolve()
    entries = list(root.iterdir())
    if len(entries) != 1 or entries[0].is_symlink() or not entries[0].is_dir():
        return False

    wrapper = entries[0]
    for item in wrapper.iterdir():
        item.replace(root / item.name)
    wrapper.rmdir()
    return True


def _acquire_repo_source(parsed: dict[str, Any]) -> tuple[str | None, str, str]:
    """Resolve a commit and acquire a bounded repository snapshot.

    Returns:
        (repo_root, source_method, commit_hash) — repo_root 是仓库内容根目录路径，
        source_method 为 "github_api" 或 "zip"，commit_hash 为真实 40 位 git hash。
        有 Token 时使用 Trees/Blobs；匿名时使用单请求 ZIP 回退。两者都使用
        默认分支解析出的不可变 commit，而不是可变分支名。
        失败返回 (None, "", "")。
    """
    tmp_dir = tempfile.mkdtemp(prefix=f"tah_repo_")
    use_github_api = bool(get_settings().github_token)
    request_budget = _new_github_request_budget() if use_github_api else None
    try:
        commit_hash = _fetch_repository_commit_hash(
            parsed,
            request_budget=request_budget,
        )
    except Exception as exc:
        print(f"[TAH-trust]     commit resolution failed: {exc}")
        force_rmtree(tmp_dir)
        return None, "", ""

    pinned = {**parsed, "ref": commit_hash}
    try:
        if use_github_api:
            print(
                f"[TAH-trust] === Budgeted GitHub API acquisition: "
                f"{commit_hash[:8]} ==="
            )
            downloaded = _download_github_repository_files(
                pinned,
                tmp_dir,
                request_budget=request_budget,
            )
            method = "github_api"
        else:
            print(
                f"[TAH-trust] === Anonymous bounded ZIP acquisition: "
                f"{commit_hash[:8]} ==="
            )
            downloaded = _download_zipball(pinned, tmp_dir)
            method = "zip"
            if downloaded and not _flatten_zipball_root(tmp_dir):
                print("[TAH-trust]     ZIP download lacks a single repository root")
                downloaded = False
    except _DeterministicAcquisitionError:
        force_rmtree(tmp_dir)
        raise
    except Exception as exc:
        print(f"[TAH-trust]     unexpected acquisition failure: {exc}")
        force_rmtree(tmp_dir)
        return None, "", ""
    if downloaded:
        print(f"[TAH-trust]     {method} commit: {commit_hash[:8]}")
        return tmp_dir, method, commit_hash

    force_rmtree(tmp_dir)
    return None, "", ""


# ---------------------------------------------------------------------------
# 后台扫描任务
# ---------------------------------------------------------------------------


def _build_acquisition_facts(
    parsed: dict[str, Any] | None,
    repo_url: str,
    subdir: str | None,
    method: str,
    commit_hash: str,
    scanner: Any,
) -> dict[str, Any]:
    """Build provenance facts from acquisition, never from package metadata.

    Repository identity is verified from the acquired URL/commit.  Signature,
    attestation, and SBOM flags are accepted only from an independent
    server-side verifier; package metadata is never used as a fallback.
    """
    scanner_facts = getattr(scanner, "acquisition_facts", {})
    if not isinstance(scanner_facts, dict):
        scanner_facts = {}
    scanner_source = scanner_facts.get("source", {})
    if not isinstance(scanner_source, dict):
        scanner_source = {}
    scanner_integrity = scanner_facts.get("integrity", {})
    if not isinstance(scanner_integrity, dict):
        scanner_integrity = {}
    scanner_verification = scanner_facts.get("verification", {})
    if not isinstance(scanner_verification, dict):
        scanner_verification = {}

    valid_commit = bool(re.fullmatch(r"^[a-f0-9]{40}$", commit_hash))
    acquired_commit = commit_hash if valid_commit else scanner_source.get("commit_hash", "")
    if not re.fullmatch(r"^[a-f0-9]{40}$", str(acquired_commit)):
        acquired_commit = ""
    acquired_sha256 = scanner_integrity.get("sha256", "")
    if not re.fullmatch(r"^[a-f0-9]{64}$", str(acquired_sha256)):
        acquired_sha256 = ""
    hash_scope = scanner_integrity.get("hash_scope")
    if hash_scope != HASH_SCOPE_SCANNED_SOURCE:
        hash_scope = None
    is_complete = (
        bool(acquired_sha256)
        and hash_scope == HASH_SCOPE_SCANNED_SOURCE
        and scanner_integrity.get("is_complete") is True
    )
    verification = build_verification_facts(
        parsed=parsed,
        repository_url=repo_url,
        acquisition_method=method,
        commit_hash=str(acquired_commit),
        content_sha256=str(acquired_sha256),
        is_complete=is_complete,
        server_verification=scanner_verification,
    )
    verification_capabilities = build_verification_capabilities(
        scanner_verification
    )

    source: dict[str, Any] = {
        "type": "github" if parsed else "unknown",
        "repository_url": repo_url if repo_url.startswith("https://") else "",
        "owner": (parsed or {}).get("owner", ""),
        "repo": (parsed or {}).get("repo", ""),
        # Treat the resolved commit as the only stable ref we know was
        # acquired.  A manifest cannot upgrade a branch into a tag/release.
        "ref_type": "commit" if acquired_commit else "branch",
        "ref": acquired_commit or (parsed or {}).get("ref", ""),
        "commit_hash": acquired_commit,
        "verified_owner": verification["owner"],
    }
    if subdir:
        source["subdirectory"] = subdir

    integrity = {
        "sha256": acquired_sha256,
        "hash_scope": hash_scope,
        "is_complete": is_complete,
    }
    return {
        "source": source,
        "integrity": integrity,
        "verification": verification,
        "verification_capabilities": verification_capabilities,
        "acquisition_method": method,
    }


def _provenance_claims(scanner: Any) -> dict[str, Any]:
    """Retain redacted source/integrity claims for audit, never for scoring."""
    claims = getattr(scanner, "package_claims", None)
    if not isinstance(claims, dict):
        claims = getattr(scanner, "_package_metadata", None)
    if not isinstance(claims, dict):
        return {"source": {}, "integrity": {}}
    source_claims = claims.get("source")
    integrity_claims = claims.get("integrity")
    claims = {
        "source": deepcopy(source_claims) if isinstance(source_claims, dict) else {},
        "integrity": (
            deepcopy(integrity_claims)
            if isinstance(integrity_claims, dict)
            else {}
        ),
    }
    redacted_claims = redact_value(claims)
    return redacted_claims if isinstance(redacted_claims, dict) else {
        "source": {},
        "integrity": {},
    }


def _apply_acquisition_facts(
    package_metadata: dict[str, Any],
    acquisition_facts: dict[str, Any],
) -> dict[str, Any]:
    """Replace provenance namespaces with server-established facts."""
    safe_metadata = deepcopy(package_metadata)
    safe_metadata["source"] = deepcopy(acquisition_facts.get("source") or {})
    safe_metadata["integrity"] = deepcopy(acquisition_facts.get("integrity") or {})
    return safe_metadata


def _run_scan_task(
    scan_id: str,
    source: str,
    *,
    on_complete: Callable[[str, dict[str, Any] | None, str | None], None] | None = None,
    signals: Dict[str, Any] | None = None,
    resolved_source: dict[str, Any] | None = None,
) -> None:
    """后台执行扫描流水线：acquire → scan → score → save。

    此函数在 BackgroundTasks 中异步运行。
    signals: 提交时从数据库采集的平台信号（author_history / review_records / feedback）。
    """
    try:
        print(f"\n[TAH-trust] >>> _run_scan_task 开始 scan_id={scan_id}")
        print(f"[TAH-trust]     source = {source}")

        parsed = (
            dict(resolved_source)
            if resolved_source is not None
            else _resolve_default_branch_source(_parse_github_url(source))
        )
        print(f"[TAH-trust]     owner={parsed['owner']}, repo={parsed['repo']}, "
              f"default_branch={parsed['ref']}, subdir={parsed['subdir']}")

        _scans[scan_id]["status"] = "downloading"

        repo_root, method, commit_hash = _acquire_repo_source(parsed)
        if repo_root is None:
            _scans[scan_id]["status"] = "error"
            _scans[scan_id]["error"] = (
                "无法解析或下载受限的仓库快照。"
                "请检查 GitHub 连接。"
            )
            print(f"[TAH-trust] *** 获取仓库失败（commit + GitHub API/ZIP）")
            if on_complete:
                on_complete(scan_id, None, _scans[scan_id]["error"])
            return
        tmp_dir = repo_root
        print(f"[TAH-trust]     仓库获取方式: {method}")

        repo_path = Path(repo_root).resolve()
        subdir = parsed.get("subdir") if parsed else None
        repo_inventory: ScanInventory | None = None
        repo_file_contents: dict[str, str] = {}
        if not subdir:
            repo_inventory, repo_file_contents = _build_repository_snapshot(
                repo_path,
                None,
                only_manifest=True,
            )
            root_manifest_text = repo_file_contents.get("manifest.json")
            if root_manifest_text is not None:
                declared = _root_manifest_subdirectory(root_manifest_text)
                if declared is not None:
                    subdir = declared
                    print(f"[TAH-trust]     manifest 声明子目录: {subdir}")
        if subdir:
            subdir = require_safe_source_subdirectory(subdir)
            candidate = (repo_path / subdir).resolve()
            if candidate != repo_path and repo_path not in candidate.parents:
                raise ValueError(f"source subdirectory escapes repository root: {subdir}")
            if not candidate.is_dir():
                raise ValueError(f"source subdirectory does not exist: {subdir}")
            subdir = candidate.relative_to(repo_path).as_posix()
            scan_dir = str(candidate)
            print(f"[TAH-trust]     扫描子目录: {subdir}")
        else:
            scan_dir = repo_root

        parent_priority_order = _parent_package_json_candidates(subdir)
        if repo_inventory is None or parent_priority_order:
            repo_file_contents.clear()
            repo_inventory, repo_file_contents = _build_repository_snapshot(
                repo_path,
                subdir,
            )
        else:
            repo_file_contents = load_text_files(
                repo_inventory,
                policy=_SOURCE_POLICY,
                priority_paths={"manifest.json"},
                priority_order=["manifest.json"],
                existing_contents=repo_file_contents,
            )
        parent_package_json, parent_package_path = _select_parent_package_json(
            subdir,
            repo_file_contents,
        )
        if parent_package_path:
            print(
                "[TAH-trust]     继承 package.json author: "
                f"{parent_package_path}"
            )

        # ── 多能力发现（供提交页选择子目录） ──
        capabilities: list[dict[str, str]] = []
        try:
            if not hasattr(
                sys.modules.get("extract_skills", None),
                "discover_capabilities",
            ):
                spec = importlib.util.spec_from_file_location(
                    "extract_skills", str(_EXTRACTOR_PATH)
                )
                if spec and spec.loader:
                    extract_mod = importlib.util.module_from_spec(spec)
                    sys.modules["extract_skills"] = extract_mod
                    spec.loader.exec_module(extract_mod)
            capabilities = sys.modules["extract_skills"].discover_capabilities(
                repo_root,
                policy=_SOURCE_POLICY,
                inventory=repo_inventory,
                file_contents=repo_file_contents,
            )
            if subdir:
                prefix = str(subdir).rstrip("/")
                filtered = [
                    c for c in capabilities
                    if c["path"] == prefix
                    or c["path"].startswith(prefix + "/")
                ]
                if filtered:
                    capabilities = filtered
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[TAH-trust]     能力发现失败（忽略）: {exc}")
            capabilities = []
        _scans[scan_id]["capabilities"] = capabilities
        print(
            f"[TAH-trust]     发现能力包: {len(capabilities)} 个"
        )

        # Release discovery data before the scanner builds the target snapshot.
        repo_file_contents.clear()
        del repo_file_contents
        del repo_inventory

        # Step 2: 运行扫描器
        _scans[scan_id]["status"] = "scanning"
        print(f"[TAH-trust]     加载扫描器, scan_dir={scan_dir}")
        RiskScanner = _load_scanner()
        scanner = RiskScanner(
            scan_dir,
            source_commit_hash=commit_hash,
            policy=_SOURCE_POLICY,
        )
        scan_report = scanner.scan()

        pkg_name = scan_report.get("package_name", "unknown")
        pkg_version = scan_report.get("version", "0.0.0")
        _scans[scan_id]["package_name"] = pkg_name
        print(f"[TAH-trust]     扫描完成: {pkg_name} v{pkg_version}, findings={scan_report['summary']['total']}")

        # Extract the complete package metadata before semantic review so the
        # LLM sees declared permissions and the report can reconcile them with
        # code/documentation evidence.
        repo_url = parsed["base_url"] if parsed else source
        package_metadata = _build_package_metadata(
            scan_report,
            scan_dir,
            repo_url=repo_url,
            subdirectory=subdir,
            policy=scanner.policy,
            inventory=scanner.inventory,
            file_contents=scanner._file_contents,
            parent_package_json=parent_package_json,
        )
        permission_evidence = package_metadata.get("permission_evidence", [])
        scan_report["permission_evidence"] = (
            permission_evidence if isinstance(permission_evidence, list) else []
        )
        reconcile_permission_advisories(
            scan_report,
            scan_report["permission_evidence"],
        )

        # Step 2.5: LLM 语义复核。上下文候选通常双审，冲突时第三审仲裁。
        findings = scan_report.get("findings", [])
        if findings:
            _scans[scan_id]["status"] = "llm_review"
            reviewable_total = sum(
                1
                for finding in findings
                if isinstance(finding, dict)
                and finding.get("id")
                and _is_llm_reviewable_finding(finding)
            )
            progress, deadline_monotonic = _initial_llm_progress(reviewable_total)
            with _SCAN_PROGRESS_LOCK:
                _scans[scan_id]["llm_review"] = progress
            heartbeat_stop = threading.Event()
            heartbeat_thread = threading.Thread(
                target=_heartbeat_llm_progress,
                args=(scan_id, heartbeat_stop),
                name=f"llm-progress-{scan_id}",
                daemon=True,
            )
            heartbeat_thread.start()
            print(
                f"[TAH-trust]     LLM 审查: {reviewable_total} findings 待审查..."
            )
            try:
                scan_report["llm_review"] = _run_llm_review_with_fallback(
                    findings,
                    scanner,
                    manifest=package_metadata,
                    progress_callback=lambda update: _update_llm_progress(
                        scan_id, update
                    ),
                    deadline_monotonic=deadline_monotonic,
                )
            finally:
                heartbeat_stop.set()
                heartbeat_thread.join(timeout=1.0)

            llm_result = scan_report["llm_review"]
            result_status = str(llm_result.get("status") or "call_failed")
            public_status = (
                "timeout"
                if result_status == "timeout"
                else "completed"
                if result_status in {"completed", "not_required"}
                else "degraded"
            )
            final_progress: dict[str, Any] = {
                "status": public_status,
                "findings_total": reviewable_total,
                "findings_reviewed": _nonnegative_int(
                    llm_result.get("findings_reviewed", 0)
                ),
                "findings_pending": _nonnegative_int(
                    llm_result.get("findings_pending", 0)
                ),
            }
            if public_status != "timeout":
                final_progress["phase"] = "complete"
            fallback = llm_result.get("fallback")
            if isinstance(fallback, str) and fallback:
                final_progress["fallback"] = fallback
            _update_llm_progress(scan_id, final_progress)
        else:
            scan_report["llm_review"] = {
                "triggered": False,
                "findings_reviewed": 0,
                "findings_skipped": 0,
                "findings_pending": 0,
                "status": "not_triggered",
                "attempts": 0,
                "review_rounds": 0,
                "arbitrated": 0,
                "labels": {},
                "decisions": {},
            }
            _scans[scan_id]["llm_review"] = {
                "status": "completed",
                "phase": "complete",
                "attempt": 0,
                "max_attempts": 3,
                "findings_total": 0,
                "findings_reviewed": 0,
                "findings_pending": 0,
            }
        refresh_report_summaries(scan_report)

        snapshot_metadata = _SOURCE_SNAPSHOT_STORE.save(
            scanner._file_contents,
            owner_id=str(
                _scans.get(scan_id, {}).get("source_owner_id")
                or _scans.get(scan_id, {}).get("user_id")
                or ""
            ) or None,
        )
        scan_report["source_snapshot_id"] = snapshot_metadata["snapshot_id"]
        scan_report["source_snapshot_sha256"] = snapshot_metadata["sha256"]
        scan_report["source_snapshot_created_at"] = snapshot_metadata["created_at"]
        scan_report["source_snapshot_expires_at"] = snapshot_metadata["expires_at"]
        scan_report = redact_report(scan_report)

        # Step 3: 运行评分引擎
        _scans[scan_id]["status"] = "scoring"
        print(f"[TAH-trust]     加载评分引擎...")
        calculate_trust_score = _load_scorer()

        acquisition_facts = _build_acquisition_facts(
            parsed,
            repo_url,
            subdir,
            method,
            commit_hash,
            scanner,
        )
        package_claims = _provenance_claims(scanner)
        package_metadata = _apply_acquisition_facts(
            package_metadata,
            acquisition_facts,
        )
        # Persist claims as evidence, but keep them outside the metadata
        # namespaces consumed by the score engine.
        scan_report["provenance"] = {
            "acquisition_facts": deepcopy(acquisition_facts),
            "package_claims": deepcopy(package_claims),
        }
        # Provenance claims are untrusted package input.  Redact once more at
        # the report boundary so future additions cannot bypass the scanner's
        # earlier redaction pass.
        scan_report = redact_report(scan_report)

        platform_signals = signals or {}
        trust_score_result = calculate_trust_score(
            package_metadata=package_metadata,
            scan_report=scan_report,
            author_history=platform_signals.get("author_history"),
            review_records=platform_signals.get("review_records"),
            feedback=platform_signals.get("feedback"),
            acquisition_facts=acquisition_facts,
        )
        if platform_signals:
            print(
                f"[TAH-trust]     平台信号接入: "
                f"author={platform_signals.get('author_history')}, "
                f"review={platform_signals.get('review_records', {}).get('status')}, "
                f"installs={platform_signals.get('feedback', {}).get('total_installs')}"
            )
        print(f"[TAH-trust]     评分完成: score={trust_score_result.get('score')}, level={trust_score_result.get('risk_summary', {}).get('level')}")

        # Step 4: 合并报告并保存到磁盘
        _scans[scan_id]["status"] = "saving"
        full_report: Dict[str, Any] = {
            "scan_id": scan_id,
            "repo_url": repo_url,
            "package_name": pkg_name,
            "version": pkg_version,
            "source_ref": parsed["ref"],
            "source_method": method,
            "commit_hash": commit_hash,
            "created_at": _scans[scan_id]["created_at"],
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "scan_report": scan_report,
            "trust_score": trust_score_result,
            "package_metadata": package_metadata,
            "acquisition_facts": acquisition_facts,
            "package_claims": package_claims,
            "source_snapshot_id": snapshot_metadata["snapshot_id"],
            "source_snapshot_sha256": snapshot_metadata["sha256"],
            "source_subdirectory": subdir,
            # 保留本地代码目录供提交时打包安装产物（不重新拉取）。
            # 由 handle_scan_complete 消费后清理，或随扫描记录过期清理。
            "local_source_dir": tmp_dir,
        }

        # Step 5: 更新内存状态
        _scans[scan_id].update({
            "status": "complete",
            "finished_at": full_report["finished_at"],
            "full_report": full_report,
            "package_metadata": package_metadata,
            "acquisition_facts": acquisition_facts,
            "package_claims": package_claims,
            "summary": scan_report.get("summary", {}),
            "trust_score": {
                "level": trust_score_result.get("risk_summary", {}).get("level"),
                "grade": trust_score_result.get("risk_summary", {}).get("grade"),
                "recommendation": trust_score_result.get("risk_summary", {}).get("install_recommendation"),
            },
        })

        # 临时目录保留给提交阶段打包产物，由 handle_scan_complete / 过期清理负责删除
        if on_complete:
            on_complete(scan_id, full_report, None)
        print(f"[TAH-trust] *** 扫描流水线完成: {scan_id}, grade={trust_score_result.get('risk_summary', {}).get('grade')}")

    except Exception as exc:
        _scans[scan_id]["status"] = "error"
        err_msg = str(exc)
        token = get_settings().github_token or ""
        if token and token in err_msg:
            err_msg = err_msg.replace(token, "***")
        if isinstance(exc, _DeterministicAcquisitionError):
            public_error = f"仓库快照未通过安全校验：{err_msg}"
        else:
            public_error = f"Scan failed: {type(exc).__name__}: {err_msg}"
        _scans[scan_id]["error"] = public_error
        print(f"[TAH-trust] *** 扫描异常: {type(exc).__name__}: {err_msg}", flush=True)
        if "tmp_dir" in locals():
            force_rmtree(tmp_dir)
        if on_complete:
            on_complete(scan_id, None, public_error)


def _normalize_fallback_author(value: Any) -> dict[str, str] | None:
    """Normalize a package.json author value for fallback metadata."""
    name = _normalized_author_name(value)
    if isinstance(value, str):
        return {"name": name} if name is not None else None
    if isinstance(value, dict):
        author: dict[str, str] = {}
        if name is not None:
            author["name"] = name
        email = str(value.get("email") or "").strip()
        if email and email.casefold() not in _AUTHOR_PLACEHOLDER_NAMES:
            author["email"] = email
        url = _normalized_author_url(value)
        if url is not None:
            author["url"] = url
        return author or None
    return None


def _repository_owner_homepage(repo_url: str) -> str | None:
    match = re.match(
        r"https?://github\.com/([^/?#]+)/[^/?#]+(?:\.git)?(?:/|$)",
        repo_url.strip(),
        flags=re.IGNORECASE,
    )
    return f"https://github.com/{match.group(1)}" if match else None


def _apply_fallback_author(
    metadata: dict[str, Any],
    local_package_author: Any,
    parent_package_json: dict[str, Any] | None,
    repo_url: str = "",
) -> dict[str, Any]:
    """Merge declared author data and infer a missing GitHub owner homepage."""
    author = _normalize_fallback_author(metadata.get("author")) or {}
    candidates = [local_package_author]
    if isinstance(parent_package_json, dict):
        candidates.append(parent_package_json.get("author"))
    for candidate in candidates:
        normalized = _normalize_fallback_author(candidate) or {}
        for field, value in normalized.items():
            author.setdefault(field, value)

    inferred_url = _repository_owner_homepage(repo_url)
    if inferred_url:
        author.setdefault("url", inferred_url)
    if author:
        metadata["author"] = author
    return metadata


def _build_package_metadata(
    scan_report: Dict[str, Any],
    target_dir: str,
    repo_url: str = "",
    subdirectory: str | None = None,
    *,
    policy: ScanPolicy | None = None,
    inventory: ScanInventory | None = None,
    file_contents: dict[str, str] | None = None,
    parent_package_json: dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """从扫描报告和目标目录构建 package_metadata 用于评分引擎。

    优先使用 extract_skills 模块进行完整提取（11 个必填字段、依赖解析、
    权限推断、分类推断）；失败时回退到原始简易逻辑。
    """
    target = Path(target_dir)

    # ── 优先：使用 extract_skills 完整提取 ──
    try:
        # 动态加载 extract_skills 模块（仅首次）
        if not hasattr(sys.modules.get("extract_skills", None), "extract_single_skill"):
            spec = importlib.util.spec_from_file_location(
                "extract_skills", str(_EXTRACTOR_PATH))
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                sys.modules["extract_skills"] = mod
                spec.loader.exec_module(mod)

        extract_single_skill = sys.modules["extract_skills"].extract_single_skill
        data = extract_single_skill(
            target,
            repo_url=repo_url,
            subdirectory=subdirectory,
            policy=policy,
            inventory=inventory,
            file_contents=file_contents,
            parent_package_json=parent_package_json,
        )
        if data:
            print(f"[TAH-trust]     extract_skills 成功提取: name={data.get('name')}, "
                  f"version={data.get('version')}, category={data.get('category')}")
            return data
    except (ValueError, FileNotFoundError) as e:
        print(f"[TAH-trust]     extract_skills 跳过（{e}），回退到简易提取")
    except Exception as e:
        print(f"[TAH-trust]     extract_skills 失败（{e}），回退到简易提取")

    # ── 回退：原始简易提取逻辑 ──
    # 尝试 manifest.json
    bounded_contents = file_contents or {}
    local_package_author: Any = None
    package_text = bounded_contents.get("package.json")
    if package_text is not None:
        try:
            package_value = json.loads(package_text)
            if isinstance(package_value, dict):
                local_package_author = package_value.get("author")
        except (ValueError, RecursionError) as exc:
            logging.warning("package.json fallback failed for %s: %s", target, exc)

    manifest_text = bounded_contents.get("manifest.json")
    if manifest_text is not None:
        try:
            value = json.loads(manifest_text)
            if isinstance(value, dict):
                return _apply_fallback_author(
                    value,
                    local_package_author,
                    parent_package_json,
                    repo_url,
                )
            logging.warning("manifest.json root is not an object for %s", target)
        except (ValueError, RecursionError, OSError) as e:
            logging.warning("manifest.json fallback failed for %s: %s", target, e)

    # 尝试 plugin.json
    plugin_text = bounded_contents.get("plugin.json")
    if plugin_text is not None:
        try:
            value = json.loads(plugin_text)
            if isinstance(value, dict):
                return _apply_fallback_author(
                    value,
                    local_package_author,
                    parent_package_json,
                    repo_url,
                )
            logging.warning("plugin.json root is not an object for %s", target)
        except (ValueError, RecursionError, OSError) as e:
            logging.warning("plugin.json fallback failed for %s: %s", target, e)

    # 尝试解析 SKILL.md frontmatter
    skill_text = bounded_contents.get("SKILL.md")
    if skill_text is not None:
        try:
            result = parse_frontmatter(skill_text)
            if result.data:
                return _apply_fallback_author(
                    result.data,
                    local_package_author,
                    parent_package_json,
                    repo_url,
                )
        except (OSError, UnicodeDecodeError) as e:
            logging.warning("SKILL.md fallback failed for %s: %s", target, e)

    # 从 scan_report 构建最简 metadata
    logging.warning("All metadata fallbacks failed for %s, returning stub metadata", target)
    fallback_metadata = {
        "name": scan_report.get("package_name", "unknown"),
        "version": scan_report.get("version", "0.0.0"),
        "type": "unknown",
        "description": "Scanned package",
        "author": {"name": "unknown", "email": "unknown@unknown.com"},
        "license": "UNKNOWN",
        "source": {"type": "unknown", "repository_url": "", "ref": "", "commit_hash": ""},
        "integrity": {"sha256": ""},
        "compatibility": [],
        "permissions": {},
        "installation": {"method": "unknown", "targets": []},
    }
    return _apply_fallback_author(
        fallback_metadata,
        local_package_author,
        parent_package_json,
        repo_url,
    )


# ---------------------------------------------------------------------------
# URL 规范化
# ---------------------------------------------------------------------------


def _parse_github_url(url: str) -> dict[str, Any]:
    """解析 GitHub URL，提取 owner / repo / tree 路径。

    处理以下格式:
        https://github.com/owner/repo
        https://github.com/owner/repo.git
        https://github.com/owner/repo/tree/main
        https://github.com/owner/repo/tree/main/subdir/path

    ``tree_path`` 会在查询 GitHub ``default_branch`` 后再解析，避免将
    非默认分支误作为扫描来源，也能正确处理名称带斜杠的默认分支。
    """
    url = url.strip().rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]

    m = re.search(r"^https://github\.com/([^/]+)/([^/]+)(?:/tree/(.+))?$", url)
    if not m:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid GitHub URL format: {url}",
        )

    owner = m.group(1)
    repo = m.group(2)

    return {
        "base_url": f"https://github.com/{owner}/{repo}",
        "owner": owner,
        "repo": repo,
        "tree_path": m.group(3) or None,
    }


# ---------------------------------------------------------------------------
# POST /scan
# ---------------------------------------------------------------------------


@router.post("/scan", response_model=ScanResponse)
def submit_scan(
    background_tasks: BackgroundTasks,
    repo_url: Optional[str] = None,
    body: Optional[ScanRequest] = None,
    _user: CurrentUser = Depends(require_role("submitter")),
) -> Dict[str, Any]:
    """提交一个新的扫描任务。

    支持两种方式:
    1. JSON body: {"repo_url": "https://github.com/..."}
    2. Query param: ?repo_url=https://github.com/...

    返回 scan_id 用于后续查询。
    """
    # 获取 URL
    url = repo_url
    if body and body.repo_url:
        url = body.repo_url

    print(f"\n[TAH-trust] >>> POST /scan 收到请求")
    print(f"[TAH-trust]     query_param repo_url = {repo_url!r}")
    print(f"[TAH-trust]     body.repo_url       = {body.repo_url if body else 'N/A'!r}")

    if not url:
        print(f"[TAH-trust] *** 缺少 repo_url，返回 400")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing 'repo_url'. Provide it in JSON body or as query parameter.",
        )

    # 基本 URL 验证
    url = url.strip()
    print(f"[TAH-trust]     raw url = {url!r}")
    if not url.startswith("https://github.com/"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only https://github.com/... URLs are supported at this time.",
        )

    # 解析 URL 并同步校验：仅允许 GitHub 声明的默认分支。
    # 同步端点由 FastAPI 放入线程池，避免阻塞事件循环的 GitHub API 请求。
    parsed = _resolve_default_branch_source(_parse_github_url(url))
    print(f"[TAH-trust]     parsed: owner={parsed['owner']}, repo={parsed['repo']}, "
          f"default_branch={parsed['ref']}, subdir={parsed['subdir']}")

    source = url

    # 创建扫描任务
    scan_id = f"scan-{uuid.uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()
    print(f"[TAH-trust]     scan_id = {scan_id}, 启动后台任务...")

    _scans[scan_id] = {
        "status": "pending",
        "package_name": None,
        "created_at": now,
        "finished_at": None,
        "full_report": None,
        "summary": None,
        "trust_score": None,
        "error": None,
        "expires_at": _time.time() + _SCAN_TTL_SECONDS,
        "user_id": _user.id,
        "source_owner_id": _user.id,
    }

    # 启动后台扫描
    background_tasks.add_task(
        _run_scan_task,
        scan_id,
        source,
        resolved_source=parsed,
    )

    return {
        "scan_id": scan_id,
        "status": "pending",
        "package_name": None,
        "created_at": now,
    }


# ---------------------------------------------------------------------------
# GET /scan/{scan_id}
# ---------------------------------------------------------------------------


@router.get("/scan/{scan_id}", response_model=ScanStatusResponse)
def get_scan_status(
    scan_id: str,
    _user: CurrentUser = Depends(require_role("submitter")),
) -> Dict[str, Any]:
    """查询扫描任务的状态。

    status 可能的值:
        pending  — 已入队，等待处理
        downloading — 正在下载受限仓库快照
        scanning — 正在运行风险扫描
        llm_review — 正在进行多评审 LLM 语义复核
        scoring  — 正在计算信任评分
        saving   — 正在保存报告
        complete — 扫描完成
        error    — 扫描失败
    """
    _cleanup_expired_scans()
    info = _scans.get(scan_id)
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_scan_not_found_detail(scan_id),
        )

    verify_resource_access(_user, info.get("user_id", ""))

    return {
        "scan_id": scan_id,
        "status": info["status"],
        "package_name": info.get("package_name"),
        "created_at": info["created_at"],
        "finished_at": info.get("finished_at"),
        "summary": info.get("summary"),
        "trust_score": info.get("trust_score"),
        "llm_review": info.get("llm_review"),
        "error": info.get("error"),
    }


# ---------------------------------------------------------------------------
# GET /scan/{scan_id}/metadata
# ---------------------------------------------------------------------------


@router.get("/scan/{scan_id}/metadata")
def get_scan_metadata(
    scan_id: str,
    _user: CurrentUser = Depends(require_role("submitter")),
) -> Dict[str, Any]:
    """获取扫描过程中提取的完整元数据（供提交页自动填充使用）。"""
    _cleanup_expired_scans()
    info = _scans.get(scan_id)
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_scan_not_found_detail(scan_id),
        )
    verify_resource_access(_user, info.get("user_id", ""))
    if info["status"] != "complete":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan is not complete yet. Current status: {info['status']}",
        )

    metadata = info.get("package_metadata")
    if not metadata:
        full_report = info.get("full_report", {})
        scan_report = full_report.get("scan_report", {})
        metadata = {
            "name": scan_report.get("package_name", "unknown"),
            "version": scan_report.get("version", "0.1.0"),
            "description": "",
            "license": "UNKNOWN",
        }

    return {
        "scan_id": scan_id,
        "metadata": metadata,
        "capabilities": info.get("capabilities", []),
    }


# ---------------------------------------------------------------------------
# GET /scans (管理用，列出所有扫描)
# ---------------------------------------------------------------------------


@router.get("/scans")
def list_scans(
    _user: CurrentUser = Depends(require_role("submitter")),
) -> List[Dict[str, Any]]:
    """列出扫描任务（submitter 及以上角色）。

    admin 可查看全部扫描记录；其他角色仅返回自己发起的扫描。
    """
    from schema.constants import UserRole
    _cleanup_expired_scans()
    is_admin = _user.role == UserRole.ADMIN.value
    return [
        {
            "scan_id": sid,
            "status": info["status"],
            "package_name": info.get("package_name"),
            "created_at": info["created_at"],
        }
        for sid, info in _scans.items()
        if is_admin or info.get("user_id") == _user.id
    ]
