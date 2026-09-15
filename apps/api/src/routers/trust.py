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

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    Header,
    HTTPException,
    Query,
    status,
)
from pydantic import BaseModel, Field

from src.auth import require_role, verify_resource_access
from src.database import create_session_factory, get_runtime_engine
from src.dependencies import CurrentUser
from src.models.common import require_safe_source_subdirectory
from src.repositories.producer_sqlalchemy import (
    ProducerRepository,
    ScanTaskSourceConflictError,
)
from src.services.artifacts import force_rmtree
from src.services.source_snapshots import SourceSnapshotStore
from src.settings import get_settings

router = APIRouter(tags=["trust-scan"])
# The legacy /api/v0/scans contract returns an array.  Keep that contract
# stable and expose the paginated management view under an explicit version.
v1_router = APIRouter(tags=["trust-scan-v1"])
_logger = logging.getLogger(__name__)

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
from schema.constants import HASH_SCOPE_SCANNED_SOURCE, UserRole

# ---------------------------------------------------------------------------
# 内存状态存储（scans 字典）
# ---------------------------------------------------------------------------
# key: scan_id, value: {status, package_name, created_at, finished_at, report_path, error, expires_at}
_scans: Dict[str, Dict[str, Any]] = {}
_SOURCE_SNAPSHOT_STORE = SourceSnapshotStore()

# Standalone scans remain available across browser refreshes for 30 days.
_SCAN_TTL_SECONDS = 30 * 24 * 60 * 60
# The execution deadline is independent of post-terminal retention.
_SCAN_TOTAL_TIMEOUT_SECONDS = 30 * 60
_SCAN_EXECUTION_LEASE_SECONDS = 30 * 60
_SCAN_LEASE_HEARTBEAT_SECONDS = 60.0
_SCAN_PERSIST_RETRY_ATTEMPTS = 3
_SCAN_PERSIST_RETRY_DELAY_SECONDS = 0.2
_SCAN_CALLBACK_INLINE_ATTEMPTS = 3
_SCAN_CALLBACK_RETRY_BASE_SECONDS = 1.0
_SCAN_CALLBACK_RETRY_MAX_SECONDS = 5 * 60
_SCAN_RECOVERY_INTERVAL_SECONDS = 5.0
_SCAN_MAINTENANCE_INTERVAL_SECONDS = 10 * 60.0
_SCAN_TIMEOUT_DATABASE_REFRESH_SECONDS = 2.0
_SCAN_RECOVERY_BATCH_SIZE = 50
# Repository snapshots are created only below this application-owned root.
# Keeping the prefix and parent fixed makes orphan cleanup auditable and
# prevents a broad system-temp sweep after a worker restart.
_SCAN_TEMP_ROOT = (
    Path(tempfile.gettempdir()) / "trusted-agent-hub" / "scan-repositories"
)
_SCAN_TEMP_PREFIX = "tah_repo_"
_SCAN_TEMP_ORPHAN_TTL_SECONDS = 24 * 60 * 60
_SCAN_TEMP_CLEANUP_BATCH_SIZE = 200
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
_SCAN_CALLBACK_RETRY_LOCK = threading.Lock()
_SCAN_CALLBACK_RETRY_SCHEDULED: set[str] = set()
_GITHUB_API_CONCURRENCY_GATE = threading.BoundedSemaphore(
    _GITHUB_GLOBAL_MAX_CONCURRENT_REQUESTS
)
_GITHUB_RATE_LIMIT_LOCK = threading.Lock()
_GITHUB_RATE_LIMIT_UNTIL = 0.0


class ScanTaskPersistenceError(RuntimeError):
    """A required scan-task state update could not be committed."""


class ScanSourceIdentityError(ValueError):
    """A scan task has no persisted immutable source identity."""


class ScanSourceReacquisitionError(RuntimeError):
    """A callback could not reacquire its immutable source snapshot yet."""


class ScanLLMTimeoutError(TimeoutError):
    """The bounded LLM review exceeded its dedicated deadline."""


class ScanTotalTimeoutError(TimeoutError):
    """The complete scan exceeded the task's total execution deadline."""


_SCAN_EXECUTING_STATUSES = frozenset({
    "pending",
    "downloading",
    "scanning",
    "llm_review",
    "scoring",
    "saving",
})
_SCAN_FAILURE_STATUSES = frozenset({
    "error",
    "llm_timeout",
    "total_timeout",
})

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
    next_progress: dict[str, Any] | None = None
    lease_token: str | None = None
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
        info["updated_at"] = _utc_now_iso()
        if isinstance(info.get("lease_token"), str):
            lease_token = info["lease_token"]
    if next_progress is not None:
        _persist_scan_updates(
            scan_id,
            {"llm_review": next_progress},
            lease_token=lease_token,
        )


def _heartbeat_llm_progress(scan_id: str, stop_event: threading.Event) -> None:
    """Keep last_update_at fresh while a bounded provider call is in flight."""
    while not stop_event.wait(_LLM_PROGRESS_HEARTBEAT_SECONDS):
        next_progress: dict[str, Any] | None = None
        lease_token: str | None = None
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
            info["updated_at"] = _utc_now_iso()
            if isinstance(info.get("lease_token"), str):
                lease_token = info["lease_token"]
        if next_progress is not None:
            _persist_scan_updates(
                scan_id,
                {"llm_review": next_progress},
                lease_token=lease_token,
            )


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


def _scan_temp_root_path() -> Path:
    """Return the canonical application-owned scan snapshot root."""
    return Path(_SCAN_TEMP_ROOT).resolve()


def _ensure_scan_temp_root() -> Path:
    """Create the private root used for bounded scan repository snapshots."""
    root = _scan_temp_root_path()
    root.mkdir(parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        pass
    return root


def _controlled_scan_temp_dir(
    path: object,
    *,
    require_directory: bool = False,
) -> Path | None:
    """Validate a path as one direct, non-symlink child of the scan root."""
    if not isinstance(path, (str, os.PathLike)):
        return None
    try:
        candidate = Path(path)
        if candidate.name == "" or not candidate.name.startswith(_SCAN_TEMP_PREFIX):
            return None
        if candidate.is_symlink():
            return None
        root = _scan_temp_root_path()
        resolved = candidate.resolve()
        if resolved.parent != root:
            return None
        if require_directory and not resolved.is_dir():
            return None
        return resolved
    except (OSError, RuntimeError, TypeError, ValueError):
        return None


def _active_scan_temp_dirs() -> set[Path]:
    """Collect runtime snapshot paths that must not be treated as orphans."""
    with _SCAN_PROGRESS_LOCK:
        runtime_infos = list(_scans.values())

    protected: set[Path] = set()
    for info in runtime_infos:
        candidates: list[object] = [info.get("local_source_dir")]
        report = info.get("full_report")
        if isinstance(report, dict):
            candidates.append(report.get("local_source_dir"))
        for candidate in candidates:
            resolved = _controlled_scan_temp_dir(candidate)
            if resolved is not None:
                protected.add(resolved)
    return protected


def _cleanup_orphan_scan_temp_dirs(
    *,
    now: float | None = None,
) -> int:
    """Delete a bounded set of old snapshots below the controlled root."""
    root = _scan_temp_root_path()
    if not root.is_dir() or root.is_symlink():
        return 0

    current_time = _time.time() if now is None else float(now)
    protected = _active_scan_temp_dirs()
    try:
        entries = sorted(root.iterdir(), key=lambda entry: entry.name)
    except OSError:
        return 0

    inspected = 0
    removed = 0
    for entry in entries:
        if inspected >= _SCAN_TEMP_CLEANUP_BATCH_SIZE:
            break
        if (
            not entry.name.startswith(_SCAN_TEMP_PREFIX)
            or entry.is_symlink()
            or not entry.is_dir()
        ):
            continue
        inspected += 1
        resolved = _controlled_scan_temp_dir(entry, require_directory=True)
        if resolved is None or resolved in protected:
            continue
        try:
            age_seconds = current_time - resolved.stat().st_mtime
        except OSError:
            continue
        if age_seconds < _SCAN_TEMP_ORPHAN_TTL_SECONDS:
            continue
        force_rmtree(resolved)
        if not resolved.exists():
            removed += 1
    return removed


def _cleanup_expired_scans() -> None:
    """Remove expired process-local scan state."""
    now = _time.time()
    with _SCAN_PROGRESS_LOCK:
        expired = [
            sid
            for sid, info in _scans.items()
            if (expires_at := _scan_expiry_seconds(info)) is not None
            and expires_at <= now
            and _scan_is_auto_expirable(info)
        ]
    for sid in expired:
        with _SCAN_PROGRESS_LOCK:
            info = _scans.pop(sid, None)
        if info is None:
            continue
        local_dir = (info.get("full_report") or {}).get("local_source_dir")
        if local_dir:
            controlled_dir = _controlled_scan_temp_dir(local_dir)
            if controlled_dir is not None:
                force_rmtree(controlled_dir)


def _scan_not_found_detail(scan_id: str) -> str:
    return (
        f"Scan '{scan_id}' not found or expired "
        "(scans are kept for 30 days). Please re-scan."
    )

# ---------------------------------------------------------------------------
# Pydantic 模型
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """扫描提交请求。"""
    repo_url: Optional[str] = Field(default=None, description="GitHub 仓库 HTTPS URL")
    client_request_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="客户端在发起请求前生成的幂等请求 ID",
    )


class ScanResponse(BaseModel):
    """扫描任务创建响应。"""
    scan_id: str
    status: str
    package_name: Optional[str] = None
    created_at: str
    client_request_id: Optional[str] = None
    expires_at: Optional[str] = None
    execution_deadline_at: Optional[str] = None
    lifecycle: str = "scanning"
    auto_refresh: bool = True
    delete_allowed: bool = False


class ScanListItem(BaseModel):
    """Public projection used by both scan-list API versions."""

    scan_id: str
    status: str
    package_name: Optional[str] = None
    created_at: str
    updated_at: Optional[str] = None
    finished_at: Optional[str] = None
    expires_at: Optional[str] = None
    client_request_id: Optional[str] = None
    execution_deadline_at: Optional[str] = None
    lifecycle: str = "unknown"
    auto_refresh: bool = False
    delete_allowed: bool = False
    owner_user_id: Optional[str] = None


class ScanPageResponse(BaseModel):
    """Versioned paginated scan-list response."""

    items: List[ScanListItem]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)
    has_more: bool


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
    updated_at: Optional[str] = None
    finished_at: Optional[str] = None
    expires_at: Optional[str] = None
    client_request_id: Optional[str] = None
    execution_deadline_at: Optional[str] = None
    lifecycle: str = "unknown"
    auto_refresh: bool = False
    delete_allowed: bool = False
    summary: Optional[Dict[str, Any]] = None
    trust_score: Optional[Dict[str, Any]] = None
    llm_review: Optional[LLMReviewProgressResponse] = None
    error: Optional[str] = None
    # Resolved immutable source identity, so clients can rebuild
    # subdirectory scan URLs without guessing the default branch.
    source_ref: Optional[str] = None
    source_subdirectory: Optional[str] = None


class ScanDeleteResponse(BaseModel):
    """Response returned after a scan task is explicitly deleted."""

    scan_id: str
    deleted: bool = True
    lifecycle: str


def _get_scan_task_repository() -> ProducerRepository | None:
    """Return the database-backed scan repository when persistence is configured."""
    database_url = get_settings().database_url
    if not database_url:
        return None
    engine = get_runtime_engine(database_url)
    return ProducerRepository(create_session_factory(engine))


def _coerce_scan_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
    return None


def _scan_expiry_seconds(info: dict[str, Any]) -> float | None:
    value = info.get("expires_at")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    parsed = _coerce_scan_datetime(value)
    return parsed.timestamp() if parsed is not None else None


def _scan_expiry_iso(info: dict[str, Any]) -> str | None:
    if not _scan_is_auto_expirable(info):
        return None
    value = info.get("expires_at_iso")
    if isinstance(value, str) and value:
        return value
    seconds = _scan_expiry_seconds(info)
    if seconds is None:
        return None
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


def _scan_execution_deadline(info: dict[str, Any]) -> datetime | None:
    """Return the total execution deadline derived from task creation time."""
    created_at = _coerce_scan_datetime(info.get("created_at"))
    if created_at is None or info.get("status") not in _SCAN_EXECUTING_STATUSES:
        return None
    return created_at + timedelta(seconds=_SCAN_TOTAL_TIMEOUT_SECONDS)


def _scan_execution_deadline_iso(info: dict[str, Any]) -> str | None:
    deadline = _scan_execution_deadline(info)
    return deadline.isoformat() if deadline is not None else None


def _scan_is_auto_expirable(info: dict[str, Any]) -> bool:
    """Whether ``expires_at`` is an active retention deadline for this task."""
    task_status = str(info.get("status") or "")
    if task_status in _SCAN_FAILURE_STATUSES:
        return True
    return task_status == "complete" and info.get("version_id") is None


def _scan_lifecycle(info: dict[str, Any]) -> str:
    """Map internal task fields to the user-facing policy rows."""
    task_status = str(info.get("status") or "")
    if task_status in _SCAN_EXECUTING_STATUSES:
        return "scanning"
    if task_status in _SCAN_FAILURE_STATUSES:
        return task_status
    if task_status == "complete":
        if info.get("version_id") is None:
            return "complete_unsubmitted"
        # Keep polling until the callback actually enters the review workflow.
        if info.get("callback_status") not in {"delivered", "not_required"}:
            return "callback_pending"
        return "submitted_reviewing"
    return task_status or "unknown"


def _scan_owner_id(info: dict[str, Any]) -> str:
    return str(info.get("owner_user_id") or info.get("user_id") or "")


def _scan_requester_flags(
    info: dict[str, Any],
    requester: CurrentUser,
) -> tuple[bool, bool]:
    return (
        _scan_owner_id(info) == requester.id,
        requester.role == UserRole.ADMIN.value,
    )


def _scan_delete_allowed(
    info: dict[str, Any],
    *,
    requester_is_owner: bool,
    requester_is_admin: bool,
) -> bool:
    """Allow eligible terminal-task deletion by its owner or an admin."""
    if not requester_is_owner and not requester_is_admin:
        return False
    if info.get("status") not in _SCAN_FAILURE_STATUSES | {"complete"}:
        return False
    lease_until = _coerce_scan_datetime(info.get("lease_until"))
    if lease_until is not None and lease_until > datetime.now(timezone.utc):
        return False
    if info.get("version_id") is not None and info.get("callback_status") not in {
        "delivered",
        "not_required",
    }:
        return False
    return True


def _scan_delete_allowed_for_user(
    info: dict[str, Any],
    requester: CurrentUser,
) -> bool:
    requester_is_owner, requester_is_admin = _scan_requester_flags(
        info,
        requester,
    )
    return _scan_delete_allowed(
        info,
        requester_is_owner=requester_is_owner,
        requester_is_admin=requester_is_admin,
    )


def scan_conflict_detail(info: dict[str, Any]) -> dict[str, Any]:
    """Build the structured 409 body for a duplicate-source scan request.

    The dedup lookup filters by owner, so the requester is always the task
    owner here: delete permission reduces to owner-only
    ``_scan_delete_allowed``.
    """
    scan_id = str(info.get("scan_id") or "")
    lifecycle = _scan_lifecycle(info)
    delete_allowed = _scan_delete_allowed(
        info,
        requester_is_owner=True,
        requester_is_admin=False,
    )
    if delete_allowed:
        message = (
            f"该源码已有扫描任务 {scan_id}（{lifecycle}），"
            f"请先删除任务 {scan_id} 后重试"
        )
    else:
        message = (
            f"该源码已有扫描任务 {scan_id}（{lifecycle}），不允许重复扫描。"
        )
    return {
        "message": message,
        "conflict_scan_id": scan_id,
        "lifecycle": lifecycle,
        "delete_allowed": delete_allowed,
    }


def _scan_auto_refresh(info: dict[str, Any]) -> bool:
    """Keep polling active tasks and terminal tasks with pending callbacks."""
    if info.get("status") in _SCAN_EXECUTING_STATUSES:
        return True
    if info.get("status") not in _SCAN_FAILURE_STATUSES | {"complete"}:
        return False
    return info.get("callback_status") not in {"delivered", "not_required"}


def _scan_retention_expiry(finished_at: str | None) -> str:
    finished = _coerce_scan_datetime(finished_at) or datetime.now(timezone.utc)
    return (finished + timedelta(seconds=_SCAN_TTL_SECONDS)).isoformat()


def _persistable_scan_report(value: object) -> dict[str, Any] | None:
    """Create the safe report representation stored in ``scan_tasks``."""
    if not isinstance(value, dict):
        return None
    report = deepcopy(value)
    report.pop("local_source_dir", None)
    report.pop("file_contents", None)
    report.pop("source_snapshot_sha256", None)
    scan_report = report.get("scan_report")
    if isinstance(scan_report, dict):
        scan_report = dict(scan_report)
        scan_report.pop("file_contents", None)
        report["scan_report"] = scan_report
    redacted = redact_report(report)
    return redacted if isinstance(redacted, dict) else {}


def _scan_info_from_task(task: dict[str, object]) -> dict[str, Any]:
    """Project a database row into the scanner's existing runtime shape."""
    owner_id = str(task.get("owner_user_id") or "")
    expires_at = _coerce_scan_datetime(task.get("expires_at"))
    report = task.get("report_json")
    metadata = task.get("metadata_json")
    completion_delivered_at = task.get("completion_delivered_at")
    callback_status = task.get("callback_status")
    if callback_status is None:
        callback_status = (
            "delivered"
            if completion_delivered_at is not None
            else "pending"
            if task.get("version_id") is not None
            else "not_required"
        )
    return {
        "scan_id": task.get("scan_id"),
        "status": task.get("status", "pending"),
        "package_name": task.get("package_name"),
        "created_at": task.get("created_at") or _utc_now_iso(),
        "updated_at": task.get("updated_at"),
        "lease_token": task.get("lease_token"),
        "lease_until": _coerce_scan_datetime(task.get("lease_until")),
        "attempt_count": int(task.get("attempt_count") or 0),
        "completion_delivered_at": completion_delivered_at,
        "callback_status": callback_status,
        "callback_attempt_count": int(
            task.get("callback_attempt_count") or 0
        ),
        "callback_next_attempt_at": task.get("callback_next_attempt_at"),
        "callback_last_error": task.get("callback_last_error"),
        "finished_at": task.get("finished_at"),
        "expires_at": expires_at.timestamp() if expires_at else None,
        "expires_at_iso": task.get("expires_at"),
        "client_request_id": task.get("client_request_id"),
        "repo_url": task.get("repo_url"),
        "source_ref": task.get("source_ref"),
        "commit_hash": task.get("commit_hash"),
        "source_subdirectory": task.get("source_subdirectory"),
        "version_id": task.get("version_id"),
        "full_report": deepcopy(report) if isinstance(report, dict) else None,
        "package_metadata": deepcopy(metadata) if isinstance(metadata, dict) else None,
        "capabilities": deepcopy(task.get("capabilities") or []),
        "summary": deepcopy(task.get("summary")),
        "trust_score": deepcopy(task.get("trust_score")),
        "llm_review": deepcopy(task.get("llm_review")),
        "error": task.get("error"),
        "owner_user_id": owner_id,
        "user_id": owner_id,
        "source_owner_id": owner_id,
    }


def _merge_runtime_scan_info(
    persisted: dict[str, Any], runtime: dict[str, Any] | None
) -> dict[str, Any]:
    """Merge transient execution data without discarding a newer DB update."""
    if runtime is None:
        return persisted
    merged = dict(persisted)
    for field in (
        "full_report",
        "local_source_dir",
        "acquisition_facts",
        "package_claims",
    ):
        if field in runtime and runtime[field] is not None:
            merged[field] = runtime[field]
    persisted_updated = _coerce_scan_datetime(persisted.get("updated_at"))
    runtime_updated = _coerce_scan_datetime(runtime.get("updated_at"))
    if runtime_updated is not None and (
        persisted_updated is None or runtime_updated > persisted_updated
    ):
        for field in (
            "status",
            "package_name",
            "summary",
            "trust_score",
            "llm_review",
            "error",
            "finished_at",
        ):
            if field in runtime:
                merged[field] = runtime[field]
        merged["updated_at"] = runtime.get("updated_at")
    if not merged.get("package_metadata") and runtime.get("package_metadata"):
        merged["package_metadata"] = runtime["package_metadata"]
    if not merged.get("capabilities") and runtime.get("capabilities"):
        merged["capabilities"] = runtime["capabilities"]
    return merged


def _remember_scan_info(info: dict[str, Any]) -> None:
    scan_id = str(info.get("scan_id") or "")
    if not scan_id:
        return
    with _SCAN_PROGRESS_LOCK:
        current = _scans.get(scan_id)
        _scans[scan_id] = _merge_runtime_scan_info(info, current)


def _load_scan_info(scan_id: str) -> dict[str, Any] | None:
    """Load a scan from the database, falling back to memory-only mode."""
    repository = _get_scan_task_repository()
    if repository is not None:
        task = repository.get_scan_task(scan_id)
        if task is None:
            return None
        info = _scan_info_from_task(task)
        expires_at = _scan_expiry_seconds(info)
        if (
            expires_at is not None
            and expires_at <= _time.time()
            and _scan_is_auto_expirable(info)
        ):
            return None
        with _SCAN_PROGRESS_LOCK:
            runtime = _scans.get(scan_id)
        info = _merge_runtime_scan_info(info, runtime)
        _remember_scan_info(info)
        return info

    with _SCAN_PROGRESS_LOCK:
        info = _scans.get(scan_id)
        if info is None:
            return None
        result = dict(info)
        result.setdefault("scan_id", scan_id)
        return result


def _persist_scan_updates(
    scan_id: str,
    updates: dict[str, Any],
    *,
    required: bool = False,
    lease_token: str | None = None,
) -> bool:
    """Persist scan progress, retrying and surfacing required failures."""
    repository = _get_scan_task_repository()
    if repository is None:
        return True

    database_updates: dict[str, object] = {}
    for field, value in updates.items():
        if field == "package_metadata":
            database_updates["metadata_json"] = deepcopy(value)
        elif field == "full_report":
            database_updates["report_json"] = _persistable_scan_report(value)
        elif field in {
            "status",
            "package_name",
            "version_id",
            "source_ref",
            "commit_hash",
            "source_subdirectory",
            "summary",
            "trust_score",
            "llm_review",
            "capabilities",
            "error",
            "lease_token",
            "attempt_count",
            "callback_status",
            "callback_attempt_count",
            "callback_last_error",
        }:
            database_updates[field] = deepcopy(value)
        elif field in {
            "finished_at",
            "expires_at",
            "lease_until",
            "completion_delivered_at",
            "callback_next_attempt_at",
        }:
            if value is None:
                database_updates[field] = None
            elif field == "expires_at" and isinstance(value, (int, float)):
                database_updates[field] = datetime.fromtimestamp(
                    value, timezone.utc
                )
            else:
                parsed = _coerce_scan_datetime(value)
                if parsed is not None:
                    database_updates[field] = parsed

    if not database_updates:
        return True

    last_error: Exception | None = None
    for attempt in range(1, _SCAN_PERSIST_RETRY_ATTEMPTS + 1):
        try:
            if lease_token:
                persisted = repository.update_scan_task(
                    scan_id,
                    database_updates,
                    lease_token=lease_token,
                )
            else:
                persisted = repository.update_scan_task(
                    scan_id,
                    database_updates,
                )
            if persisted:
                return True
            last_error = ScanTaskPersistenceError(
                f"scan task {scan_id} was not found or its lease expired"
            )
        except Exception as exc:  # pragma: no cover - defensive runtime logging
            last_error = exc
        if attempt < _SCAN_PERSIST_RETRY_ATTEMPTS:
            _time.sleep(_SCAN_PERSIST_RETRY_DELAY_SECONDS * attempt)

    if required:
        raise ScanTaskPersistenceError(
            f"Failed to persist required scan task update for {scan_id}"
        ) from last_error
    if last_error is not None:
        _logger.error(
            "Failed to persist non-critical scan task update %s after %s attempts: %s",
            scan_id,
            _SCAN_PERSIST_RETRY_ATTEMPTS,
            last_error,
        )
    return False


def _update_scan_state(
    scan_id: str,
    updates: dict[str, Any],
    *,
    required: bool = False,
) -> bool:
    """Update runtime state and mirror public fields to the database."""
    with _SCAN_PROGRESS_LOCK:
        info = _scans.get(scan_id)
        if info is None:
            if required:
                raise ScanTaskPersistenceError(
                    f"Runtime scan state is missing for {scan_id}"
                )
            return False
        lease_token = info.get("lease_token")
        requested_status = updates.get("status")
        current_status = str(info.get("status") or "")
        if (
            requested_status is not None
            and current_status in (_SCAN_FAILURE_STATUSES | {"complete"})
            and str(requested_status) != current_status
        ):
            if required:
                raise ScanTaskPersistenceError(
                    f"scan task {scan_id} is already terminal: {current_status}"
                )
            return False

    # Required terminal writes happen before the success callback.  If the
    # database rejects them, the runtime record is not advertised as complete.
    if required:
        _persist_scan_updates(
            scan_id,
            updates,
            required=True,
            lease_token=lease_token if isinstance(lease_token, str) else None,
        )

    persisted = True
    if not required:
        persisted = _persist_scan_updates(
            scan_id,
            updates,
            lease_token=lease_token if isinstance(lease_token, str) else None,
        )
        if not persisted and "status" in updates:
            return False
    with _SCAN_PROGRESS_LOCK:
        info = _scans.get(scan_id)
        if info is None:
            if required:
                raise ScanTaskPersistenceError(
                    f"Runtime scan state disappeared for {scan_id}"
                )
            return False
        info.update(updates)
        info["updated_at"] = _utc_now_iso()
        lease_token = info.get("lease_token")
    return persisted


def _register_scan_task(
    *,
    scan_id: str,
    owner_user_id: str,
    client_request_id: str,
    repo_url: str,
    source_ref: str | None = None,
    commit_hash: str | None = None,
    source_subdirectory: str | None = None,
    version_id: str | None = None,
    created_at: datetime | None = None,
) -> tuple[dict[str, Any], bool]:
    """Create a durable scan row and its local execution record."""
    now = created_at or datetime.now(timezone.utc)
    repository = _get_scan_task_repository()
    if repository is not None:
        task, created = repository.create_scan_task(
            scan_id=scan_id,
            owner_user_id=owner_user_id,
            client_request_id=client_request_id,
            repo_url=repo_url,
            source_ref=source_ref,
            commit_hash=commit_hash,
            source_subdirectory=source_subdirectory,
            version_id=version_id,
            status="pending",
            created_at=now,
            # Active tasks use the execution deadline, not retention expiry.
            expires_at=None,
        )
        info = _scan_info_from_task(task)
        with _SCAN_PROGRESS_LOCK:
            runtime = _scans.get(str(info["scan_id"]))
        info = _merge_runtime_scan_info(info, runtime)
        _remember_scan_info(info)
        return info, created

    now_iso = now.isoformat()
    info = {
        "scan_id": scan_id,
        "status": "pending",
        "package_name": None,
        "created_at": now_iso,
        "updated_at": now_iso,
        "lease_token": None,
        "lease_until": None,
        "attempt_count": 0,
        "completion_delivered_at": None,
        "finished_at": None,
        "full_report": None,
        "package_metadata": None,
        "capabilities": [],
        "source_ref": source_ref,
        "commit_hash": commit_hash,
        "source_subdirectory": source_subdirectory,
        "callback_status": (
            "pending" if version_id is not None else "not_required"
        ),
        "callback_attempt_count": 0,
        "callback_next_attempt_at": None,
        "callback_last_error": None,
        "summary": None,
        "trust_score": None,
        "llm_review": None,
        "error": None,
        "expires_at": None,
        "expires_at_iso": None,
        "client_request_id": client_request_id,
        "repo_url": repo_url,
        "version_id": version_id,
        "owner_user_id": owner_user_id,
        "user_id": owner_user_id,
        "source_owner_id": owner_user_id,
    }
    with _SCAN_PROGRESS_LOCK:
        _scans[scan_id] = info
    return info, True


def _claim_scan_task_for_execution(scan_id: str) -> dict[str, Any] | None:
    """Claim a scan task once, using a DB lease when persistence is enabled."""
    repository = _get_scan_task_repository()
    if repository is not None:
        task = repository.claim_scan_task(
            scan_id,
            lease_seconds=_SCAN_EXECUTION_LEASE_SECONDS,
        )
        if task is None:
            return None
        info = _scan_info_from_task(task)
        _remember_scan_info(info)
        return _load_scan_info(scan_id) or info

    now = _time.time()
    with _SCAN_PROGRESS_LOCK:
        info = _scans.get(scan_id)
        if info is None:
            return None
        lease_until = _scan_expiry_seconds(
            {"expires_at": info.get("lease_until")}
        )
        if lease_until is not None and lease_until > now:
            return None
        info["lease_token"] = f"local-{uuid.uuid4().hex}"
        info["lease_until"] = now + _SCAN_EXECUTION_LEASE_SECONDS
        info["attempt_count"] = int(info.get("attempt_count") or 0) + 1
        info["updated_at"] = _utc_now_iso()
        return dict(info)


def _enqueue_scan_task(
    background_tasks: BackgroundTasks | None,
    info: dict[str, Any],
    *,
    source: str | None = None,
    on_complete: Callable[[str, dict[str, Any] | None, str | None], None]
    | None = None,
    signals: Dict[str, Any] | None = None,
    resolved_source: dict[str, Any] | None = None,
) -> bool:
    """Claim a task and enqueue it, leaving stale claims recoverable."""
    scan_id = str(info.get("scan_id") or "")
    if not scan_id:
        return False
    claimed = _claim_scan_task_for_execution(scan_id)
    if claimed is None:
        return False
    if on_complete is None and claimed.get("version_id"):
        on_complete = _version_scan_completion_callback(
            str(claimed["version_id"])
        )
    if resolved_source is None:
        resolved_source = _resolved_source_from_scan_info(claimed)
    task_source = str(claimed.get("repo_url") or source or "")
    task_kwargs = {
        "on_complete": on_complete,
        "signals": signals,
        "resolved_source": resolved_source,
        "lease_token": (
            claimed.get("lease_token")
            if isinstance(claimed.get("lease_token"), str)
            else None
        ),
    }
    if background_tasks is not None:
        background_tasks.add_task(
            _run_scan_task,
            scan_id,
            task_source,
            **task_kwargs,
        )
    else:
        thread = threading.Thread(
            target=_run_scan_task,
            args=(scan_id, task_source),
            kwargs=task_kwargs,
            name=f"scan-task-{scan_id}",
            daemon=True,
        )
        thread.start()
    return True


def _version_scan_completion_callback(
    version_id: str,
) -> Callable[[str, dict[str, Any] | None, str | None], None]:
    """Build the producer callback used by request and recovery dispatchers."""

    def on_scan_done(
        _scan_id: str,
        report: dict[str, Any] | None,
        error: str | None,
    ) -> None:
        from src.routers.producer import _get_producer_repository
        from src.services.producer import ProducerService

        service = ProducerService(_get_producer_repository())
        if error is not None:
            service.handle_scan_error(version_id, error, scan_id=_scan_id)
        elif report is not None:
            service.handle_scan_complete(version_id, report)

    return on_scan_done


def _recovery_signals(
    repository: ProducerRepository,
    version_id: str | None,
) -> dict[str, Any]:
    if not version_id:
        return {}
    try:
        version = repository.get_version(version_id)
        if not version:
            return {}
        from src.services.signals import collect_platform_signals

        return collect_platform_signals(
            repository,
            version_id=version_id,
            package_id=str(version.get("package_id") or ""),
            submitter_id=str(version.get("submitter_id") or ""),
        )
    except Exception:  # pragma: no cover - recovery should not block startup
        _logger.exception("Failed to collect recovery signals for %s", version_id)
        return {}


def _enqueue_claimed_scan_thread(
    info: dict[str, Any],
    *,
    on_complete: Callable[[str, dict[str, Any] | None, str | None], None]
    | None,
    signals: Dict[str, Any] | None,
) -> None:
    """Start a task already claimed by the startup recovery transaction."""
    scan_id = str(info.get("scan_id") or "")
    source = str(info.get("repo_url") or "")
    kwargs = {
        "on_complete": on_complete,
        "signals": signals,
        "resolved_source": _resolved_source_from_scan_info(info),
        "lease_token": (
            info.get("lease_token")
            if isinstance(info.get("lease_token"), str)
            else None
        ),
    }
    thread = threading.Thread(
        target=_run_scan_task,
        args=(scan_id, source),
        kwargs=kwargs,
        name=f"scan-task-{scan_id}",
        daemon=True,
    )
    thread.start()


def _retry_persisted_scan_callback(scan_id: str) -> bool | None:
    """Claim and deliver one due success or failure callback."""
    repository = _get_scan_task_repository()
    if repository is None:
        return None
    task = repository.claim_scan_callback_task(
        scan_id,
        lease_seconds=_SCAN_EXECUTION_LEASE_SECONDS,
    )
    if task is None:
        return None
    info = _scan_info_from_task(task)
    _remember_scan_info(info)
    version_id = task.get("version_id")
    on_complete = (
        _version_scan_completion_callback(str(version_id))
        if version_id is not None
        else None
    )
    return _deliver_claimed_scan_callback(info, on_complete)


def _deliver_claimed_scan_callback(
    info: dict[str, Any],
    on_complete: Callable[[str, dict[str, Any] | None, str | None], None]
    | None,
) -> bool:
    """Deliver a callback for a task whose callback lease is already held."""
    scan_id = str(info.get("scan_id") or "")
    report = info.get("full_report")
    callback_error = (
        str(info.get("error"))
        if info.get("status") in _SCAN_FAILURE_STATUSES and info.get("error")
        else None
    )
    lease_token = (
        info.get("lease_token")
        if isinstance(info.get("lease_token"), str)
        else None
    )
    try:
        delivered = _deliver_scan_callback(
            scan_id,
            report if isinstance(report, dict) else None,
            callback_error,
            on_complete,
            lease_token=lease_token,
        )
    finally:
        if lease_token:
            _release_scan_lease(scan_id, lease_token)
    if not delivered:
        _schedule_scan_callback_retry(scan_id)
    return delivered


def _retry_delay_for_scan_callback(info: dict[str, Any]) -> float:
    next_attempt = _coerce_scan_datetime(info.get("callback_next_attempt_at"))
    if next_attempt is None:
        return _SCAN_CALLBACK_RETRY_BASE_SECONDS
    return max(0.0, (next_attempt - datetime.now(timezone.utc)).total_seconds())


def _schedule_scan_callback_retry(scan_id: str) -> None:
    """Keep retrying in-process while retaining a durable restart fallback."""
    repository = _get_scan_task_repository()
    if repository is None:
        return
    info = _load_scan_info(scan_id)
    if info is None or info.get("callback_status") == "delivered":
        return
    with _SCAN_CALLBACK_RETRY_LOCK:
        if scan_id in _SCAN_CALLBACK_RETRY_SCHEDULED:
            return
        _SCAN_CALLBACK_RETRY_SCHEDULED.add(scan_id)
    delay = _retry_delay_for_scan_callback(info)

    def worker() -> None:
        try:
            if delay > 0:
                _time.sleep(delay)
            delivered = _retry_persisted_scan_callback(scan_id)
        except Exception:  # pragma: no cover - durable state is the fallback
            _logger.exception("Scheduled scan callback retry failed: %s", scan_id)
            delivered = False
        finally:
            with _SCAN_CALLBACK_RETRY_LOCK:
                _SCAN_CALLBACK_RETRY_SCHEDULED.discard(scan_id)
        if delivered is False:
            _schedule_scan_callback_retry(scan_id)

    threading.Thread(
        target=worker,
        name=f"scan-callback-retry-{scan_id}",
        daemon=True,
    ).start()


def recover_persisted_scan_tasks() -> int:
    """Claim and start scans left pending by a prior process exit.

    Recovery is deliberately drained in batches. A single startup pass must
    not leave the 51st task waiting for another process restart.
    """
    repository = _get_scan_task_repository()
    if repository is None:
        return 0

    recovered = 0
    while True:
        try:
            tasks = repository.claim_recoverable_scan_tasks(
                lease_seconds=_SCAN_EXECUTION_LEASE_SECONDS,
            )
        except Exception:  # pragma: no cover - startup must remain available
            _logger.exception("Failed to recover persisted scan tasks")
            return recovered
        if not tasks:
            break

        for task in tasks:
            info = _scan_info_from_task(task)
            _remember_scan_info(info)
            version_id = (
                str(task.get("version_id"))
                if task.get("version_id") is not None
                else None
            )
            on_complete = (
                _version_scan_completion_callback(version_id)
                if version_id
                else None
            )
            if info.get("status") == "complete":
                thread = threading.Thread(
                    target=_deliver_claimed_scan_callback,
                    args=(info, on_complete),
                    name=f"scan-completion-{info.get('scan_id')}",
                    daemon=True,
                )
                thread.start()
            elif info.get("status") in _SCAN_FAILURE_STATUSES:
                thread = threading.Thread(
                    target=_deliver_claimed_scan_callback,
                    args=(info, on_complete),
                    name=f"scan-failure-callback-{info.get('scan_id')}",
                    daemon=True,
                )
                thread.start()
            else:
                _enqueue_claimed_scan_thread(
                    info,
                    on_complete=on_complete,
                    signals=_recovery_signals(repository, version_id),
                )
            recovered += 1
    return recovered


def run_persisted_scan_recovery_loop(
    stop_event: threading.Event,
    *,
    interval_seconds: float = _SCAN_RECOVERY_INTERVAL_SECONDS,
) -> None:
    """Periodically recover due scans and callbacks until shutdown."""
    wait_seconds = max(0.1, float(interval_seconds))
    while not stop_event.wait(wait_seconds):
        try:
            recover_persisted_scan_tasks()
        except Exception:  # pragma: no cover - defensive worker boundary
            _logger.exception("Periodic persisted scan recovery failed")


def run_scan_maintenance() -> None:
    """Clean expired scan state and controlled orphan snapshots."""
    _cleanup_expired_scans()
    repository = _get_scan_task_repository()
    if repository is not None:
        repository.delete_expired_scan_tasks()
    try:
        _cleanup_orphan_scan_temp_dirs()
    except Exception:  # pragma: no cover - defensive maintenance boundary
        _logger.exception("Failed to clean orphan scan temp directories")


def run_scan_maintenance_loop(
    stop_event: threading.Event,
    *,
    interval_seconds: float = _SCAN_MAINTENANCE_INTERVAL_SECONDS,
) -> None:
    """Run scan maintenance at a low frequency until shutdown."""
    wait_seconds = max(1.0, float(interval_seconds))
    while not stop_event.wait(wait_seconds):
        try:
            run_scan_maintenance()
        except Exception:
            _logger.exception("Periodic scan maintenance failed")


def _authorized_scan_info(
    scan_id: str,
    user: CurrentUser,
) -> dict[str, Any] | None:
    _cleanup_expired_scans()
    info = _load_scan_info(scan_id)
    if info is None:
        return None
    verify_resource_access(
        user,
        str(info.get("owner_user_id") or info.get("user_id") or ""),
    )
    return info


def _find_local_scan_by_request(
    owner_user_id: str,
    client_request_id: str,
) -> dict[str, Any] | None:
    with _SCAN_PROGRESS_LOCK:
        for scan_id, info in _scans.items():
            owner_id = info.get("owner_user_id") or info.get("user_id")
            if owner_id == owner_user_id and info.get("client_request_id") == client_request_id:
                result = dict(info)
                result.setdefault("scan_id", scan_id)
                return result
    return None


def _scan_response(
    info: dict[str, Any],
    *,
    requester: CurrentUser,
) -> dict[str, Any]:
    return {
        "scan_id": info.get("scan_id"),
        "status": info.get("status", "pending"),
        "package_name": info.get("package_name"),
        "created_at": info.get("created_at") or _utc_now_iso(),
        "client_request_id": info.get("client_request_id"),
        "expires_at": _scan_expiry_iso(info),
        "execution_deadline_at": _scan_execution_deadline_iso(info),
        "lifecycle": _scan_lifecycle(info),
        "auto_refresh": _scan_auto_refresh(info),
        "delete_allowed": _scan_delete_allowed_for_user(info, requester),
    }


def _scan_source_matches(
    info: dict[str, Any],
    repo_url: str,
    *,
    resolved_source: dict[str, Any] | None = None,
    expected_source: dict[str, Any] | None = None,
    expected_commit_hash: str | None = None,
) -> bool:
    """Check the complete immutable identity of a completed scan."""
    full_report = info.get("full_report")
    scanned_url = (
        full_report.get("repo_url")
        if isinstance(full_report, dict)
        else None
    ) or info.get("repo_url")
    if not isinstance(scanned_url, str) or not scanned_url:
        return False
    try:
        scanned = _parse_github_url(scanned_url)
        requested = _parse_github_url(repo_url)
    except HTTPException:
        return False
    same_repository = (
        str(scanned.get("owner", "")).casefold()
        == str(requested.get("owner", "")).casefold()
        and str(scanned.get("repo", "")).casefold()
        == str(requested.get("repo", "")).casefold()
    )
    if not same_repository:
        return False

    def normalized_subdirectory(value: object) -> str | None:
        if value is None or value == "":
            return ""
        if not isinstance(value, str):
            return None
        try:
            normalized = require_safe_source_subdirectory(value.strip())
        except ValueError:
            return None
        return "" if normalized == "." else normalized

    requested_subdir: object = (
        resolved_source.get("subdir")
        if isinstance(resolved_source, dict)
        else None
    )
    if isinstance(expected_source, dict) and "subdirectory" in expected_source:
        requested_subdir = expected_source.get("subdirectory")
    scanned_subdir: object = (
        full_report.get("source_subdirectory")
        if isinstance(full_report, dict)
        else None
    )
    if isinstance(full_report, dict) and scanned_subdir is None:
        acquisition_facts = full_report.get("acquisition_facts")
        if isinstance(acquisition_facts, dict):
            acquired_source = acquisition_facts.get("source")
            if isinstance(acquired_source, dict):
                scanned_subdir = acquired_source.get("subdirectory")
    requested_subdir_value = normalized_subdirectory(requested_subdir)
    scanned_subdir_value = normalized_subdirectory(scanned_subdir)
    if (
        requested_subdir_value is None
        or scanned_subdir_value is None
        or requested_subdir_value != scanned_subdir_value
    ):
        return False

    def valid_commit(value: object) -> str | None:
        if not isinstance(value, str):
            return None
        candidate = value.strip().lower()
        if not _is_full_commit_hash(candidate) or set(candidate) == {"0"}:
            return None
        return candidate

    scanned_commit: str | None = None
    if isinstance(full_report, dict):
        scanned_commit = valid_commit(full_report.get("commit_hash"))
        if scanned_commit is None:
            acquisition_facts = full_report.get("acquisition_facts")
            if isinstance(acquisition_facts, dict):
                acquired_source = acquisition_facts.get("source")
                if isinstance(acquired_source, dict):
                    scanned_commit = valid_commit(
                        acquired_source.get("commit_hash")
                    )
    expected_commit = valid_commit(expected_commit_hash)
    if expected_commit is None and isinstance(expected_source, dict):
        expected_commit = valid_commit(expected_source.get("commit_hash"))
    # Reuse is denied unless both sides identify the exact immutable commit.
    return (
        scanned_commit is not None
        and expected_commit is not None
        and scanned_commit == expected_commit
    )


def _canonical_scan_repo_url(url: str) -> str:
    """Normalize a GitHub repository URL to its bare repository identity."""
    from src.repositories.producer_sqlalchemy import canonical_scan_repo_url

    return canonical_scan_repo_url(url)


def _scan_dedup_identity(
    repo_url: object,
    source_subdirectory: object = None,
    source_ref: object = None,
) -> tuple[str, str] | None:
    """Return the canonical repository and normalized subdirectory identity."""
    if not isinstance(repo_url, str) or not repo_url.strip():
        return None
    raw = repo_url.strip().rstrip("/")
    subdir: str | None = (
        str(source_subdirectory).strip()
        if isinstance(source_subdirectory, str) and source_subdirectory.strip()
        else None
    )
    canonical = _canonical_scan_repo_url(raw)
    if subdir is None:
        ref: str | None = (
            source_ref.strip()
            if isinstance(source_ref, str) and source_ref.strip()
            else None
        )
        parsed = urllib.parse.urlsplit(raw)
        segments = [part for part in parsed.path.split("/") if part]
        if len(segments) > 3 and segments[2].casefold() == "tree":
            ref_parts = ref.split("/") if ref is not None else None
            if ref_parts is not None and segments[3:3 + len(ref_parts)] == ref_parts:
                # Strip exactly ``/tree/<ref>``: a slashed default branch
                # (e.g. ``release/1.0``) must not be mistaken for a
                # subdirectory.
                path_after_ref = "/".join(segments[3 + len(ref_parts):])
                subdir = path_after_ref or None
            elif ref_parts is None:
                # The segment after ``tree`` is the ref, not a subdirectory.
                path_after_ref = "/".join(segments[4:])
                subdir = path_after_ref or None
            # A known ref that does not align with the URL tree path leaves
            # the identity at repository level; the database unique
            # source-identity constraint remains the backstop.
    return canonical, (subdir or "")


def _scan_request_urls_match(first: object, second: str) -> bool:
    """Compare scan sources by repository and URL-derived subdirectory."""
    if not isinstance(first, str):
        return False
    first_identity = _scan_dedup_identity(first)
    second_identity = _scan_dedup_identity(second)
    if first_identity is None or second_identity is None:
        return False
    return first_identity == second_identity


def _scan_source_identity_match(
    info: dict[str, Any],
    repo_url: str,
    source_subdirectory: str | None,
) -> bool:
    """Check a task's complete source identity against a request."""
    task_identity = _scan_dedup_identity(
        info.get("repo_url"),
        info.get("source_subdirectory"),
        info.get("source_ref"),
    )
    request_identity = _scan_dedup_identity(repo_url, source_subdirectory)
    if task_identity is None or request_identity is None:
        return False
    return task_identity == request_identity


def _find_scan_task_by_source(
    owner_user_id: str,
    repo_url: str,
) -> dict[str, Any] | None:
    """Find a retained task for the same owner and repository target."""
    now = _time.time()

    def retained(info: dict[str, Any]) -> bool:
        expires_at = _scan_expiry_seconds(info)
        return not (
            expires_at is not None
            and expires_at <= now
            and _scan_is_auto_expirable(info)
        )

    repository = _get_scan_task_repository()
    if repository is not None:
        tasks = repository.list_scan_tasks_for_dedup(
            owner_user_id=owner_user_id
        )
        for task in tasks:
            info = _scan_info_from_task(task)
            if retained(info) and _scan_request_urls_match(
                info.get("repo_url"), repo_url
            ):
                return info
        return None

    with _SCAN_PROGRESS_LOCK:
        runtime_scans = list(_scans.values())
    for info in runtime_scans:
        owner = str(info.get("owner_user_id") or info.get("user_id") or "")
        if owner == owner_user_id and retained(info) and _scan_request_urls_match(
            info.get("repo_url"), repo_url
        ):
            return dict(info)
    return None


def _find_scan_task_by_source_identity(
    owner_user_id: str,
    repo_url: str,
    source_subdirectory: str | None = None,
) -> dict[str, Any] | None:
    """Find a retained task with the same repository and subdirectory."""
    now = _time.time()

    def retained(info: dict[str, Any]) -> bool:
        expires_at = _scan_expiry_seconds(info)
        return not (
            expires_at is not None
            and expires_at <= now
            and _scan_is_auto_expirable(info)
        )

    repository = _get_scan_task_repository()
    if repository is not None:
        tasks = repository.list_scan_tasks_for_dedup(
            owner_user_id=owner_user_id
        )
        for task in tasks:
            info = _scan_info_from_task(task)
            if retained(info) and _scan_source_identity_match(
                info,
                repo_url,
                source_subdirectory,
            ):
                return info
        return None

    with _SCAN_PROGRESS_LOCK:
        runtime_scans = list(_scans.values())
    for info in runtime_scans:
        owner = str(info.get("owner_user_id") or info.get("user_id") or "")
        if (
            owner == owner_user_id
            and retained(info)
            and _scan_source_identity_match(
                info,
                repo_url,
                source_subdirectory,
            )
        ):
            return dict(info)
    return None


def _normalized_commit_hash(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().lower()
    if not _is_full_commit_hash(candidate) or set(candidate) == {"0"}:
        return None
    return candidate


def _pin_resolved_source(parsed: dict[str, Any]) -> dict[str, Any]:
    """Attach the immutable commit resolved for a newly-created scan task."""
    source_ref = parsed.get("ref")
    if not isinstance(source_ref, str) or not source_ref.strip():
        raise ValueError("resolved source is missing its ref")
    if "commit_hash" in parsed:
        commit_hash = _normalized_commit_hash(parsed.get("commit_hash"))
        if commit_hash is None:
            raise ValueError("resolved source contains an invalid commit hash")
    else:
        commit_hash = _normalized_commit_hash(
            _fetch_repository_commit_hash(parsed)
        )
        if commit_hash is None:
            raise ValueError("GitHub did not return a valid full commit hash")
    return {
        **parsed,
        "ref": source_ref.strip(),
        "commit_hash": commit_hash,
        "subdir": parsed.get("subdir"),
    }


def _resolved_source_from_scan_info(
    info: dict[str, Any],
) -> dict[str, Any] | None:
    """Rebuild a pinned acquisition descriptor without consulting GitHub."""
    report = info.get("full_report")
    report_dict = report if isinstance(report, dict) else {}
    source_ref = info.get("source_ref") or report_dict.get("source_ref")
    commit_hash = _normalized_commit_hash(
        info.get("commit_hash") or report_dict.get("commit_hash")
    )
    source_subdirectory = info.get("source_subdirectory")
    if source_subdirectory is None:
        source_subdirectory = report_dict.get("source_subdirectory")
    if (
        not isinstance(source_ref, str)
        or not source_ref.strip()
        or commit_hash is None
    ):
        return None
    if source_subdirectory in ("", "."):
        source_subdirectory = None
    elif source_subdirectory is not None:
        if not isinstance(source_subdirectory, str):
            return None
        try:
            source_subdirectory = require_safe_source_subdirectory(
                source_subdirectory.strip()
            )
        except ValueError:
            return None
    repo_url = info.get("repo_url")
    if not isinstance(repo_url, str) or not repo_url.strip():
        return None
    try:
        parsed = _parse_github_url(repo_url)
    except HTTPException:
        return None
    return {
        **parsed,
        "tree_path": None,
        "ref": source_ref.strip(),
        "subdir": source_subdirectory,
        "commit_hash": commit_hash,
        "repository_verified": True,
        "repository_resolved": True,
    }


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
    temp_root = _ensure_scan_temp_root()
    tmp_dir = tempfile.mkdtemp(
        prefix=_SCAN_TEMP_PREFIX,
        dir=str(temp_root),
    )
    use_github_api = bool(get_settings().github_token)
    request_budget = _new_github_request_budget() if use_github_api else None
    try:
        if "commit_hash" in parsed:
            commit_hash = _normalized_commit_hash(parsed.get("commit_hash"))
            if commit_hash is None:
                raise _DeterministicAcquisitionError(
                    "扫描任务的固定 commit 身份无效"
                )
        else:
            commit_hash = _normalized_commit_hash(
                _fetch_repository_commit_hash(
                    parsed,
                    request_budget=request_budget,
                )
            )
            if commit_hash is None:
                raise _DeterministicAcquisitionError(
                    "GitHub did not return a valid full commit hash"
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


def _heartbeat_scan_lease(
    scan_id: str,
    lease_token: str,
    stop_event: threading.Event,
    lease_lost_event: threading.Event,
) -> None:
    """Keep a running scan claim alive until the worker exits."""
    while not stop_event.wait(_SCAN_LEASE_HEARTBEAT_SECONDS):
        repository = _get_scan_task_repository()
        if repository is None:
            return
        try:
            renewed = repository.renew_scan_task_lease(
                scan_id,
                lease_token=lease_token,
                lease_seconds=_SCAN_EXECUTION_LEASE_SECONDS,
            )
        except Exception:  # pragma: no cover - defensive runtime logging
            _logger.exception("Failed to renew scan lease %s", scan_id)
            continue
        if not renewed:
            lease_lost_event.set()
            _logger.error("Scan lease is no longer owned by worker: %s", scan_id)
            return


def _mark_total_scan_timeout(
    scan_id: str,
    *,
    lease_token: str | None,
) -> bool:
    """Atomically move an active task to the total-timeout terminal state."""
    finished_at = datetime.now(timezone.utc)
    error = "Scan failed: ScanTotalTimeoutError: total scan deadline exceeded"
    expires_at = finished_at + timedelta(seconds=_SCAN_TTL_SECONDS)
    repository = _get_scan_task_repository()
    if repository is not None:
        try:
            marked = bool(
                repository.mark_scan_task_timed_out(
                    scan_id,
                    status="total_timeout",
                    error=error,
                    finished_at=finished_at,
                    expires_at=expires_at,
                    lease_token=lease_token,
                )
            )
        except Exception:  # pragma: no cover - defensive watchdog boundary
            _logger.exception("Failed to persist total scan timeout for %s", scan_id)
            return False
        if not marked:
            return False

    with _SCAN_PROGRESS_LOCK:
        info = _scans.get(scan_id)
        if info is None:
            return False
        current_status = str(info.get("status") or "")
        if current_status not in _SCAN_EXECUTING_STATUSES:
            return False
        info.update(
            {
                "status": "total_timeout",
                "error": error,
                "finished_at": finished_at.isoformat(),
                "expires_at": expires_at.timestamp(),
                "expires_at_iso": expires_at.isoformat(),
                "callback_status": (
                    "pending" if info.get("version_id") is not None else "not_required"
                ),
                "completion_delivered_at": None,
                "callback_next_attempt_at": None,
                "callback_last_error": None,
                "updated_at": finished_at.isoformat(),
            }
        )
    return True


def _watch_scan_total_timeout(
    scan_id: str,
    lease_token: str | None,
    stop_event: threading.Event,
    timeout_event: threading.Event,
    timeout_callback_started: threading.Event,
    on_complete: Callable[[str, dict[str, Any] | None, str | None], None]
    | None,
) -> None:
    """Terminalize a scan even when an individual blocking step is slow."""
    with _SCAN_PROGRESS_LOCK:
        cached = _scans.get(scan_id)
        info = dict(cached) if cached is not None else None
    if info is None:
        info = _load_scan_info(scan_id)
    if info is None or info.get("status") not in _SCAN_EXECUTING_STATUSES:
        return
    deadline = _scan_execution_deadline(info)
    if deadline is None:
        return

    remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
    refresh_window = _SCAN_TIMEOUT_DATABASE_REFRESH_SECONDS
    if remaining > refresh_window and stop_event.wait(remaining - refresh_window):
        return
    if stop_event.is_set():
        return

    info = _load_scan_info(scan_id)
    if info is None or info.get("status") not in _SCAN_EXECUTING_STATUSES:
        return
    deadline = _scan_execution_deadline(info)
    if deadline is None:
        return
    remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
    if remaining > 0 and stop_event.wait(remaining):
        return
    if stop_event.is_set() or not _mark_total_scan_timeout(
        scan_id, lease_token=lease_token
    ):
        return
    timeout_event.set()
    if on_complete is not None:
        timeout_callback_started.set()
        delivered = _deliver_scan_callback(
            scan_id,
            None,
            "Scan failed: ScanTotalTimeoutError: total scan deadline exceeded",
            on_complete,
            lease_token=lease_token,
        )
        if not delivered:
            _schedule_scan_callback_retry(scan_id)


def _raise_if_scan_total_timeout(
    scan_id: str,
    timeout_event: threading.Event | None = None,
) -> None:
    """Raise at stage boundaries when the total scan deadline has elapsed."""
    if timeout_event is not None and timeout_event.is_set():
        raise ScanTotalTimeoutError("total scan deadline exceeded")
    with _SCAN_PROGRESS_LOCK:
        cached = _scans.get(scan_id)
        info = dict(cached) if cached is not None else None
    if info is None:
        info = _load_scan_info(scan_id)
    if info is None:
        raise ScanTaskPersistenceError(f"scan task {scan_id} disappeared")
    status_value = str(info.get("status") or "")
    deadline = _scan_execution_deadline(info)
    remaining = (
        (deadline - datetime.now(timezone.utc)).total_seconds()
        if deadline is not None
        else None
    )
    if status_value not in _SCAN_EXECUTING_STATUSES or (
        remaining is not None
        and remaining <= _SCAN_TIMEOUT_DATABASE_REFRESH_SECONDS
    ):
        info = _load_scan_info(scan_id)
        if info is None:
            raise ScanTaskPersistenceError(f"scan task {scan_id} disappeared")
        status_value = str(info.get("status") or "")
    if status_value == "total_timeout":
        raise ScanTotalTimeoutError("total scan deadline exceeded")
    if status_value not in _SCAN_EXECUTING_STATUSES:
        return
    deadline = _scan_execution_deadline(info)
    if deadline is not None and datetime.now(timezone.utc) >= deadline:
        raise ScanTotalTimeoutError("total scan deadline exceeded")


def _release_scan_lease(scan_id: str, lease_token: str | None) -> None:
    if not lease_token:
        return
    repository = _get_scan_task_repository()
    if repository is None:
        return
    try:
        repository.release_scan_task_lease(
            scan_id,
            lease_token=lease_token,
        )
    except Exception:  # pragma: no cover - defensive cleanup
        _logger.exception("Failed to release scan lease %s", scan_id)


def _mark_scan_callback_delivered(
    scan_id: str,
    lease_token: str | None,
) -> bool:
    """Persist callback delivery only after the callback has returned."""
    repository = _get_scan_task_repository()
    if repository is None:
        with _SCAN_PROGRESS_LOCK:
            info = _scans.get(scan_id)
            if info is not None:
                info["completion_delivered_at"] = _utc_now_iso()
                info["callback_status"] = "delivered"
                info["callback_next_attempt_at"] = None
                info["callback_last_error"] = None
        return True

    last_error: Exception | None = None
    for attempt in range(1, _SCAN_PERSIST_RETRY_ATTEMPTS + 1):
        try:
            delivered = repository.mark_scan_callback_delivered(
                scan_id,
                lease_token=lease_token,
            )
            if delivered:
                with _SCAN_PROGRESS_LOCK:
                    info = _scans.get(scan_id)
                    if info is not None:
                        info["completion_delivered_at"] = _utc_now_iso()
                        info["callback_status"] = "delivered"
                        info["callback_next_attempt_at"] = None
                        info["callback_last_error"] = None
                return True
            last_error = ScanTaskPersistenceError(
                f"scan callback lease was lost for {scan_id}"
            )
        except Exception as exc:  # pragma: no cover - retryable
            last_error = exc
        if attempt < _SCAN_PERSIST_RETRY_ATTEMPTS:
            _time.sleep(_SCAN_PERSIST_RETRY_DELAY_SECONDS * attempt)
    raise ScanTaskPersistenceError(
        f"Failed to mark scan callback delivered for {scan_id}"
    ) from last_error


def _prepare_scan_callback_attempt(
    scan_id: str,
    lease_token: str | None,
) -> int:
    with _SCAN_PROGRESS_LOCK:
        info = _scans.get(scan_id)
        if info is None:
            raise ScanTaskPersistenceError(
                f"Runtime scan state is missing for {scan_id}"
            )
        if lease_token and info.get("lease_token") != lease_token:
            info["lease_token"] = lease_token
        attempt = int(info.get("callback_attempt_count") or 0) + 1
    _update_scan_state(
        scan_id,
        {
            "callback_status": "pending",
            "callback_attempt_count": attempt,
            "callback_next_attempt_at": None,
            "callback_last_error": None,
            "completion_delivered_at": None,
        },
        required=True,
    )
    return attempt


def _record_scan_callback_failure(
    scan_id: str,
    error: str,
    *,
    lease_token: str | None,
) -> float:
    with _SCAN_PROGRESS_LOCK:
        info = _scans.get(scan_id) or {}
        attempt = max(1, int(info.get("callback_attempt_count") or 1))
    delay = min(
        _SCAN_CALLBACK_RETRY_BASE_SECONDS * (2 ** (attempt - 1)),
        _SCAN_CALLBACK_RETRY_MAX_SECONDS,
    )
    next_attempt = datetime.now(timezone.utc) + timedelta(seconds=delay)
    _update_scan_state(
        scan_id,
        {
            "callback_status": "pending",
            "callback_next_attempt_at": next_attempt,
            "callback_last_error": error,
            "completion_delivered_at": None,
        },
        required=True,
    )
    return delay


def _prepare_scan_callback_report(
    scan_id: str,
    report: dict[str, Any],
) -> tuple[dict[str, Any], str | None]:
    """Restore a complete callback report and reacquire a missing snapshot.

    The persisted report intentionally omits the process-local source path.
    When a callback runs after a restart, use the persisted commit/ref and
    subdirectory to acquire a new bounded API/ZIP snapshot. Never hand the
    artifact service an untrusted URL-only fallback.
    """
    with _SCAN_PROGRESS_LOCK:
        runtime_info = dict(_scans.get(scan_id) or {})
    if not runtime_info:
        loaded_info = _load_scan_info(scan_id)
        runtime_info = loaded_info or {}

    runtime_report = runtime_info.get("full_report")
    callback_report: dict[str, Any] = (
        deepcopy(runtime_report) if isinstance(runtime_report, dict) else {}
    )
    callback_report.update(deepcopy(report))

    local_source_dir = callback_report.get("local_source_dir")
    controlled_dir = _controlled_scan_temp_dir(
        local_source_dir,
        require_directory=True,
    )
    if controlled_dir is not None:
        callback_report["local_source_dir"] = str(controlled_dir)
        return callback_report, None
    callback_report.pop("local_source_dir", None)

    source_info = dict(runtime_info)
    source_info["full_report"] = callback_report
    for field in (
        "repo_url",
        "source_ref",
        "commit_hash",
        "source_subdirectory",
    ):
        if not source_info.get(field) and callback_report.get(field) is not None:
            source_info[field] = callback_report[field]

    resolved_source = _resolved_source_from_scan_info(source_info)
    if resolved_source is None:
        callback_report["_source_reacquisition_attempted"] = True
        callback_report["_source_reacquisition_error"] = (
            "扫描回调缺少可验证的固定源码提交身份"
        )
        return callback_report, None

    try:
        repo_root, _method, _commit_hash = _acquire_repo_source(resolved_source)
    except _DeterministicAcquisitionError as exc:
        callback_report["_source_reacquisition_attempted"] = True
        callback_report["_source_reacquisition_error"] = str(exc)
        return callback_report, None
    except Exception as exc:  # pragma: no cover - acquisition is environment-dependent
        _logger.exception("Failed to reacquire callback source for %s", scan_id)
        raise ScanSourceReacquisitionError(
            str(exc) or type(exc).__name__
        ) from exc

    if not repo_root:
        raise ScanSourceReacquisitionError(
            "无法按固定 commit 重新获取扫描源码"
        )

    controlled_dir = _controlled_scan_temp_dir(
        repo_root,
        require_directory=True,
    )
    if controlled_dir is not None:
        callback_report["local_source_dir"] = str(controlled_dir)
        with _SCAN_PROGRESS_LOCK:
            runtime_info = _scans.get(scan_id)
            if runtime_info is not None:
                runtime_info["local_source_dir"] = str(controlled_dir)
        return callback_report, str(controlled_dir)

    raise ScanSourceReacquisitionError(
        "源码重取路径不在受控扫描临时根目录内"
    )


def _deliver_scan_callback(
    scan_id: str,
    report: dict[str, Any] | None,
    error: str | None,
    on_complete: Callable[[str, dict[str, Any] | None, str | None], None]
    | None,
    *,
    lease_token: str | None,
) -> bool:
    """Deliver either terminal callback with durable retry bookkeeping."""
    if on_complete is None:
        _update_scan_state(
            scan_id,
            {
                "callback_status": "not_required",
                "callback_next_attempt_at": None,
                "callback_last_error": None,
            },
            required=True,
        )
        return True

    existing_info = _load_scan_info(scan_id)
    if existing_info is not None and (
        existing_info.get("callback_status") == "delivered"
        or existing_info.get("completion_delivered_at") is not None
    ):
        return True

    for inline_attempt in range(_SCAN_CALLBACK_INLINE_ATTEMPTS):
        reacquired_source_dir: str | None = None
        try:
            _prepare_scan_callback_attempt(scan_id, lease_token)
            if error is None and not isinstance(report, dict):
                raise ValueError(
                    "completed scan callback is missing its persisted report"
                )
            callback_report = report
            if error is None and isinstance(report, dict):
                callback_report, reacquired_source_dir = (
                    _prepare_scan_callback_report(scan_id, report)
                )
            on_complete(scan_id, callback_report, error)
            _mark_scan_callback_delivered(scan_id, lease_token)
            return True
        except Exception as exc:
            callback_error = str(exc) or type(exc).__name__
            try:
                delay = _record_scan_callback_failure(
                    scan_id,
                    callback_error,
                    lease_token=lease_token,
                )
            except Exception:
                _logger.exception(
                    "Failed to persist callback retry state for %s",
                    scan_id,
                )
                delay = _SCAN_CALLBACK_RETRY_BASE_SECONDS
            if inline_attempt + 1 < _SCAN_CALLBACK_INLINE_ATTEMPTS:
                _time.sleep(delay)
                continue
            _logger.exception(
                "Failed to deliver scan callback after %s attempts: %s",
                _SCAN_CALLBACK_INLINE_ATTEMPTS,
                scan_id,
                exc_info=exc,
            )
            return False
        finally:
            if reacquired_source_dir:
                force_rmtree(reacquired_source_dir)
    return False


def _run_scan_task(
    scan_id: str,
    source: str,
    *,
    on_complete: Callable[[str, dict[str, Any] | None, str | None], None] | None = None,
    signals: Dict[str, Any] | None = None,
    resolved_source: dict[str, Any] | None = None,
    lease_token: str | None = None,
) -> None:
    """后台执行扫描流水线：acquire → scan → score → save。

    此函数在 BackgroundTasks 中异步运行。
    signals: 提交时从数据库采集的平台信号（author_history / review_records / feedback）。
    """
    lease_stop = threading.Event()
    lease_lost = threading.Event()
    lease_thread: threading.Thread | None = None
    total_timeout_stop = threading.Event()
    total_timeout_event = threading.Event()
    total_timeout_callback_started = threading.Event()
    total_timeout_thread: threading.Thread | None = None
    if lease_token:
        lease_thread = threading.Thread(
            target=_heartbeat_scan_lease,
            args=(scan_id, lease_token, lease_stop, lease_lost),
            name=f"scan-lease-{scan_id}",
            daemon=True,
        )
        lease_thread.start()
    try:
        print(f"\n[TAH-trust] >>> _run_scan_task 开始 scan_id={scan_id}")
        print(f"[TAH-trust]     source = {source}")

        persisted_info = _load_scan_info(scan_id) or {}
        total_timeout_thread = threading.Thread(
            target=_watch_scan_total_timeout,
            args=(
                scan_id,
                lease_token,
                total_timeout_stop,
                total_timeout_event,
                total_timeout_callback_started,
                on_complete,
            ),
            name=f"scan-timeout-{scan_id}",
            daemon=True,
        )
        total_timeout_thread.start()
        _raise_if_scan_total_timeout(scan_id, total_timeout_event)
        persisted_source = _resolved_source_from_scan_info(persisted_info)
        if persisted_source is not None:
            # The database record is the source of truth even when a caller
            # supplies a stale in-memory descriptor.
            parsed = persisted_source
        elif resolved_source is not None:
            parsed = dict(resolved_source)
            commit_hash = _normalized_commit_hash(parsed.get("commit_hash"))
            if commit_hash is None:
                raise ScanSourceIdentityError(
                    "扫描任务缺少固定的 commit/ref/子目录身份，拒绝重新解析默认分支"
                )
            parsed["commit_hash"] = commit_hash
            parsed.setdefault("subdir", None)
        else:
            raise ScanSourceIdentityError(
                "扫描任务缺少固定的 commit/ref/子目录身份，拒绝重新解析默认分支"
            )
        print(f"[TAH-trust]     owner={parsed['owner']}, repo={parsed['repo']}, "
              f"default_branch={parsed['ref']}, subdir={parsed['subdir']}")

        _raise_if_scan_total_timeout(scan_id, total_timeout_event)
        _update_scan_state(scan_id, {"status": "downloading"})

        repo_root, method, commit_hash = _acquire_repo_source(parsed)
        _raise_if_scan_total_timeout(scan_id, total_timeout_event)
        if repo_root is None:
            raise RuntimeError(
                "无法解析或下载受限的仓库快照。"
                "请检查 GitHub 连接。"
            )
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

        with _SCAN_PROGRESS_LOCK:
            persisted_subdir = (_scans.get(scan_id) or {}).get(
                "source_subdirectory"
            )
        if persisted_subdir != subdir:
            try:
                _update_scan_state(
                    scan_id,
                    {"source_subdirectory": subdir},
                    required=True,
                )
            except ScanTaskPersistenceError as exc:
                # A dedup collision must terminate instead of being reclaimed.
                _logger.error(
                    "Scan %s cannot adopt subdirectory %r (identity "
                    "conflict or persistence failure); terminalizing",
                    scan_id,
                    subdir,
                )
                try:
                    _update_scan_state(
                        scan_id,
                        {
                            "status": "error",
                            "error": (
                                "扫描期间源码子目录与其他扫描任务冲突，"
                                "任务已终止。请删除冲突的任务后重试。"
                            ),
                            "finished_at": datetime.now(timezone.utc),
                            "expires_at": datetime.now(timezone.utc)
                            + timedelta(seconds=_SCAN_TTL_SECONDS),
                            "callback_status": (
                                "pending" if on_complete else "not_required"
                            ),
                        },
                        required=True,
                    )
                except Exception:
                    _logger.exception(
                        "Failed to terminalize scan %s after identity conflict",
                        scan_id,
                    )
                raise RuntimeError(
                    f"Scan {scan_id} aborted: source subdirectory conflict"
                ) from exc

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
        _update_scan_state(scan_id, {"capabilities": capabilities})
        print(
            f"[TAH-trust]     发现能力包: {len(capabilities)} 个"
        )

        # Release discovery data before the scanner builds the target snapshot.
        repo_file_contents.clear()
        del repo_file_contents
        del repo_inventory

        # Step 2: 运行扫描器
        _raise_if_scan_total_timeout(scan_id, total_timeout_event)
        _update_scan_state(scan_id, {"status": "scanning"})
        print(f"[TAH-trust]     加载扫描器, scan_dir={scan_dir}")
        RiskScanner = _load_scanner()
        scanner = RiskScanner(
            scan_dir,
            source_commit_hash=commit_hash,
            policy=_SOURCE_POLICY,
        )
        scan_report = scanner.scan()
        _raise_if_scan_total_timeout(scan_id, total_timeout_event)

        pkg_name = scan_report.get("package_name", "unknown")
        pkg_version = scan_report.get("version", "0.0.0")
        _update_scan_state(scan_id, {"package_name": pkg_name})
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
            _raise_if_scan_total_timeout(scan_id, total_timeout_event)
            _update_scan_state(scan_id, {"status": "llm_review"})
            reviewable_total = sum(
                1
                for finding in findings
                if isinstance(finding, dict)
                and finding.get("id")
                and _is_llm_reviewable_finding(finding)
            )
            progress, deadline_monotonic = _initial_llm_progress(reviewable_total)
            _update_scan_state(scan_id, {"llm_review": progress})
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
            if result_status == "timeout":
                raise ScanLLMTimeoutError("LLM review deadline exceeded")
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
            _update_scan_state(
                scan_id,
                {
                    "llm_review": {
                        "status": "completed",
                        "phase": "complete",
                        "attempt": 0,
                        "max_attempts": 3,
                        "findings_total": 0,
                        "findings_reviewed": 0,
                        "findings_pending": 0,
                    }
                },
            )
        refresh_report_summaries(scan_report)

        _raise_if_scan_total_timeout(scan_id, total_timeout_event)

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
        _raise_if_scan_total_timeout(scan_id, total_timeout_event)
        _update_scan_state(scan_id, {"status": "scoring"})
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
        _raise_if_scan_total_timeout(scan_id, total_timeout_event)
        if platform_signals:
            print(
                f"[TAH-trust]     平台信号接入: "
                f"author={platform_signals.get('author_history')}, "
                f"review={platform_signals.get('review_records', {}).get('status')}, "
                f"installs={platform_signals.get('feedback', {}).get('total_installs')}"
            )
        print(f"[TAH-trust]     评分完成: score={trust_score_result.get('score')}, level={trust_score_result.get('risk_summary', {}).get('level')}")

        # Step 4: 合并报告并保存到磁盘
        _raise_if_scan_total_timeout(scan_id, total_timeout_event)
        _update_scan_state(scan_id, {"status": "saving"})
        with _SCAN_PROGRESS_LOCK:
            scan_created_at = (_scans.get(scan_id) or {}).get(
                "created_at"
            ) or _utc_now_iso()
        full_report: Dict[str, Any] = {
            "scan_id": scan_id,
            "repo_url": repo_url,
            "package_name": pkg_name,
            "version": pkg_version,
            "source_ref": parsed["ref"],
            "source_method": method,
            "commit_hash": commit_hash,
            "created_at": scan_created_at,
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
        standalone_retention_expires_at = (
            _scan_retention_expiry(full_report["finished_at"])
            if on_complete is None
            else None
        )

        # Step 5: 更新内存状态
        _update_scan_state(
            scan_id,
            {
                "status": "complete",
                "finished_at": full_report["finished_at"],
                "expires_at": standalone_retention_expires_at,
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
                "callback_status": "pending" if on_complete else "not_required",
                "callback_next_attempt_at": None,
                "callback_last_error": None,
                "completion_delivered_at": None,
            },
            required=True,
        )

        # 临时目录保留给提交阶段打包产物，由 handle_scan_complete / 过期清理负责删除
        if lease_lost.is_set():
            _logger.error(
                "Skipping scan completion callback after lease loss: %s",
                scan_id,
            )
            return
        delivered = _deliver_scan_callback(
            scan_id,
            full_report,
            None,
            on_complete,
            lease_token=lease_token,
        )
        if not delivered:
            _logger.error(
                "Scan completion callback remains pending for %s",
                scan_id,
            )
            return
        print(f"[TAH-trust] *** 扫描流水线完成: {scan_id}, grade={trust_score_result.get('risk_summary', {}).get('grade')}")

    except Exception as exc:
        err_msg = str(exc)
        token = get_settings().github_token or ""
        if token and token in err_msg:
            err_msg = err_msg.replace(token, "***")
        if isinstance(exc, ScanLLMTimeoutError):
            terminal_status = "llm_timeout"
            public_error = "Scan failed: LLM review deadline exceeded"
        elif isinstance(exc, ScanTotalTimeoutError):
            terminal_status = "total_timeout"
            public_error = "Scan failed: total scan deadline exceeded"
        elif isinstance(exc, _DeterministicAcquisitionError):
            terminal_status = "error"
            public_error = f"仓库快照未通过安全校验：{err_msg}"
        else:
            terminal_status = "error"
            public_error = f"Scan failed: {type(exc).__name__}: {err_msg}"
        finished_at = datetime.now(timezone.utc)
        failure_expires_at = finished_at + timedelta(seconds=_SCAN_TTL_SECONDS)
        error_state_persisted = False
        if not lease_lost.is_set() and not isinstance(
            exc, ScanTaskPersistenceError
        ):
            try:
                error_state_persisted = _update_scan_state(
                    scan_id,
                    {
                        "status": terminal_status,
                        "error": public_error,
                        "finished_at": finished_at,
                        "expires_at": failure_expires_at,
                        "callback_status": (
                            "pending" if on_complete else "not_required"
                        ),
                        "callback_next_attempt_at": None,
                        "callback_last_error": None,
                        "completion_delivered_at": None,
                    },
                    required=True,
                )
            except Exception:
                _logger.exception(
                    "Failed to persist terminal scan failure for %s",
                    scan_id,
                )
        else:
            _logger.error(
                "Skipping scan error callback because task ownership or "
                "persistence is uncertain: %s",
                scan_id,
            )
        print(f"[TAH-trust] *** 扫描异常: {type(exc).__name__}: {err_msg}", flush=True)
        if "tmp_dir" in locals():
            force_rmtree(tmp_dir)
        if (
            not lease_lost.is_set()
            and error_state_persisted
            and not total_timeout_callback_started.is_set()
        ):
            delivered = _deliver_scan_callback(
                scan_id,
                None,
                public_error,
                on_complete,
                lease_token=lease_token,
            )
            if not delivered:
                _logger.error(
                    "Scan failure callback remains pending for %s",
                    scan_id,
                )
    finally:
        total_timeout_stop.set()
        if total_timeout_thread is not None:
            total_timeout_thread.join(timeout=2.0)
        lease_stop.set()
        if lease_thread is not None:
            lease_thread.join(timeout=2.0)
        _release_scan_lease(scan_id, lease_token)
        if (
            not lease_lost.is_set()
            and isinstance(lease_token, str)
        ):
            with _SCAN_PROGRESS_LOCK:
                pending_callback = (
                    _scans.get(scan_id, {}).get("callback_status")
                    == "pending"
                    and _scans.get(scan_id, {}).get("status")
                    in ({"complete"} | _SCAN_FAILURE_STATUSES)
                )
            if pending_callback:
                _schedule_scan_callback_retry(scan_id)


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


def _canonical_github_url(url: str) -> str:
    """Normalize repository casing while preserving the GitHub tree path."""
    raw = url.strip().rstrip("/")
    parsed = urllib.parse.urlsplit(raw)
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return raw
    owner = parts[0].casefold()
    repo = parts[1]
    repo_folded = repo.casefold()
    if repo_folded.endswith(".git"):
        repo = repo[:-4]
        repo_folded = repo_folded[:-4]
    normalized_path = "/".join(
        [owner, repo_folded, *parts[2:]]
    )
    return f"https://github.com/{normalized_path}"


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
    raw_url = url.strip().rstrip("/")
    try:
        parsed_url = urllib.parse.urlsplit(raw_url)
        hostname = parsed_url.hostname
        port = parsed_url.port
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid GitHub URL format: {url}",
        ) from None
    if (
        parsed_url.scheme.casefold() != "https"
        or hostname is None
        or hostname.casefold() != "github.com"
        or port is not None
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid GitHub URL format: {url}",
        )

    path = parsed_url.path.strip("/")
    parts = path.split("/") if path else []
    if len(parts) < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid GitHub URL format: {url}",
        )
    owner = parts[0]
    repo = parts[1]
    if repo.casefold().endswith(".git"):
        repo = repo[:-4]
    tree_path: str | None = None
    if len(parts) > 2:
        if len(parts) < 4 or parts[2] != "tree":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid GitHub URL format: {url}",
            )
        tree_path = "/".join(parts[3:])
    if (
        not owner
        or not repo
        or owner in {".", ".."}
        or repo in {".", ".."}
        or (len(parts) > 2 and not tree_path)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid GitHub URL format: {url}",
        )
    owner = owner.casefold()
    repo = repo.casefold()

    return {
        "base_url": f"https://github.com/{owner}/{repo}",
        "owner": owner,
        "repo": repo,
        "tree_path": tree_path,
    }


# ---------------------------------------------------------------------------
# POST /scan
# ---------------------------------------------------------------------------


@router.post("/scan", response_model=ScanResponse)
def submit_scan(
    background_tasks: BackgroundTasks,
    repo_url: Optional[str] = None,
    body: Optional[ScanRequest] = None,
    idempotency_key: Optional[str] = Header(
        default=None,
        alias="Idempotency-Key",
        description="客户端生成的幂等请求 ID",
    ),
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

    # _parse_github_url below performs the canonical scheme/host validation.
    # Do not use a case-sensitive prefix check here: HTTPS and github.com are
    # case-insensitive, while branch and subdirectory path segments are not.
    url = url.strip()
    print(f"[TAH-trust]     raw url = {url!r}")

    body_request_id = (
        body.client_request_id.strip()
        if body and body.client_request_id
        else None
    )
    header_request_id = (
        idempotency_key.strip()
        if isinstance(idempotency_key, str) and idempotency_key
        else None
    )
    if body_request_id and header_request_id and body_request_id != header_request_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="client_request_id and Idempotency-Key must match when both are provided.",
        )
    client_request_id = (body_request_id or header_request_id or "").strip()
    if not client_request_id:
        # The fallback keeps the database schema non-null.  Browser clients
        # should still generate and send their own ID before POST /scan.
        client_request_id = f"server-{uuid.uuid4().hex}"
    if len(client_request_id) > 128:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="client_request_id must be at most 128 characters.",
        )

    parsed_url = _parse_github_url(url)
    source = str(parsed_url["base_url"])
    if parsed_url.get("tree_path"):
        source = f"{source}/tree/{parsed_url['tree_path']}"

    # Resolve an existing idempotent request before making a new GitHub API
    # call.  A refresh/retry must be able to recover even if the repository's
    # default branch endpoint is temporarily unavailable.
    _cleanup_expired_scans()
    repository = _get_scan_task_repository()
    if repository is not None:
        existing_task = repository.get_scan_task_by_request(
            owner_user_id=_user.id,
            client_request_id=client_request_id,
        )
        if existing_task is not None:
            if not _scan_request_urls_match(
                existing_task.get("repo_url"),
                source,
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="The idempotency key was already used for another repository URL.",
                )
            info = _scan_info_from_task(existing_task)
            with _SCAN_PROGRESS_LOCK:
                runtime = _scans.get(str(info["scan_id"]))
            info = _merge_runtime_scan_info(info, runtime)
            _remember_scan_info(info)
            _enqueue_scan_task(
                background_tasks,
                info,
                source=source,
                resolved_source=_resolved_source_from_scan_info(info),
            )
            return _scan_response(info, requester=_user)
    else:
        existing_info = _find_local_scan_by_request(
            _user.id,
            client_request_id,
        )
        if existing_info is not None:
            if not _scan_request_urls_match(
                existing_info.get("repo_url"),
                source,
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="The idempotency key was already used for another repository URL.",
                )
            _enqueue_scan_task(
                background_tasks,
                existing_info,
                source=source,
                resolved_source=_resolved_source_from_scan_info(existing_info),
            )
            return _scan_response(existing_info, requester=_user)

    # A new request ID cannot bypass source-level duplicate prevention.
    duplicate_info = _find_scan_task_by_source(_user.id, source)
    if duplicate_info is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=scan_conflict_detail(duplicate_info),
        )

    # 解析 URL 并同步校验：仅允许 GitHub 声明的默认分支。
    # 同步端点由 FastAPI 放入线程池，避免阻塞事件循环的 GitHub API 请求。
    parsed = _resolve_default_branch_source(parsed_url)
    try:
        parsed = _pin_resolved_source(parsed)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Unable to resolve the repository to an immutable commit.",
        ) from exc
    print(f"[TAH-trust]     parsed: owner={parsed['owner']}, repo={parsed['repo']}, "
          f"default_branch={parsed['ref']}, commit={parsed['commit_hash'][:8]}, "
          f"subdir={parsed['subdir']}")

    # 创建扫描任务
    scan_id = f"scan-{uuid.uuid4().hex[:12]}"
    print(f"[TAH-trust]     scan_id = {scan_id}, 启动后台任务...")
    try:
        info, created = _register_scan_task(
            scan_id=scan_id,
            owner_user_id=_user.id,
            client_request_id=client_request_id,
            repo_url=source,
            source_ref=str(parsed["ref"]),
            commit_hash=str(parsed["commit_hash"]),
            source_subdirectory=parsed.get("subdir"),
        )
    except ScanTaskSourceConflictError as exc:
        # The unique source-identity index rejected a second retained task
        # for this repository: a concurrent duplicate, not an outage.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "该源码已有扫描任务，不允许重复扫描；"
                "请先删除原扫描任务后再重试"
            ),
        ) from exc
    except Exception as exc:
        _logger.exception("Failed to create scan task")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan task persistence is temporarily unavailable.",
        ) from exc

    if not created:
        if not _scan_request_urls_match(info.get("repo_url"), source):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The idempotency key was already used for another repository URL.",
            )
        return _scan_response(info, requester=_user)

    # Claim before enqueueing.  If the process exits between these two steps,
    # the lease expires and the next startup/retry can claim the task again.
    if not _enqueue_scan_task(
        background_tasks,
        info,
        source=source,
        resolved_source=parsed,
    ):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="扫描任务暂时无法入队，请稍后重试",
        )

    return _scan_response(info, requester=_user)


# ---------------------------------------------------------------------------
# GET /scan/{scan_id}
# ---------------------------------------------------------------------------


@router.get("/scan/{scan_id}", response_model=ScanStatusResponse)
def get_scan_status(
    scan_id: str,
    _user: CurrentUser = Depends(require_role("submitter")),
) -> Dict[str, Any]:
    """查询扫描任务的当前状态与生命周期策略。"""
    info = _authorized_scan_info(scan_id, _user)
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_scan_not_found_detail(scan_id),
        )

    return {
        "scan_id": scan_id,
        "status": info["status"],
        "package_name": info.get("package_name"),
        "created_at": info["created_at"],
        "updated_at": info.get("updated_at"),
        "finished_at": info.get("finished_at"),
        "expires_at": _scan_expiry_iso(info),
        "client_request_id": info.get("client_request_id"),
        "execution_deadline_at": _scan_execution_deadline_iso(info),
        "lifecycle": _scan_lifecycle(info),
        "auto_refresh": _scan_auto_refresh(info),
        "delete_allowed": _scan_delete_allowed_for_user(info, _user),
        "summary": info.get("summary"),
        "trust_score": info.get("trust_score"),
        "llm_review": info.get("llm_review"),
        "error": info.get("error"),
        "source_ref": info.get("source_ref"),
        "source_subdirectory": info.get("source_subdirectory"),
    }


@router.delete("/scan/{scan_id}", response_model=ScanDeleteResponse)
def delete_scan_task(
    scan_id: str,
    _user: CurrentUser = Depends(require_role("submitter")),
) -> Dict[str, Any]:
    """Delete an allowed terminal task as its owner or an administrator."""
    info = _authorized_scan_info(scan_id, _user)
    if info is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_scan_not_found_detail(scan_id),
        )
    task_owner_id = _scan_owner_id(info)
    requester_is_owner, requester_is_admin = _scan_requester_flags(info, _user)
    if not requester_is_owner and not requester_is_admin:
        # v1 reviewers can see this task, so return an explicit 403.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="只有扫描任务的所有者或管理员可以删除扫描任务",
        )
    lifecycle = _scan_lifecycle(info)
    if not _scan_delete_allowed(
        info,
        requester_is_owner=requester_is_owner,
        requester_is_admin=requester_is_admin,
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "扫描任务当前状态不允许删除；活动扫描需等待结束或超时，"
                "已提交任务需等待回调完成。"
            ),
        )

    repository = _get_scan_task_repository()
    audit_via_repository = repository is not None
    if repository is not None:
        try:
            deleted = repository.delete_scan_task(
                scan_id,
                owner_user_id=(
                    _user.id if requester_is_owner else None
                ),
                audit_operator_id=_user.id,
                audit_detail={
                    "scan_id": scan_id,
                    "owner_user_id": task_owner_id,
                    "lifecycle": lifecycle,
                    "deleted_by_admin": requester_is_admin
                    and not requester_is_owner,
                },
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        if deleted is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=_scan_not_found_detail(scan_id),
            )
    else:
        with _SCAN_PROGRESS_LOCK:
            current = _scans.get(scan_id)
            if current is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=_scan_not_found_detail(scan_id),
                )
            if not _scan_delete_allowed(
                current,
                requester_is_owner=requester_is_owner,
                requester_is_admin=requester_is_admin,
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="扫描任务状态已变化，暂时不能删除",
                )
            deleted = dict(_scans.pop(scan_id))

    # Database deletes audit atomically; only memory mode needs this write.
    if not audit_via_repository:
        try:
            from src.routers.producer import _get_producer_repository

            repo = _get_producer_repository()
            if repo is not None:
                from schema.constants import AuditAction

                repo.create_audit_log(
                    action=AuditAction.SCAN_DELETE.value,
                    target_type="scan_task",
                    target_id=scan_id,
                    operator_id=_user.id,
                    detail={
                        "scan_id": scan_id,
                        "owner_user_id": task_owner_id,
                        "lifecycle": lifecycle,
                        "deleted_by_admin": requester_is_admin
                        and not requester_is_owner,
                    },
                )
        except Exception:  # pragma: no cover - deletion already succeeded
            _logger.exception(
                "Failed to write scan-delete audit record for %s", scan_id
            )

    with _SCAN_PROGRESS_LOCK:
        runtime_info = _scans.pop(scan_id, None)
    for candidate_info in (info, runtime_info or {}):
        report = candidate_info.get("full_report")
        local_dir = (
            report.get("local_source_dir")
            if isinstance(report, dict)
            else candidate_info.get("local_source_dir")
        )
        controlled_dir = _controlled_scan_temp_dir(local_dir)
        if controlled_dir is not None:
            force_rmtree(controlled_dir)

    return {
        "scan_id": scan_id,
        "deleted": True,
        "lifecycle": lifecycle,
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
    info = _authorized_scan_info(scan_id, _user)
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_scan_not_found_detail(scan_id),
        )
    if info["status"] != "complete":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan is not complete yet. Current status: {info['status']}",
        )

    metadata = info.get("package_metadata")
    if not metadata:
        full_report = info.get("full_report")
        if not isinstance(full_report, dict):
            full_report = {}
        scan_report = full_report.get("scan_report", {})
        if not isinstance(scan_report, dict):
            scan_report = {}
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


def _scan_list_item(
    scan_id: str,
    record: dict[str, Any],
    *,
    requester: CurrentUser,
) -> dict[str, Any]:
    expires_at = _scan_expiry_iso(record)
    return {
        "scan_id": str(record.get("scan_id") or scan_id),
        "status": str(record.get("status") or "unknown"),
        "package_name": record.get("package_name"),
        "created_at": str(record.get("created_at") or _utc_now_iso()),
        "updated_at": (
            str(record["updated_at"])
            if record.get("updated_at") is not None
            else None
        ),
        "finished_at": (
            str(record["finished_at"])
            if record.get("finished_at") is not None
            else None
        ),
        "expires_at": expires_at,
        "client_request_id": record.get("client_request_id"),
        "execution_deadline_at": _scan_execution_deadline_iso(record),
        "lifecycle": _scan_lifecycle(record),
        "auto_refresh": _scan_auto_refresh(record),
        "delete_allowed": _scan_delete_allowed_for_user(record, requester),
        "owner_user_id": _scan_owner_id(record) or None,
    }


def _list_scan_page(
    _user: CurrentUser,
    *,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    """Build the versioned paginated projection with owner isolation."""
    can_view_all_scans = _user.role in (
        UserRole.ADMIN.value,
        UserRole.REVIEWER.value,
    )
    repository = _get_scan_task_repository()
    if repository is not None:
        owner_user_id = None if can_view_all_scans else _user.id
        tasks = repository.list_scan_tasks(
            owner_user_id=owner_user_id,
            limit=limit,
            offset=offset,
        )
        total = int(
            repository.count_scan_tasks(owner_user_id=owner_user_id)
        )
        items = [
            _scan_list_item(
                str(task.get("scan_id") or ""),
                task,
                requester=_user,
            )
            for task in tasks
        ]
        return {
            "items": items,
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(items) < total,
        }

    with _SCAN_PROGRESS_LOCK:
        runtime_scans = list(_scans.items())
    visible_runtime_scans = [
        (sid, info)
        for sid, info in runtime_scans
        if can_view_all_scans or info.get("user_id") == _user.id
    ]
    visible_runtime_scans.sort(
        key=lambda item: _coerce_scan_datetime(item[1].get("created_at"))
        or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    total = len(visible_runtime_scans)
    items = [
        _scan_list_item(
            sid,
            info,
            requester=_user,
        )
        for sid, info in visible_runtime_scans[offset:offset + limit]
    ]
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(items) < total,
    }


@router.get("/scans", response_model=List[ScanListItem])
def list_scans(
    _user: CurrentUser = Depends(require_role("submitter")),
) -> List[Dict[str, Any]]:
    """Legacy scan-list contract: return an array for existing clients."""
    _cleanup_expired_scans()
    can_view_all_scans = _user.role == UserRole.ADMIN.value
    repository = _get_scan_task_repository()
    if repository is not None:
        tasks = repository.list_scan_tasks(
            owner_user_id=None if can_view_all_scans else _user.id,
        )
        return [
            _scan_list_item(
                str(task.get("scan_id") or ""),
                task,
                requester=_user,
            )
            for task in tasks
        ]

    with _SCAN_PROGRESS_LOCK:
        runtime_scans = list(_scans.items())
    return [
        _scan_list_item(
            sid,
            info,
            requester=_user,
        )
        for sid, info in runtime_scans
        if can_view_all_scans or info.get("user_id") == _user.id
    ]


@v1_router.get("/scans", response_model=ScanPageResponse)
def list_scans_v1(
    limit: int = Query(
        default=50,
        ge=1,
        le=200,
        description="Number of scan tasks per page",
    ),
    offset: int = Query(
        default=0,
        ge=0,
        description="Number of scan tasks to skip",
    ),
    _user: CurrentUser = Depends(require_role("submitter")),
) -> Dict[str, Any]:
    """List scan tasks with stable pagination for the management UI."""
    _cleanup_expired_scans()
    return _list_scan_page(_user, limit=limit, offset=offset)
