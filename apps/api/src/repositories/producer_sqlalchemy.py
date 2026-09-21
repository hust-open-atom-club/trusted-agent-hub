"""供给侧数据库操作仓库。

与消费侧 SqlAlchemyPackageRepository 并行，
专门负责供给侧表（review_records / scan_reports / audit_logs / users）
以及可恢复扫描任务（scan_tasks）的持久化，
以及供给侧对 packages / package_versions 的写操作。
"""

from __future__ import annotations

from collections.abc import Callable, Collection, Mapping
from datetime import datetime, timedelta, timezone
import hashlib
from typing import NoReturn
from uuid import uuid4

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.llm_progress import finalize_running_llm_progress
from src.repositories.orm import (
    FeedbackRecordRow,
    PackageRow,
    PackageVersionRow,
    TrustLevelRow,
)
from src.repositories.orm_producer import (
    AuditLogRow,
    ReviewRecordRow,
    ScanReportRow,
    ScanTaskRow,
    UserRow,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso_date(value: str) -> datetime:
    """将 ISO 格式日期字符串转为带时区的 datetime。"""
    s = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _normalize_iso_boundary(value: str) -> str:
    """Normalize a client-provided ISO boundary to the stored UTC format.

    Submitted timestamps are currently stored inside JSON using
    ``datetime.isoformat()`` (for example, ``+00:00``).  Normalizing query
    boundaries avoids a lexicographic mismatch with equivalent ``.000Z``
    values sent by browsers.
    """
    try:
        return _parse_iso_date(value).astimezone(timezone.utc).isoformat()
    except ValueError:
        # Preserve the previous comparison behavior for malformed values.
        return value


def _serialize_dt(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def _serialize_optional_dt(value: datetime | None) -> str | None:
    return _serialize_dt(value) if value is not None else None


def _scan_task_data(row: ScanTaskRow) -> dict[str, object]:
    """Return the complete internal representation of a persisted scan."""
    return {
        "scan_id": row.id,
        "owner_user_id": row.owner_user_id,
        "client_request_id": row.client_request_id,
        "repo_url": row.repo_url,
        "dedup_repo_url": row.dedup_repo_url,
        "source_ref": row.source_ref,
        "commit_hash": row.commit_hash,
        "source_subdirectory": row.source_subdirectory,
        "version_id": row.version_id,
        "status": row.status,
        "package_name": row.package_name,
        "created_at": _serialize_dt(row.created_at),
        "updated_at": _serialize_dt(row.updated_at),
        "lease_token": row.lease_token,
        "lease_until": _serialize_optional_dt(row.lease_until),
        "attempt_count": row.attempt_count,
        "completion_delivered_at": _serialize_optional_dt(
            row.completion_delivered_at
        ),
        "resource_consumed": row.resource_consumed,
        "callback_status": row.callback_status,
        "callback_attempt_count": row.callback_attempt_count,
        "callback_next_attempt_at": _serialize_optional_dt(
            row.callback_next_attempt_at
        ),
        "callback_last_error": row.callback_last_error,
        "finished_at": _serialize_optional_dt(row.finished_at),
        "expires_at": _serialize_optional_dt(row.expires_at),
        "summary": row.summary,
        "trust_score": row.trust_score,
        "llm_review": row.llm_review,
        "metadata_json": row.metadata_json,
        "capabilities": row.capabilities,
        "report_json": row.report_json,
        "error": row.error,
    }


_SCAN_TASK_UPDATE_FIELDS = frozenset(
    {
        "status",
        "package_name",
        "version_id",
        "source_ref",
        "commit_hash",
        "source_subdirectory",
        "finished_at",
        "expires_at",
        "summary",
        "trust_score",
        "llm_review",
        "metadata_json",
        "capabilities",
        "report_json",
        "error",
        "lease_token",
        "lease_until",
        "attempt_count",
        "completion_delivered_at",
        "resource_consumed",
        "callback_status",
        "callback_attempt_count",
        "callback_next_attempt_at",
        "callback_last_error",
    }
)

_SCAN_TASK_RETENTION = timedelta(days=30)
_SCAN_TASK_EXECUTABLE_STATUSES = frozenset(
    {
        "pending",
        "downloading",
        "scanning",
        "llm_review",
        "scoring",
        "saving",
    }
)
_SCAN_TASK_FAILURE_STATUSES = frozenset({
    "error",
    "llm_timeout",
    "total_timeout",
})


class ScanTaskSourceConflictError(Exception):
    """A retained scan task already exists for the same source identity."""


# Only these constraints map an integrity error to a scan conflict.
_IDEMPOTENCY_CHECK_CONSTRAINT = "uq_scan_tasks_owner_request"
_SOURCE_IDENTITY_CONSTRAINT = "uq_scan_tasks_source_identity"


def _scan_integrity_constraint(exc: IntegrityError) -> str | None:
    """Extract the violated unique-constraint name from an IntegrityError."""
    if exc.orig is not None and hasattr(exc.orig, "constraint_name"):
        name = getattr(exc.orig, "constraint_name", None)
        if isinstance(name, str):
            return name
    message = str(exc.orig or exc)
    for name in (_SOURCE_IDENTITY_CONSTRAINT, _IDEMPOTENCY_CHECK_CONSTRAINT):
        if name in message:
            return name
    return None


def _raise_scan_source_conflict(dedup_url: str) -> NoReturn:
    """Raise when a retained task already owns this source identity."""
    raise ScanTaskSourceConflictError(
        f"A retained scan task already exists for {dedup_url}"
    )


def canonical_scan_repo_url(url: str) -> str:
    """Normalize a GitHub URL to the repository key used by the migration."""
    raw = url.strip()
    lower = raw.casefold()
    if not lower.startswith("https://github.com/"):
        return raw.rstrip("/")
    path = raw[len("https://github.com/"):].strip("/")
    parts = [part for part in path.split("/") if part]
    if len(parts) < 2:
        return raw.rstrip("/")
    owner = parts[0].casefold()
    repo = parts[1].casefold()
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"https://github.com/{owner}/{repo}"


def _scan_task_dedup_url(repo_url: str) -> str:
    """Return the repository component of the source-identity key."""
    return canonical_scan_repo_url(repo_url)


class ProducerRepository:
    """供给侧所有数据库写操作 + 查询。"""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self.session_factory = session_factory

    # ── 包操作 ────────────────────────────────────────────

    def create_package(
        self,
        *,
        name: str,
        type: str,
        description: str,
        submitter_id: str | None = None,
        license: str | None = None,
        keywords: list[str] | None = None,
        category: str | None = None,
        homepage: str | None = None,
        icon_url: str | None = None,
        author: dict[str, object] | None = None,
        permissions: dict[str, object] | None = None,
        use_cases: list[dict[str, object]] | None = None,
        type_config: dict[str, object] | None = None,
        installation: dict[str, object] | None = None,
        dependencies: dict[str, object] | None = None,
        source: dict[str, object] | None = None,
        compatibility: list[str] | None = None,
        field_source: dict[str, str] | None = None,
    ) -> dict[str, object]:
        """创建能力包，返回包基本信息。"""
        pkg_id = f"pkg-{uuid4().hex}"
        now = _utc_now()
        data: dict[str, object] = {
            "id": pkg_id,
            "name": name,
            "description": description,
            "type": type,
            "submitter_id": submitter_id,
            "license": license,
            "keywords": keywords or [],
            "category": category,
            "homepage": homepage,
            "icon_url": icon_url,
            "author": author,
            "permissions": permissions,
            "use_cases": use_cases,
            "type_config": type_config,
            "installation": installation,
            "dependencies": dependencies,
            "source": source,
            "field_source": field_source,
            "compatibility": compatibility or [],
            "latest_version": "0.0.0",
            "status": "draft",
            "trust_score": None,
            "risk_level": None,
            "install_count": 0,
            "avg_rating": None,
            "created_at": _serialize_dt(now),
            "updated_at": _serialize_dt(now),
        }
        with self.session_factory() as session:
            session.add(
                PackageRow(
                    id=pkg_id,
                    name=name,
                    status="draft",
                    latest_version="0.0.0",
                    data=data,
                )
            )
            session.commit()
        return data

    def package_name_exists(self, name: str) -> bool:
        """检查包名是否已存在。"""
        with self.session_factory() as session:
            return session.scalar(
                select(func.count())
                .select_from(PackageRow)
                .where(PackageRow.name == name)
            ) > 0

    def get_package(self, package_id: str) -> dict[str, object] | None:
        with self.session_factory() as session:
            row = session.get(PackageRow, package_id)
            if row is None:
                return None
            versions_count = session.scalar(
                select(func.count())
                .select_from(PackageVersionRow)
                .where(PackageVersionRow.package_id == package_id)
            )
            data = dict(row.data)
            data["versions_count"] = versions_count or 0
            return data

    def delete_package(self, package_id: str) -> bool:
        """删除包（仅无版本的包可删除，防止误删有数据的包）。"""
        with self.session_factory() as session:
            pkg = session.get(PackageRow, package_id)
            if pkg is None:
                return False
            has_versions = session.scalar(
                select(func.count())
                .select_from(PackageVersionRow)
                .where(PackageVersionRow.package_id == package_id)
            )
            if has_versions:
                return False
            session.delete(pkg)
            session.commit()
            return True

    def delete_version(self, version_id: str) -> bool:
        """删除指定版本，并给关联扫描任务回填保留期（不物理删，保留审计）。"""
        with self.session_factory() as session:
            ver = session.get(PackageVersionRow, version_id)
            if ver is None:
                return False
            current_time = _utc_now()
            # scan_tasks.version_id drops to NULL via FK ondelete=SET NULL.
            # Backfill retention now so the detached rows do not hold the
            # source-identity dedup key forever.
            for scan_row in session.scalars(
                select(ScanTaskRow).where(
                    ScanTaskRow.version_id == version_id,
                    ScanTaskRow.expires_at.is_(None),
                )
            ):
                finished = scan_row.finished_at or current_time
                scan_row.expires_at = finished + _SCAN_TASK_RETENTION
                scan_row.updated_at = current_time
            session.delete(ver)
            session.commit()
            return True

    def list_all_packages(
        self,
        *,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, object]]:
        """列出所有能力包（不限状态），含版本数和最新版本。"""
        with self.session_factory() as session:
            rows = session.execute(
                select(
                    PackageRow.id,
                    PackageRow.name,
                    PackageRow.status,
                    PackageRow.latest_version,
                    PackageRow.data,
                )
                .order_by(PackageRow.data["created_at"].as_string().desc().nullslast())
                .offset(offset)
                .limit(limit)
            ).all()
        packages: list[dict[str, object]] = []
        for row in rows:
            pkg_data = row.data or {}
            packages.append({
                "package_id": row.id,
                "package_name": row.name,
                "package_type": pkg_data.get("type"),
                "description": pkg_data.get("description"),
                "status": row.status,
                "latest_version": row.latest_version,
                "submitter_id": pkg_data.get("submitter_id"),
                "created_at": pkg_data.get("created_at"),
                "updated_at": pkg_data.get("updated_at"),
            })
        return packages

    def list_package_versions(
        self, package_id: str
    ) -> list[dict[str, object]]:
        with self.session_factory() as session:
            rows = session.scalars(
                select(PackageVersionRow)
                .where(PackageVersionRow.package_id == package_id)
                .order_by(PackageVersionRow.version)
            ).all()
            return [_version_brief(row) for row in rows]

    # ── 版本操作 ──────────────────────────────────────────

    def create_version(
        self,
        *,
        package_id: str,
        version: str,
        submitter_id: str | None = None,
        repo_url: str | None = None,
        description: str | None = None,
        author: dict[str, object] | None = None,
        license: str | None = None,
        source: dict[str, object] | None = None,
        integrity: dict[str, object] | None = None,
        permissions: dict[str, object] | None = None,
        use_cases: list[dict[str, object]] | None = None,
        type_config: dict[str, object] | None = None,
        compatibility: list[str] | None = None,
        installation: dict[str, object] | None = None,
        dependencies: dict[str, object] | None = None,
        field_source: dict[str, str] | None = None,
    ) -> dict[str, object]:
        """创建新版本，返回版本信息。"""
        version_id = f"ver-{uuid4().hex}"
        now = _utc_now()
        data: dict[str, object] = {
            "id": version_id,
            "package_id": package_id,
            "version": version,
            "status": "draft",
            "submitter_id": submitter_id,
            "source": source or {"type": "git", "repository_url": repo_url or "", "ref": "", "commit_hash": ""},
            "integrity": integrity,
            "permissions": permissions or {},
            "use_cases": use_cases,
            "type_config": type_config,
            "compatibility": compatibility or [],
            "description": description,
            "author": author,
            "license": license,
            "installation": installation,
            "dependencies": dependencies,
            "field_source": field_source,
            "submitted_at": None,
            "trust_score": None,
            "created_at": _serialize_dt(now),
        }
        with self.session_factory() as session:
            session.add(
                PackageVersionRow(
                    id=version_id,
                    package_id=package_id,
                    version=version,
                    status="draft",
                    data=data,
                )
            )
            session.commit()
        return data

    def get_version(self, version_id: str) -> dict[str, object] | None:
        with self.session_factory() as session:
            row = session.get(PackageVersionRow, version_id)
            if row is None:
                return None
            data = dict(row.data) if row.data else {}
            data["manual_grade"] = row.manual_grade if row.manual_grade and row.manual_grade != "F" else None
            data["manual_grade_by"] = row.manual_grade_by
            data["manual_grade_at"] = _serialize_dt(row.manual_grade_at) if row.manual_grade_at else None
            data["manual_grade_reason"] = row.manual_grade_reason
            if row.manual_grade_by:
                user_row = session.get(UserRow, row.manual_grade_by)
                if user_row:
                    data["manual_grade_by_name"] = user_row.display_name or user_row.email
            return data

    def get_previous_version(
        self, version_id: str
    ) -> dict[str, object] | None:
        with self.session_factory() as session:
            current = session.get(PackageVersionRow, version_id)
            if current is None:
                return None
            prev = session.scalars(
                select(PackageVersionRow)
                .where(
                    PackageVersionRow.package_id == current.package_id,
                    PackageVersionRow.id != version_id,
                )
                .order_by(
                    PackageVersionRow.data["created_at"]
                    .as_string()
                    .desc()
                )
                .limit(1)
            ).first()
            if prev is None:
                return None
            return dict(prev.data)

    def update_version_status(
        self, version_id: str, new_status: str
    ) -> None:
        with self.session_factory() as session:
            row = session.get(PackageVersionRow, version_id)
            if row is None:
                return
            row.status = new_status
            # 同步更新 data JSON 中的 status
            data = dict(row.data) if row.data else {}
            data["status"] = new_status
            row.data = data
            session.commit()

    def transition_version_status_if_current(
        self,
        version_id: str,
        expected_statuses: tuple[str, ...],
        new_status: str,
    ) -> bool:
        """Transition a version only if its status is still one of the expected values."""
        if not expected_statuses:
            return False
        with self.session_factory() as session:
            row = session.get(PackageVersionRow, version_id)
            if row is None:
                return False
            data = dict(row.data) if row.data else {}
            data["status"] = new_status
            result = session.execute(
                update(PackageVersionRow)
                .where(
                    PackageVersionRow.id == version_id,
                    PackageVersionRow.status.in_(expected_statuses),
                )
                .values(status=new_status, data=data)
            )
            if result.rowcount != 1:
                session.rollback()
                return False
            session.commit()
            return True

    def update_version_data(
        self, version_id: str, updates: dict[str, object]
    ) -> None:
        with self.session_factory() as session:
            row = session.get(PackageVersionRow, version_id)
            if row is None:
                return
            data = dict(row.data) if row.data else {}
            data.update(updates)
            row.data = data
            session.commit()

    def set_manual_grade(
        self,
        *,
        version_id: str,
        grade: str | None,
        operator_id: str | None = None,
        reason: str | None = None,
    ) -> None:
        with self.session_factory() as session:
            row = session.get(PackageVersionRow, version_id)
            if row is None:
                return
            row.manual_grade = grade
            row.manual_grade_by = operator_id if grade else None
            row.manual_grade_at = _utc_now() if grade else None
            row.manual_grade_reason = reason if grade else None
            session.commit()

    def clear_manual_grade(self, version_id: str) -> None:
        self.set_manual_grade(version_id=version_id, grade=None)

    def update_package_status(
        self, package_id: str, new_status: str, latest_version: str | None = None
    ) -> None:
        """更新包状态，同步数据 JSON。"""
        with self.session_factory() as session:
            row = session.get(PackageRow, package_id)
            if row is None:
                return
            row.status = new_status
            if latest_version:
                row.latest_version = latest_version
            data = dict(row.data) if row.data else {}
            data["status"] = new_status
            if latest_version:
                data["latest_version"] = latest_version
            row.data = data
            session.commit()

    def update_package_data(
        self, package_id: str, updates: dict[str, object]
    ) -> None:
        with self.session_factory() as session:
            row = session.get(PackageRow, package_id)
            if row is None:
                return
            data = dict(row.data) if row.data else {}
            data.update(updates)
            row.data = data
            session.commit()

    def upsert_trust_level(
        self,
        *,
        version_id: str,
        level: str,
        recommendation: str,
        model_version: str | None = None,
        model_fingerprint: str | None = None,
    ) -> None:
        with self.session_factory() as session:
            existing = session.get(TrustLevelRow, version_id)
            if existing:
                existing.level = level
                existing.install_recommendation = recommendation
                if model_version is not None:
                    existing.model_version = model_version
                if model_fingerprint is not None:
                    existing.model_fingerprint = model_fingerprint
            else:
                version = session.get(PackageVersionRow, version_id)
                trust_score = (
                    version.data.get("trust_score")
                    if version is not None and isinstance(version.data, dict)
                    else None
                )
                if model_version is None and isinstance(trust_score, dict):
                    model_version = trust_score.get("model_version")
                if model_fingerprint is None and isinstance(trust_score, dict):
                    model_fingerprint = trust_score.get("model_fingerprint")
                if model_version is None and model_fingerprint:
                    model_version = f"auto-{model_fingerprint[:12]}"
                # The score refresh immediately following publication replaces
                # this compatibility fallback when a legacy version has no
                # model identity yet.  The fingerprint, never this fallback,
                # is used by backfill decisions.
                model_version = model_version or "legacy-unknown"
                session.add(TrustLevelRow(
                    version_id=version_id,
                    level=level,
                    install_recommendation=recommendation,
                    top_risks=[],
                    model_version=model_version,
                    model_fingerprint=model_fingerprint,
                ))
            session.commit()

    def get_feedback_level_counts(
        self,
        package_id: str,
    ) -> dict[str, int]:
        """聚合某包的 level 反馈计数（positive/neutral/negative）。"""
        with self.session_factory() as session:
            rows = session.execute(
                select(FeedbackRecordRow.level, func.count())
                .where(FeedbackRecordRow.package_id == package_id)
                .group_by(FeedbackRecordRow.level)
            ).all()
        counts = {"positive": 0, "neutral": 0, "negative": 0}
        for level, count in rows:
            counts[str(level)] = int(count)
        return counts

    # ── 扫描报告 ──────────────────────────────────────────

    def save_scan_report(
        self,
        *,
        version_id: str,
        scan_json: dict[str, object],
        report_path: str | None = None,
    ) -> None:
        with self.session_factory() as session:
            existing = session.get(ScanReportRow, version_id)
            if existing is not None:
                existing.scan_json = scan_json
                existing.report_path = report_path
                existing.scanned_at = _utc_now()
            else:
                session.add(
                    ScanReportRow(
                        version_id=version_id,
                        scan_json=scan_json,
                        report_path=report_path,
                        scanned_at=_utc_now(),
                    )
                )
            session.commit()

    def get_scan_report(
        self, version_id: str
    ) -> dict[str, object] | None:
        with self.session_factory() as session:
            row = session.get(ScanReportRow, version_id)
            if row is None:
                return None
            return {
                "scan_json": row.scan_json,
                "report_path": row.report_path,
                "scanned_at": _serialize_dt(row.scanned_at),
            }

    # ── 持久化扫描任务 ────────────────────────────────────

    def create_scan_task(
        self,
        *,
        scan_id: str,
        owner_user_id: str,
        client_request_id: str,
        repo_url: str,
        source_ref: str | None = None,
        commit_hash: str | None = None,
        source_subdirectory: str | None = None,
        version_id: str | None = None,
        status: str = "pending",
        created_at: datetime | None = None,
        expires_at: datetime | None = None,
        callback_status: str | None = None,
    ) -> tuple[dict[str, object], bool]:
        """Create a scan task, returning ``(task, created)``.

        The unique owner/request constraint makes retries safe.  A losing
        concurrent insert is resolved by reading the row created by the
        winning request and returning it as an idempotent response.
        """
        now = created_at or _utc_now()
        # Active tasks use the execution deadline; ``expires_at`` starts only
        # after a terminal outcome.
        if status in _SCAN_TASK_EXECUTABLE_STATUSES:
            expiry = None
        elif status in _SCAN_TASK_FAILURE_STATUSES:
            expiry = expires_at or now + _SCAN_TASK_RETENTION
        elif status == "complete":
            expiry = None if version_id is not None else expires_at or now + _SCAN_TASK_RETENTION
        else:
            expiry = expires_at
        callback_state = callback_status or (
            "pending" if version_id is not None else "not_required"
        )
        dedup_url = _scan_task_dedup_url(repo_url)
        with self.session_factory() as session:
            existing = session.scalar(
                select(ScanTaskRow).where(
                    ScanTaskRow.owner_user_id == owner_user_id,
                    ScanTaskRow.client_request_id == client_request_id,
                )
            )
            if existing is not None:
                return _scan_task_data(existing), False

            row = ScanTaskRow(
                id=scan_id,
                owner_user_id=owner_user_id,
                client_request_id=client_request_id,
                repo_url=repo_url,
                dedup_repo_url=dedup_url,
                source_ref=source_ref,
                commit_hash=commit_hash,
                source_subdirectory=source_subdirectory,
                version_id=version_id,
                status=status,
                created_at=now,
                updated_at=now,
                expires_at=expiry,
                callback_status=callback_state,
            )
            session.add(row)
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                existing = session.scalar(
                    select(ScanTaskRow).where(
                        ScanTaskRow.owner_user_id == owner_user_id,
                        ScanTaskRow.client_request_id == client_request_id,
                    )
                )
                if existing is not None:
                    return _scan_task_data(existing), False
                # Other integrity failures must remain persistence errors.
                if _scan_integrity_constraint(exc) == _SOURCE_IDENTITY_CONSTRAINT:
                    _raise_scan_source_conflict(dedup_url)
                raise
            return _scan_task_data(row), True

    def create_version_scan_task(
        self,
        *,
        version_id: str,
        scan_id: str,
        owner_user_id: str,
        client_request_id: str,
        repo_url: str,
        source_ref: str | None = None,
        commit_hash: str | None = None,
        source_subdirectory: str | None = None,
        expected_statuses: Collection[str],
        operator_id: str,
        expires_at: datetime | None = None,
    ) -> dict[str, object]:
        """Atomically move a version to scanning and create its scan task.

        The version row, scan task row, and submit audit entry share one
        transaction.  A missing ``scan_tasks`` table or any constraint error
        therefore cannot leave the version in a non-retryable state.
        """
        now = _utc_now()
        # Submitted tasks remain available to the review workflow and use the
        # execution deadline while active.
        expiry = None
        dedup_url = _scan_task_dedup_url(repo_url)
        with self.session_factory() as session:
            version_row = session.get(
                PackageVersionRow,
                version_id,
                with_for_update=True,
            )
            if version_row is None:
                raise LookupError(f"Version {version_id} does not exist")
            if version_row.status not in set(expected_statuses):
                raise ValueError(
                    f"Version {version_id} changed state while being submitted"
                )
            if session.get(ScanTaskRow, scan_id) is not None:
                raise ValueError(f"Scan task {scan_id} already exists")

            version_row.status = "scanning"
            version_data = dict(version_row.data) if version_row.data else {}
            version_data["status"] = "scanning"
            version_row.data = version_data

            scan_row = ScanTaskRow(
                id=scan_id,
                owner_user_id=owner_user_id,
                client_request_id=client_request_id,
                repo_url=repo_url,
                dedup_repo_url=dedup_url,
                source_ref=source_ref,
                commit_hash=commit_hash,
                source_subdirectory=source_subdirectory,
                version_id=version_id,
                status="pending",
                created_at=now,
                updated_at=now,
                expires_at=expiry,
                callback_status="pending",
            )
            session.add(scan_row)
            try:
                session.add(
                    AuditLogRow(
                        id=f"audit-{uuid4().hex}",
                        action="submit",
                        target_type="version",
                        target_id=version_id,
                        operator_id=operator_id,
                        detail=None,
                        timestamp=now,
                    )
                )
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                if _scan_integrity_constraint(exc) == _SOURCE_IDENTITY_CONSTRAINT:
                    _raise_scan_source_conflict(dedup_url)
                raise
            return _scan_task_data(scan_row)

    def attach_scan_task_to_version(
        self,
        *,
        scan_id: str,
        version_id: str,
        owner_user_id: str,
        expected_statuses: Collection[str],
        operator_id: str,
    ) -> dict[str, object]:
        """Atomically attach a completed standalone scan to a version.

        Reusing a scan is a state transition of both records.  Keeping the
        association, version status, and submit audit in one transaction
        ensures a callback cannot run while the task is still unassociated.
        """
        now = _utc_now()
        with self.session_factory() as session:
            version_row = session.get(
                PackageVersionRow,
                version_id,
                with_for_update=True,
            )
            if version_row is None:
                raise LookupError(f"Version {version_id} does not exist")
            if version_row.status not in set(expected_statuses):
                raise ValueError(
                    f"Version {version_id} changed state while being submitted"
                )

            scan_row = session.get(ScanTaskRow, scan_id, with_for_update=True)
            if scan_row is None:
                raise LookupError(f"Scan task {scan_id} does not exist")
            if scan_row.owner_user_id != owner_user_id:
                raise ValueError("Scan task does not belong to the submitting user")
            if scan_row.status != "complete" or scan_row.report_json is None:
                raise ValueError("Only a completed scan task can be reused")
            if scan_row.resource_consumed:
                raise ValueError("Scan task result has already been consumed")
            if scan_row.version_id not in (None, version_id):
                raise ValueError("Scan task is already attached to another version")

            version_row.status = "scanning"
            version_data = dict(version_row.data) if version_row.data else {}
            version_data["status"] = "scanning"
            version_row.data = version_data

            scan_row.version_id = version_id
            scan_row.callback_status = "pending"
            scan_row.callback_attempt_count = 0
            scan_row.callback_next_attempt_at = None
            scan_row.callback_last_error = None
            scan_row.completion_delivered_at = None
            # The review workflow owns retention after attachment.
            scan_row.expires_at = None
            scan_row.updated_at = now
            session.add(
                AuditLogRow(
                    id=f"audit-{uuid4().hex}",
                    action="submit",
                    target_type="version",
                    target_id=version_id,
                    operator_id=operator_id,
                    detail={"scan_id": scan_id},
                    timestamp=now,
                )
            )
            session.commit()
            return _scan_task_data(scan_row)

    def delete_expired_scan_tasks(self, *, now: datetime | None = None) -> int:
        """Delete expired tasks without dropping callback-owing rows."""
        current_time = now or _utc_now()
        with self.session_factory() as session:
            result = session.execute(
                delete(ScanTaskRow).where(
                    ScanTaskRow.expires_at.is_not(None),
                    ScanTaskRow.expires_at <= current_time,
                    or_(
                        and_(
                            ScanTaskRow.status.in_(_SCAN_TASK_FAILURE_STATUSES),
                            # Preserve rows still needed for callback recovery.
                            or_(
                                ScanTaskRow.version_id.is_(None),
                                ScanTaskRow.callback_status.in_(
                                    ("delivered", "not_required")
                                ),
                            ),
                        ),
                        and_(
                            ScanTaskRow.status == "complete",
                            ScanTaskRow.version_id.is_(None),
                        ),
                    ),
                )
            )
            session.commit()
            return int(result.rowcount or 0)

    def backfill_orphan_scan_task_retention(
        self,
        *,
        now: datetime | None = None,
    ) -> int:
        """Give detached version-scans a retention deadline.

        A scan task attached to a version runs with ``expires_at = NULL``
        while the version lives.  When the version is removed through a
        path that bypasses ``delete_version`` (legacy rows, manual SQL), the
        FK ``ondelete=SET NULL`` leaves an orphan holding the dedup key
        forever.  This maintenance pass writes ``expires_at`` so the normal
        expiry cleaner can reclaim them.
        """
        current_time = now or _utc_now()
        with self.session_factory() as session:
            orphan_rows = session.scalars(
                select(ScanTaskRow).where(
                    ScanTaskRow.expires_at.is_(None),
                    ScanTaskRow.version_id.is_(None),
                    ScanTaskRow.status.in_(
                        {"complete"} | _SCAN_TASK_FAILURE_STATUSES
                    ),
                )
            ).all()
            for row in orphan_rows:
                finished = row.finished_at or current_time
                row.expires_at = finished + _SCAN_TASK_RETENTION
                row.updated_at = current_time
            session.commit()
            return len(orphan_rows)

    def list_scan_tasks_for_dedup(
        self,
        *,
        owner_user_id: str,
        repo_url: str | None = None,
        source_subdirectory: str | None = None,
    ) -> list[dict[str, object]]:
        """Return lightweight owner tasks for source-level duplicate checks.

        Only the dedup columns are loaded — ``report_json`` and other heavy
        fields stay unread.  With ``repo_url`` the repository filter is
        pushed down to SQL via the indexed ``dedup_repo_url`` column,
        and with ``source_subdirectory`` the subdirectory half of the
        identity key follows it.  The repo, callback and lease columns are
        part of the projection because the duplicate prechecks
        (``_scan_source_identity_match``, ``_scan_lifecycle``,
        ``_scan_delete_allowed``) read them.
        """
        dedup_url = (
            _scan_task_dedup_url(repo_url) if repo_url is not None else None
        )
        normalized_subdirectory: str | None = None
        subdirectory_filter_given = False
        if source_subdirectory not in (None, ""):
            from src.models.common import require_safe_source_subdirectory

            try:
                normalized_subdirectory = require_safe_source_subdirectory(
                    str(source_subdirectory).strip()
                )
            except ValueError:
                return []
            if normalized_subdirectory == ".":
                normalized_subdirectory = None
            subdirectory_filter_given = True
        elif source_subdirectory == "":
            subdirectory_filter_given = True
        with self.session_factory() as session:
            statement = select(
                ScanTaskRow.id.label("scan_id"),
                ScanTaskRow.owner_user_id,
                ScanTaskRow.dedup_repo_url,
                ScanTaskRow.repo_url,
                ScanTaskRow.source_ref,
                ScanTaskRow.commit_hash,
                ScanTaskRow.source_subdirectory,
                ScanTaskRow.version_id,
                ScanTaskRow.status,
                ScanTaskRow.callback_status,
                ScanTaskRow.completion_delivered_at,
                ScanTaskRow.lease_until,
                ScanTaskRow.created_at,
                ScanTaskRow.updated_at,
                ScanTaskRow.finished_at,
                ScanTaskRow.expires_at,
            ).where(ScanTaskRow.owner_user_id == owner_user_id)
            if dedup_url is not None:
                statement = statement.where(
                    ScanTaskRow.dedup_repo_url == dedup_url
                )
            if subdirectory_filter_given:
                if normalized_subdirectory is None:
                    statement = statement.where(
                        ScanTaskRow.source_subdirectory.is_(None)
                    )
                else:
                    statement = statement.where(
                        ScanTaskRow.source_subdirectory
                        == normalized_subdirectory
                    )
            rows = session.execute(
                statement.order_by(ScanTaskRow.created_at.desc())
            ).mappings()
            return [dict(row) for row in rows]

    def list_version_labels(
        self,
        version_ids: Collection[str],
    ) -> dict[str, dict[str, str]]:
        """Resolve version ids to their package name and version label."""
        ids = sorted({str(version_id) for version_id in version_ids if version_id})
        if not ids:
            return {}
        with self.session_factory() as session:
            rows = session.execute(
                select(
                    PackageVersionRow.id,
                    PackageVersionRow.version,
                    PackageRow.name,
                )
                .join(PackageRow, PackageRow.id == PackageVersionRow.package_id)
                .where(PackageVersionRow.id.in_(ids))
            ).all()
        return {
            str(row.id): {
                "package_name": str(row.name or ""),
                "version": str(row.version or ""),
            }
            for row in rows
        }

    def delete_scan_task(
        self,
        scan_id: str,
        *,
        owner_user_id: str | None = None,
        now: datetime | None = None,
        audit_operator_id: str | None = None,
        audit_detail: dict[str, object] | None = None,
    ) -> dict[str, object] | None:
        """Atomically delete an eligible task and optionally audit it."""
        current_time = now or _utc_now()
        with self.session_factory() as session:
            statement = select(ScanTaskRow).where(ScanTaskRow.id == scan_id)
            if owner_user_id is not None:
                statement = statement.where(
                    ScanTaskRow.owner_user_id == owner_user_id
                )
            row = session.scalar(statement.with_for_update())
            if row is None:
                return None

            if row.lease_until is not None and row.lease_until > current_time:
                raise ValueError("扫描任务仍在处理中，暂时不能删除")

            failure = row.status in _SCAN_TASK_FAILURE_STATUSES
            complete = row.status == "complete"
            if not failure and not complete:
                raise ValueError("扫描任务仍在处理中，暂时不能删除")
            if row.version_id is not None and row.callback_status not in {
                "delivered",
                "not_required",
            }:
                raise ValueError("扫描任务回调尚未完成，暂时不能删除")

            data = _scan_task_data(row)
            session.delete(row)
            if audit_operator_id is not None:
                session.add(
                    AuditLogRow(
                        id=f"audit-{uuid4().hex}",
                        action="scan_delete",
                        target_type="scan_task",
                        target_id=scan_id,
                        operator_id=audit_operator_id,
                        detail=audit_detail,
                        timestamp=current_time,
                    )
                )
            session.commit()
            return data

    def mark_scan_task_timed_out(
        self,
        scan_id: str,
        *,
        status: str,
        error: str,
        finished_at: datetime,
        expires_at: datetime,
        lease_token: str | None = None,
    ) -> bool:
        """Atomically terminalize an active task at the total-time deadline."""
        if status != "total_timeout":
            raise ValueError("Unsupported scan timeout status")
        with self.session_factory() as session:
            statement = (
                select(ScanTaskRow)
                .where(
                    ScanTaskRow.id == scan_id,
                    ScanTaskRow.status.in_(_SCAN_TASK_EXECUTABLE_STATUSES),
                )
                .with_for_update()
            )
            if lease_token:
                statement = statement.where(
                    ScanTaskRow.lease_token == lease_token
                )
            row = session.scalar(statement)
            if row is None:
                return False
            row.status = status
            row.error = error
            row.finished_at = finished_at
            row.expires_at = expires_at
            row.callback_status = (
                "pending" if row.version_id is not None else "not_required"
            )
            row.callback_next_attempt_at = None
            row.callback_last_error = None
            row.completion_delivered_at = None
            llm_review = finalize_running_llm_progress(
                row.llm_review,
                terminal_status="timeout",
                reason_code="scan_budget_exhausted",
                last_update_at=finished_at.isoformat(),
            )
            if llm_review is not None and llm_review != row.llm_review:
                row.llm_review = llm_review
            row.updated_at = finished_at
            session.commit()
            return True

    def get_scan_task(
        self,
        scan_id: str,
        *,
        owner_user_id: str | None = None,
    ) -> dict[str, object] | None:
        with self.session_factory() as session:
            statement = select(ScanTaskRow).where(ScanTaskRow.id == scan_id)
            if owner_user_id is not None:
                statement = statement.where(
                    ScanTaskRow.owner_user_id == owner_user_id
                )
            row = session.scalar(statement)
            return _scan_task_data(row) if row is not None else None

    def get_scan_task_by_request(
        self,
        *,
        owner_user_id: str,
        client_request_id: str,
    ) -> dict[str, object] | None:
        with self.session_factory() as session:
            row = session.scalar(
                select(ScanTaskRow).where(
                    ScanTaskRow.owner_user_id == owner_user_id,
                    ScanTaskRow.client_request_id == client_request_id,
                )
            )
            return _scan_task_data(row) if row is not None else None

    def claim_scan_task(
        self,
        scan_id: str,
        *,
        lease_seconds: int,
        now: datetime | None = None,
    ) -> dict[str, object] | None:
        current_time = now or _utc_now()
        lease_duration = max(60, int(lease_seconds))
        with self.session_factory() as session:
            statement = (
                select(ScanTaskRow)
                .where(
                    ScanTaskRow.id == scan_id,
                    ScanTaskRow.status.in_(_SCAN_TASK_EXECUTABLE_STATUSES),
                    or_(
                        ScanTaskRow.lease_until.is_(None),
                        ScanTaskRow.lease_until <= current_time,
                    ),
                )
                .with_for_update(skip_locked=True)
            )
            row = session.scalar(statement)
            if row is None:
                return None
            row.lease_token = uuid4().hex
            row.lease_until = current_time + timedelta(seconds=lease_duration)
            row.attempt_count = int(row.attempt_count or 0) + 1
            row.updated_at = current_time
            session.commit()
            return _scan_task_data(row)

    def claim_recoverable_scan_tasks(
        self,
        *,
        lease_seconds: int,
        limit: int = 50,
        now: datetime | None = None,
    ) -> list[dict[str, object]]:
        """Claim pending/stale tasks for startup recovery.

        Terminal tasks with an undelivered version callback are included so a
        crash or prolonged callback outage cannot strand the version.
        """
        current_time = now or _utc_now()
        lease_duration = max(60, int(lease_seconds))
        bounded_limit = max(1, min(int(limit), 200))
        active_condition = ScanTaskRow.status.in_(_SCAN_TASK_EXECUTABLE_STATUSES)
        callback_owing_condition = and_(
            ScanTaskRow.status.in_({"complete"} | _SCAN_TASK_FAILURE_STATUSES),
            ScanTaskRow.version_id.is_not(None),
            ScanTaskRow.completion_delivered_at.is_(None),
        )
        callback_condition = and_(
            callback_owing_condition,
            or_(
                ScanTaskRow.callback_status == "pending",
                ScanTaskRow.callback_status.is_(None),
            ),
            or_(
                ScanTaskRow.callback_next_attempt_at.is_(None),
                ScanTaskRow.callback_next_attempt_at <= current_time,
            ),
        )
        # Keep active and callback-owing rows recoverable despite stale legacy
        # expiry values.
        retention_condition = or_(
            active_condition,
            ScanTaskRow.expires_at.is_(None),
            ScanTaskRow.expires_at > current_time,
            callback_owing_condition,
        )
        with self.session_factory() as session:
            rows = session.scalars(
                select(ScanTaskRow)
                .where(
                    or_(active_condition, callback_condition),
                    retention_condition,
                    or_(
                        ScanTaskRow.lease_until.is_(None),
                        ScanTaskRow.lease_until <= current_time,
                    ),
                )
                .order_by(ScanTaskRow.created_at)
                .limit(bounded_limit)
                .with_for_update(skip_locked=True)
            ).all()
            for row in rows:
                row.lease_token = uuid4().hex
                row.lease_until = current_time + timedelta(
                    seconds=lease_duration
                )
                if row.status in _SCAN_TASK_EXECUTABLE_STATUSES:
                    row.attempt_count = int(row.attempt_count or 0) + 1
                row.updated_at = current_time
            session.commit()
            return [_scan_task_data(row) for row in rows]

    def claim_scan_callback_task(
        self,
        scan_id: str,
        *,
        lease_seconds: int,
        now: datetime | None = None,
    ) -> dict[str, object] | None:
        current_time = now or _utc_now()
        lease_duration = max(60, int(lease_seconds))
        with self.session_factory() as session:
            row = session.scalar(
                select(ScanTaskRow)
                .where(
                    ScanTaskRow.id == scan_id,
                    ScanTaskRow.status.in_({"complete"} | _SCAN_TASK_FAILURE_STATUSES),
                    ScanTaskRow.version_id.is_not(None),
                    ScanTaskRow.completion_delivered_at.is_(None),
                    or_(
                        ScanTaskRow.callback_status == "pending",
                        ScanTaskRow.callback_status.is_(None),
                    ),
                    or_(
                        ScanTaskRow.callback_next_attempt_at.is_(None),
                        ScanTaskRow.callback_next_attempt_at <= current_time,
                    ),
                    or_(
                        ScanTaskRow.lease_until.is_(None),
                        ScanTaskRow.lease_until <= current_time,
                    ),
                )
                .with_for_update(skip_locked=True)
            )
            if row is None:
                return None
            row.lease_token = uuid4().hex
            row.lease_until = current_time + timedelta(seconds=lease_duration)
            row.updated_at = current_time
            session.commit()
            return _scan_task_data(row)

    def renew_scan_task_lease(
        self,
        scan_id: str,
        *,
        lease_token: str,
        lease_seconds: int,
        now: datetime | None = None,
    ) -> bool:
        current_time = now or _utc_now()
        lease_duration = max(60, int(lease_seconds))
        with self.session_factory() as session:
            row = session.scalar(
                select(ScanTaskRow)
                .where(
                    ScanTaskRow.id == scan_id,
                    ScanTaskRow.lease_token == lease_token,
                    ScanTaskRow.lease_until > current_time,
                )
                .with_for_update()
            )
            if row is None:
                return False
            row.lease_until = current_time + timedelta(seconds=lease_duration)
            row.updated_at = current_time
            session.commit()
            return True

    def release_scan_task_lease(
        self,
        scan_id: str,
        *,
        lease_token: str,
        now: datetime | None = None,
    ) -> bool:
        current_time = now or _utc_now()
        with self.session_factory() as session:
            row = session.scalar(
                select(ScanTaskRow)
                .where(
                    ScanTaskRow.id == scan_id,
                    ScanTaskRow.lease_token == lease_token,
                )
                .with_for_update()
            )
            if row is None:
                return False
            row.lease_token = None
            row.lease_until = None
            row.updated_at = current_time
            session.commit()
            return True

    def mark_scan_callback_delivered(
        self,
        scan_id: str,
        *,
        lease_token: str | None = None,
        resource_consumed: bool = False,
        now: datetime | None = None,
    ) -> bool:
        current_time = now or _utc_now()
        with self.session_factory() as session:
            row = session.scalar(
                select(ScanTaskRow)
                .where(ScanTaskRow.id == scan_id)
                .with_for_update()
            )
            if row is None:
                return False
            if row.callback_status == "delivered" or (
                row.completion_delivered_at is not None
            ):
                if resource_consumed and not row.resource_consumed:
                    row.resource_consumed = True
                    row.updated_at = current_time
                    session.commit()
                return True
            if lease_token and row.lease_token != lease_token:
                return False
            row.callback_status = "delivered"
            if resource_consumed:
                row.resource_consumed = True
            row.callback_next_attempt_at = None
            row.callback_last_error = None
            row.completion_delivered_at = current_time
            row.lease_token = None
            row.lease_until = None
            row.updated_at = current_time
            session.commit()
            return True

    def terminalize_scan_task_after_packaging_failure(
        self,
        scan_id: str,
        error: str,
        *,
        now: datetime | None = None,
    ) -> bool:
        current_time = now or _utc_now()
        with self.session_factory() as session:
            row = session.scalar(
                select(ScanTaskRow)
                .where(ScanTaskRow.id == scan_id)
                .with_for_update()
            )
            if row is None or row.status != "complete":
                return False
            row.status = "error"
            row.error = error
            if row.finished_at is None:
                row.finished_at = current_time
            finished = row.finished_at or current_time
            row.expires_at = finished + _SCAN_TASK_RETENTION
            row.callback_status = "delivered"
            row.resource_consumed = True
            row.callback_next_attempt_at = None
            row.callback_last_error = None
            row.completion_delivered_at = current_time
            row.lease_token = None
            row.lease_until = None
            row.updated_at = current_time
            session.commit()
            return True

    def list_scan_tasks(
        self,
        *,
        owner_user_id: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[dict[str, object]]:
        """List persisted scans, optionally restricted to one owner.

        ``limit=None`` returns the full set; the legacy array contract uses
        it because silently truncating the list would hide retained tasks
        behind a 409.
        """
        with self.session_factory() as session:
            statement = select(ScanTaskRow)
            if owner_user_id is not None:
                statement = statement.where(
                    ScanTaskRow.owner_user_id == owner_user_id
                )
            statement = statement.order_by(ScanTaskRow.created_at.desc())
            if limit is not None:
                statement = statement.offset(offset).limit(limit)
            elif offset:
                statement = statement.offset(offset)
            rows = session.scalars(statement).all()
            return [_scan_task_data(row) for row in rows]

    def count_scan_tasks(self, *, owner_user_id: str | None = None) -> int:
        with self.session_factory() as session:
            statement = select(func.count()).select_from(ScanTaskRow)
            if owner_user_id is not None:
                statement = statement.where(
                    ScanTaskRow.owner_user_id == owner_user_id
                )
            return int(session.scalar(statement) or 0)

    def update_scan_task(
        self,
        scan_id: str,
        updates: Mapping[str, object],
        *,
        lease_token: str | None = None,
        expected_statuses: Collection[str] | None = None,
    ) -> bool:
        """Apply an allow-listed update while holding the task row lock.

        ``expected_statuses`` provides a compare-and-set guard for progress
        writers so a late heartbeat cannot mutate an already terminal task.
        """
        unknown_fields = set(updates) - _SCAN_TASK_UPDATE_FIELDS
        if unknown_fields:
            raise ValueError(
                "Unsupported scan task fields: "
                + ", ".join(sorted(unknown_fields))
            )
        if not updates:
            return False

        with self.session_factory() as session:
            statement = select(ScanTaskRow).where(ScanTaskRow.id == scan_id)
            if lease_token:
                statement = statement.where(
                    ScanTaskRow.lease_token == lease_token
                )
            row = session.scalar(statement.with_for_update())
            if row is None:
                return False
            if (
                expected_statuses is not None
                and row.status not in set(expected_statuses)
            ):
                return False
            requested_status = updates.get("status")
            if (
                requested_status is not None
                and row.status in ({"complete"} | _SCAN_TASK_FAILURE_STATUSES)
                and str(requested_status) != row.status
            ):
                # A late worker update must not resurrect a task that a
                # timeout watchdog already terminalized.
                return False
            for field, value in updates.items():
                setattr(row, field, value)
            current_time = _utc_now()
            effective_status = str(updates.get("status") or row.status)
            effective_version_id = updates.get("version_id", row.version_id)
            if effective_status in _SCAN_TASK_EXECUTABLE_STATUSES:
                # A stale pre-terminal expiry must never remove a running
                # task. The execution deadline is enforced by the worker.
                if "expires_at" not in updates:
                    row.expires_at = None
            elif effective_status in _SCAN_TASK_FAILURE_STATUSES:
                if "finished_at" not in updates and row.finished_at is None:
                    row.finished_at = current_time
                if "expires_at" not in updates:
                    finished = row.finished_at or current_time
                    if isinstance(finished, str):
                        try:
                            finished = _parse_iso_date(finished)
                        except ValueError:
                            finished = current_time
                    row.expires_at = finished + _SCAN_TASK_RETENTION
            elif effective_status == "complete" and "expires_at" not in updates:
                if effective_version_id is None:
                    finished = row.finished_at or current_time
                    if isinstance(finished, str):
                        try:
                            finished = _parse_iso_date(finished)
                        except ValueError:
                            finished = current_time
                    row.expires_at = finished + _SCAN_TASK_RETENTION
                else:
                    # Once a scan is attached and its callback is delivered,
                    # the review workflow owns retention, not this cleaner.
                    row.expires_at = None
            row.updated_at = current_time
            session.commit()
            return True

    # ── 审核记录 ──────────────────────────────────────────

    def create_review_record(
        self,
        *,
        version_id: str,
        reviewer_id: str,
        conclusion: str,
        comment: str | None = None,
    ) -> dict[str, object]:
        record_id = f"rev-{uuid4().hex}"
        now = _utc_now()
        with self.session_factory() as session:
            session.add(
                ReviewRecordRow(
                    id=record_id,
                    version_id=version_id,
                    reviewer_id=reviewer_id,
                    conclusion=conclusion,
                    comment=comment,
                    created_at=now,
                )
            )
            session.commit()
        return {
            "id": record_id,
            "version_id": version_id,
            "reviewer_id": reviewer_id,
            "conclusion": conclusion,
            "comment": comment,
            "created_at": _serialize_dt(now),
        }

    def list_review_records(
        self, version_id: str
    ) -> list[dict[str, object]]:
        with self.session_factory() as session:
            stmt = (
                select(
                    ReviewRecordRow.id,
                    ReviewRecordRow.version_id,
                    ReviewRecordRow.reviewer_id,
                    ReviewRecordRow.conclusion,
                    ReviewRecordRow.comment,
                    ReviewRecordRow.created_at,
                    UserRow.display_name.label("reviewer_display_name"),
                )
                .outerjoin(UserRow, UserRow.id == ReviewRecordRow.reviewer_id)
                .where(ReviewRecordRow.version_id == version_id)
                .order_by(ReviewRecordRow.created_at.desc())
            )
            rows = session.execute(stmt).all()
            return [
                {
                    "id": row.id,
                    "version_id": row.version_id,
                    "reviewer_id": row.reviewer_id,
                    "reviewer_name": row.reviewer_display_name,
                    "reviewer_display_name": row.reviewer_display_name,
                    "conclusion": row.conclusion,
                    "comment": row.comment,
                    "created_at": _serialize_dt(row.created_at),
                }
                for row in rows
            ]

    def list_reviews_by_reviewer(
        self, reviewer_id: str, limit: int = 50, offset: int = 0
    ) -> list[dict[str, object]]:
        """返回某审核员的全部审核记录，附带版本和包信息。"""
        with self.session_factory() as session:
            stmt = (
                select(
                    ReviewRecordRow.id,
                    ReviewRecordRow.version_id,
                    ReviewRecordRow.conclusion,
                    ReviewRecordRow.comment,
                    ReviewRecordRow.created_at,
                    PackageVersionRow.version.label("version_label"),
                    PackageVersionRow.status.label("version_status"),
                    PackageRow.name.label("package_name"),
                )
                .join(
                    PackageVersionRow,
                    PackageVersionRow.id == ReviewRecordRow.version_id,
                )
                .join(
                    PackageRow,
                    PackageRow.id == PackageVersionRow.package_id,
                )
                .where(ReviewRecordRow.reviewer_id == reviewer_id)
                .order_by(ReviewRecordRow.created_at.desc())
                .offset(offset)
                .limit(limit)
            )
            rows = session.execute(stmt).all()
            return [
                {
                    "id": row.id,
                    "version_id": row.version_id,
                    "conclusion": row.conclusion,
                    "comment": row.comment,
                    "created_at": _serialize_dt(row.created_at),
                    "version": row.version_label,
                    "version_status": row.version_status,
                    "package_name": row.package_name,
                }
                for row in rows
            ]

    # ── 审计日志 ──────────────────────────────────────────

    def create_audit_log(
        self,
        *,
        action: str,
        target_type: str,
        target_id: str,
        operator_id: str,
        detail: dict[str, object] | None = None,
        idempotency_key: str | None = None,
    ) -> None:
        self._create_audit_log(
            action=action,
            target_type=target_type,
            target_id=target_id,
            operator_id=operator_id,
            detail=detail,
            idempotency_key=idempotency_key,
        )

    def _create_audit_log(
        self,
        *,
        action: str,
        target_type: str,
        target_id: str,
        operator_id: str,
        detail: dict[str, object] | None = None,
        idempotency_key: str | None = None,
    ) -> None:
        with self.session_factory() as session:
            audit_id = (
                f"audit-{hashlib.sha256(idempotency_key.encode()).hexdigest()[:58]}"
                if idempotency_key
                else f"audit-{uuid4().hex}"
            )
            session.add(
                AuditLogRow(
                    id=audit_id,
                    action=action,
                    target_type=target_type,
                    target_id=target_id,
                    operator_id=operator_id,
                    detail=detail,
                    timestamp=_utc_now(),
                )
            )
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                if not idempotency_key:
                    raise
                if session.get(AuditLogRow, audit_id) is None:
                    raise



    def list_audit_logs(
        self,
        *,
        target_type: str | None = None,
        target_id: str | None = None,
        action: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, object]]:
        """分页查询审计日志，支持按目标类型/目标ID/操作类型/时间范围筛选。"""
        with self.session_factory() as session:
            stmt = select(
                AuditLogRow.id,
                AuditLogRow.action,
                AuditLogRow.target_type,
                AuditLogRow.target_id,
                AuditLogRow.operator_id,
                AuditLogRow.timestamp,
                AuditLogRow.detail,
                UserRow.display_name.label("operator_name"),
            ).outerjoin(UserRow, UserRow.id == AuditLogRow.operator_id)
            if target_type:
                stmt = stmt.where(AuditLogRow.target_type == target_type)
            if target_id:
                stmt = stmt.where(AuditLogRow.target_id == target_id)
            if action:
                stmt = stmt.where(AuditLogRow.action == action)
            if start_date:
                stmt = stmt.where(AuditLogRow.timestamp >= _parse_iso_date(start_date))
            if end_date:
                stmt = stmt.where(AuditLogRow.timestamp <= _parse_iso_date(end_date))
            stmt = stmt.order_by(AuditLogRow.timestamp.desc())
            stmt = stmt.offset(offset).limit(limit)
            rows = session.execute(stmt).all()
            return [
                {
                    "id": row.id,
                    "action": row.action,
                    "target_type": row.target_type,
                    "target_id": row.target_id,
                    "operator_id": row.operator_id,
                    "operator_name": row.operator_name,
                    "timestamp": _serialize_dt(row.timestamp),
                    "detail": row.detail,
                }
                for row in rows
            ]
# ── 统计查询 ──────────────────────────────────────────────

    def get_dashboard_stats(self) -> dict[str, object]:
        """返回管理仪表盘统计数据。"""
        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        with self.session_factory() as session:
            total_packages = session.scalar(
                select(func.count()).select_from(PackageRow)
            ) or 0
            total_versions = session.scalar(
                select(func.count()).select_from(PackageVersionRow)
            ) or 0
            # Review workflow state belongs to versions.  Keep dashboard counts
            # aligned with the version lists each card opens instead of using the
            # package's public catalog state (draft/published/yanked).
            pending_review = session.scalar(
                select(func.count())
                .select_from(PackageVersionRow)
                .where(PackageVersionRow.status == "pending_review")
            ) or 0
            today_submissions = session.scalar(
                select(func.count())
                .select_from(PackageVersionRow)
                .where(
                    PackageVersionRow.data["submitted_at"]
                    .as_string()
                    >= today_start.isoformat()
                )
            ) or 0
            # The publish page exposes only the newest approved version per
            # package, so count the same unit here instead of raw versions.
            approved_count = session.scalar(
                select(func.count(func.distinct(PackageVersionRow.package_id)))
                .select_from(PackageVersionRow)
                .where(PackageVersionRow.status == "approved")
            ) or 0
            published_count = session.scalar(
                select(func.count())
                .select_from(PackageVersionRow)
                .where(PackageVersionRow.status == "published")
            ) or 0
            rejected_count = session.scalar(
                select(func.count())
                .select_from(PackageVersionRow)
                .where(PackageVersionRow.status == "rejected")
            ) or 0
            yanked_count = session.scalar(
                select(func.count())
                .select_from(PackageVersionRow)
                .where(PackageVersionRow.status == "yanked")
            ) or 0
            # The user-management page lists both active and disabled users.
            total_users = session.scalar(
                select(func.count()).select_from(UserRow)
            ) or 0
            total_audit_logs = session.scalar(
                select(func.count()).select_from(AuditLogRow)
            ) or 0
            today_audit_actions = session.scalar(
                select(func.count())
                .select_from(AuditLogRow)
                .where(AuditLogRow.timestamp >= today_start)
            ) or 0
        return {
            "total_packages": total_packages,
            "total_versions": total_versions,
            "pending_review": pending_review,
            "today_submissions": today_submissions,
            "approved": approved_count,
            "published": published_count,
            "rejected": rejected_count,
            "yanked": yanked_count,
            "total_users": total_users,
            "total_audit_logs": total_audit_logs,
            # Retain this field for existing API consumers.  The dashboard
            # card uses total_audit_logs because its destination shows all
            # audit records, not only today's records.
            "today_audit_actions": today_audit_actions,
        }

# ── 辅助函数 ──────────────────────────────────────────────

    def list_versions_by_submitter(
        self, submitter_id: str, limit: int = 50, offset: int = 0
    ) -> list[dict[str, object]]:
        """返回某个提交者的所有版本列表，按提交时间倒序。"""
        with self.session_factory() as session:
            rows = session.execute(
                select(
                    PackageVersionRow.id,
                    PackageVersionRow.package_id,
                    PackageVersionRow.version,
                    PackageVersionRow.status,
                    PackageVersionRow.data,
                    PackageRow.name.label("package_name"),
                )
                .join(PackageRow, PackageRow.id == PackageVersionRow.package_id)
                .where(
                    PackageVersionRow.data["submitter_id"].as_string()
                    == submitter_id
                )
                .order_by(
                    PackageVersionRow.data["submitted_at"]
                    .as_string()
                    .desc()
                    .nullslast()
                )
                .offset(offset)
                .limit(limit)
            ).all()
            return [
                {
                    "version_id": row.id,
                    "package_id": row.package_id,
                    "package_name": row.package_name,
                    "version": row.version,
                    "status": row.status,
                    "submitted_at": (row.data or {}).get("submitted_at"),
                    "yank_reason": (row.data or {}).get("yank_reason"),
                    "trust_score": (row.data or {}).get("trust_score"),
                }
                for row in rows
            ]

    def list_versions_by_status(
        self,
        *,
        status: str | list[str] | None = None,
        grade: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, object]]:
        """按状态筛选版本列表（审核员视图用），带包名和扫描摘要。

        支持逗号分隔的多状态筛选、风险等级过滤、提交时间范围过滤。
        返回字段：version_id / package_id / package_name / package_type /
        version / status / submitted_at / grade / findings_count。
        """
        with self.session_factory() as session:
            stmt = (
                select(
                    PackageVersionRow.id,
                    PackageVersionRow.package_id,
                    PackageVersionRow.version,
                    PackageVersionRow.status,
                    PackageVersionRow.data,
                    PackageVersionRow.manual_grade,
                    PackageVersionRow.manual_grade_by,
                    PackageVersionRow.manual_grade_at,
                    PackageVersionRow.manual_grade_reason,
                    PackageRow.name.label("package_name"),
                    PackageRow.data.label("package_data"),
                    ScanReportRow.scan_json,
                )
                .join(PackageRow, PackageRow.id == PackageVersionRow.package_id)
                .outerjoin(
                    ScanReportRow,
                    ScanReportRow.version_id == PackageVersionRow.id,
                )
            )

            if status:
                if isinstance(status, str):
                    statuses = [s.strip() for s in status.split(",") if s.strip()]
                else:
                    statuses = status
                if statuses:
                    stmt = stmt.where(PackageVersionRow.status.in_(statuses))

            if since:
                stmt = stmt.where(
                    PackageVersionRow.data["submitted_at"].as_string()
                    >= _normalize_iso_boundary(since)
                )
            if until:
                stmt = stmt.where(
                    PackageVersionRow.data["submitted_at"].as_string()
                    <= _normalize_iso_boundary(until)
                )

            stmt = stmt.order_by(
                PackageVersionRow.data["submitted_at"]
                .as_string()
                .desc()
                .nullslast()
            ).offset(offset).limit(limit)

            rows = session.execute(stmt).all()

        results: list[dict[str, object]] = []
        user_ids = {row.manual_grade_by for row in rows if row.manual_grade_by}
        user_names: dict[str, str] = {}
        if user_ids:
            with self.session_factory() as session:
                user_rows = session.execute(
                    select(UserRow.id, UserRow.display_name)
                    .where(UserRow.id.in_(user_ids))
                ).all()
                user_names = {r.id: r.display_name or r.id for r in user_rows}

        for row in rows:
            data = row.data or {}
            trust_score = data.get("trust_score", {})
            grade_val = None
            if isinstance(trust_score, dict):
                risk_summary = trust_score.get("risk_summary", {})
                if isinstance(risk_summary, dict):
                    grade_val = risk_summary.get("grade")

            findings_count = 0
            if row.scan_json and isinstance(row.scan_json, dict):
                summary = row.scan_json.get("summary", {})
                if isinstance(summary, dict):
                    findings_count = summary.get("total", 0)

            pkg_data = row.package_data or {}
            package_type = None
            if isinstance(pkg_data, dict):
                package_type = pkg_data.get("type")

            results.append({
                "version_id": row.id,
                "package_id": row.package_id,
                "package_name": row.package_name,
                "package_type": package_type,
                "version": row.version,
                "status": row.status,
                "submitted_at": data.get("submitted_at"),
                "published_at": data.get("published_at"),
                "auto_grade": grade_val,
                "manual_grade": row.manual_grade if row.manual_grade and row.manual_grade != "F" else None,
                "manual_grade_by": row.manual_grade_by,
                "manual_grade_by_name": user_names.get(row.manual_grade_by or "") if row.manual_grade_by else None,
                "manual_grade_at": _serialize_dt(row.manual_grade_at) if row.manual_grade_at else None,
                "manual_grade_reason": row.manual_grade_reason,
                "grade": (row.manual_grade if row.manual_grade and row.manual_grade != "F" else None) or grade_val,
                "findings_count": findings_count,
                "yank_reason": data.get("yank_reason"),
            })

        if grade:
            results = [r for r in results if r.get("grade") == grade]

        return results

    def list_artifact_versions(self) -> list[dict[str, object]]:
        """返回制品清理所需的版本状态、命名和来源信息。"""
        with self.session_factory() as session:
            rows = session.execute(
                select(
                    PackageVersionRow.status,
                    PackageVersionRow.version,
                    PackageVersionRow.data,
                    PackageRow.name.label("package_name"),
                ).join(PackageRow, PackageRow.id == PackageVersionRow.package_id)
            ).all()

        return [
            {
                "status": row.status,
                "version": row.version,
                "package_name": row.package_name,
                "source": (row.data or {}).get("source") or {},
            }
            for row in rows
        ]

    # ── 用户管理 ────────────────────────────────────────────

    def list_users(
        self,
        *,
        search: str | None = None,
        role: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, object]], int]:
        """分页查询用户列表，支持邮箱/昵称模糊搜索 + 角色筛选。"""
        with self.session_factory() as session:
            base = select(UserRow)
            count_base = select(func.count()).select_from(UserRow)

            if search:
                pattern = f"%{search}%"
                base = base.where(
                    UserRow.email.ilike(pattern) | UserRow.display_name.ilike(pattern)
                )
                count_base = count_base.where(
                    UserRow.email.ilike(pattern) | UserRow.display_name.ilike(pattern)
                )

            if role:
                base = base.where(UserRow.role == role)
                count_base = count_base.where(UserRow.role == role)

            total = session.scalar(count_base) or 0

            rows = session.execute(
                base.order_by(UserRow.created_at.desc()).offset(offset).limit(limit)
            ).scalars().all()

            items = [
                {
                    "id": row.id,
                    "email": row.email,
                    "display_name": row.display_name,
                    "role": row.role,
                    "is_active": row.is_active,
                    "created_at": _serialize_dt(row.created_at),
                }
                for row in rows
            ]
            return items, total

    def update_user_role(self, user_id: str, new_role: str) -> dict[str, object] | None:
        """更新用户角色。返回更新后的用户信息；若用户不存在返回 None；若角色未变返回特殊标记。
        
        Returns:
            dict with "conflict": True 表示角色未变化。
        """
        with self.session_factory() as session:
            user = session.get(UserRow, user_id)
            if user is None:
                return None
            if user.role == new_role:
                return {"conflict": True}
            user.role = new_role
            session.commit()
            return {
                "id": user.id,
                "email": user.email,
                "display_name": user.display_name,
                "role": user.role,
                "is_active": user.is_active,
                "created_at": _serialize_dt(user.created_at),
            }

    def update_user_status(self, user_id: str, is_active: bool) -> dict[str, object] | None:
        """启用或禁用用户账号。返回更新后的用户信息，若用户不存在返回 None。"""
        with self.session_factory() as session:
            user = session.get(UserRow, user_id)
            if user is None:
                return None
            user.is_active = is_active
            session.commit()
            return {
                "id": user.id,
                "email": user.email,
                "display_name": user.display_name,
                "role": user.role,
                "is_active": user.is_active,
                "created_at": _serialize_dt(user.created_at),
            }


def _version_brief(row: PackageVersionRow) -> dict[str, object]:
    data = dict(row.data) if row.data else {}
    return {
        "id": row.id,
        "version": row.version,
        "status": row.status,
        "submitted_at": data.get("submitted_at"),
        "created_at": data.get("created_at"),
    }
