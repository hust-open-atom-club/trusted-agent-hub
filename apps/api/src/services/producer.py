"""供给侧业务逻辑 — 状态机校验、扫描触发协调。"""

from __future__ import annotations

import difflib
import logging
import re
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from src.repositories.producer_sqlalchemy import (
    ProducerRepository,
    ScanTaskSourceConflictError,
)
from src.services.source_snapshots import SourceSnapshotStore
from src.services.trust_boundary import public_trust_boundary
from scanners.risk_scanner.redaction import redact_report
from src.models.producer import (
    CreatePackageRequest,
    CreateVersionRequest,
    PackageResponse,
    SubmitResponse,
    VersionResponse,
)

# 从 constants.py 导入状态常量
from schema.constants import (
    STATUS_TRANSITIONS, VersionStatus, AuditAction,
    GRADE_TO_RISK_LEVEL, GRADE_TO_RECOMMENDATION,
    PACKAGE_TYPE_INSTALL_CLIENTS,
    PACKAGE_TYPE_INSTALL_ROOTS,
    HASH_SCOPE_ARTIFACT_ARCHIVE,
)

_SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)

logger = logging.getLogger(__name__)


_SUBMITTER_FINDING_FIELDS = (
    "id",
    "rule_id",
    "file",
    "line",
    "suggestion",
    "remediation",
    "cwe_id",
)

_SUBMITTER_SEVERITIES = frozenset({
    "critical",
    "high",
    "medium",
    "low",
    "info",
})

_SUBMITTER_TRUST_SCORE_FIELDS = ("score", "level", "grade", "recommendation")
_SUBMITTER_RISK_SUMMARY_FIELDS = (
    "level",
    "grade",
    "install_recommendation",
)


def _project_submitter_trust_score(value: object) -> dict[str, object]:
    """Return only the score conclusion needed by the submitter status page."""
    if not isinstance(value, dict):
        return {"risk_summary": None}

    projected: dict[str, object] = {}
    for key in _SUBMITTER_TRUST_SCORE_FIELDS:
        raw = value.get(key)
        if key == "score":
            if isinstance(raw, (int, float)) and not isinstance(raw, bool):
                if 0 <= float(raw) <= 100:
                    projected[key] = raw
        elif isinstance(raw, str) and raw:
            projected[key] = raw

    risk_summary = value.get("risk_summary")
    if isinstance(risk_summary, dict):
        projected["risk_summary"] = {
            key: deepcopy(risk_summary[key])
            for key in _SUBMITTER_RISK_SUMMARY_FIELDS
            if isinstance(risk_summary.get(key), str) and risk_summary[key]
        }
    else:
        projected["risk_summary"] = None
    return projected


def _project_submitter_findings(value: object) -> list[dict[str, object]]:
    """Return a bounded, redacted finding projection for the owning submitter."""
    if not isinstance(value, list):
        return []

    projected: list[dict[str, object]] = []
    for raw in value:
        if not isinstance(raw, dict):
            continue
        raw = redact_report(raw)
        finding = {
            key: deepcopy(raw[key])
            for key in _SUBMITTER_FINDING_FIELDS
            if key in raw
        }
        # ``severity`` is the public effective severity. Never forward the
        # detector's static severity or other review workflow metadata.
        effective_severity = raw.get("effective_severity")
        if (
            not isinstance(effective_severity, str)
            or effective_severity not in _SUBMITTER_SEVERITIES
        ):
            effective_severity = raw.get("severity")
        if (
            isinstance(effective_severity, str)
            and effective_severity in _SUBMITTER_SEVERITIES
        ):
            finding["severity"] = effective_severity
        location = raw.get("location")
        if isinstance(location, dict):
            safe_location = {
                key: deepcopy(location[key])
                for key in ("file", "line")
                if key in location
            }
            if safe_location:
                finding["location"] = safe_location
                finding.setdefault("file", safe_location.get("file"))
                finding.setdefault("line", safe_location.get("line"))
        projected.append(finding)
    return projected
_SOURCE_SNAPSHOT_STORE = SourceSnapshotStore()


_AUTHOR_PLACEHOLDERS = {
    "unknown",
    "unknown@unknown.org",
    "unknown@unknown.com",
}


def _usable_author_fields(author: object) -> dict[str, str]:
    """Return non-placeholder legacy author fields safe to persist."""
    if not isinstance(author, dict):
        return {}
    result: dict[str, str] = {}
    for field in ("name", "email", "url"):
        value = str(author.get(field) or "").strip()
        if not value or value.casefold() in _AUTHOR_PLACEHOLDERS:
            continue
        if field == "url" and "github.com/unknown/" in value.casefold():
            continue
        result[field] = value
    return result


def _canonical_comparison_url(value: str | None) -> str | None:
    """Normalize benign URL spelling differences for duplicate detection."""
    if not value or not value.strip():
        return None
    parsed = urlparse(value.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return value.strip().rstrip("/")
    path = parsed.path.rstrip("/")
    if path.casefold().endswith(".git"):
        path = path[:-4]
    normalized = f"{parsed.scheme.casefold()}://{parsed.netloc.casefold()}{path}"
    return normalized.casefold() if parsed.hostname == "github.com" else normalized


def _distinct_homepage(
    homepage: str | None,
    repository_url: str | None,
) -> str | None:
    """Drop a project homepage that merely repeats the source repository."""
    value = homepage.strip() if homepage else ""
    if not value:
        return None
    if (
        _canonical_comparison_url(value)
        == _canonical_comparison_url(repository_url)
    ):
        return None
    return value


def _backfill_author_license(
    repository: ProducerRepository,
    version_id: str,
    extracted: dict[str, object],
) -> None:
    """用扫描提取的真实 author/license 补齐版本元数据。

    规则：逐字段合并且手动值优先；提取器的占位兜底值
    （UNKNOWN / UNLICENSED / 空）不写回。作者 URL 被用户修改或清空后，
    后续扫描都不得覆盖该选择。
    """
    version = repository.get_version(version_id)
    if not version:
        return

    updates: dict[str, object] = {}

    current_author = _usable_author_fields(version.get("author"))
    scanned_author = _usable_author_fields(extracted.get("author"))
    field_source = version.get("field_source")
    author_url_is_manual = (
        isinstance(field_source, dict)
        and field_source.get("author.url") == "manual"
    )
    merged_author = dict(current_author)
    for field, value in scanned_author.items():
        if field == "url" and author_url_is_manual:
            continue
        merged_author.setdefault(field, value)
    raw_author = version.get("author")
    if merged_author and merged_author != raw_author:
        updates["author"] = merged_author

    current_license = str(version.get("license") or "").strip()
    if not current_license or current_license.upper() in ("NONE", "UNLICENSED"):
        new_license = str(extracted.get("license") or "").strip()
        if new_license and new_license.upper() not in ("NONE", "UNLICENSED", "UNKNOWN"):
            updates["license"] = new_license

    if updates:
        repository.update_version_data(version_id, updates)


class ProducerServiceError(Exception):
    """供给侧业务逻辑错误。"""


class ProducerPersistenceError(ProducerServiceError):
    """A submission could not be committed to the database."""


class ProducerSourceConflictError(ProducerServiceError):
    """A retained scan task already exists for the same source identity."""


class ProducerSubmissionConflict(ProducerServiceError):
    """The version was claimed by another submission or is already in flight."""


class ProducerService:
    """供给侧业务逻辑服务。"""

    def __init__(self, repository: ProducerRepository) -> None:
        self.repository = repository

    @staticmethod
    def _normalize_compatibility(
        package_type: str, compatibility: list[str] | None
    ) -> list[str]:
        """Validate and normalize install clients allowed by the package type."""
        allowed = list(PACKAGE_TYPE_INSTALL_CLIENTS.get(package_type, ()))
        values = [
            str(c).strip()
            for c in (compatibility or [])
            if c and str(c).strip()
        ]
        invalid = [c for c in values if c not in allowed]
        if invalid:
            raise ProducerServiceError(
                f"包类型 '{package_type}' 不允许安装到客户端: "
                f"{', '.join(invalid)}；允许的客户端: "
                f"{', '.join(allowed) or '无'}"
            )
        if values:
            return values
        return allowed or ["claude-code"]

    @staticmethod
    def _validate_installation_clients(
        package_type: str,
        installation: object,
    ) -> None:
        """Reject installation targets that the package type cannot support."""
        if installation is None:
            return
        allowed = set(PACKAGE_TYPE_INSTALL_CLIENTS.get(package_type, ()))
        clients: list[str] = []
        target_client = getattr(installation, "target_client", None)
        if target_client:
            clients.append(str(target_client))
        for target in getattr(installation, "targets", None) or []:
            client = getattr(target, "client", None)
            if client:
                clients.append(str(client))
        invalid = sorted({client for client in clients if client not in allowed})
        if invalid:
            raise ProducerServiceError(
                f"包类型 '{package_type}' 不允许安装目标客户端: "
                f"{', '.join(invalid)}；允许的客户端: "
                f"{', '.join(sorted(allowed)) or '无'}"
            )

    # ── 创建包 ────────────────────────────────────────────

    def create_package(
        self, data: CreatePackageRequest, submitter_id: str | None = None
    ) -> PackageResponse:
        if not data.name or not data.name.strip():
            raise ProducerServiceError("包名称不能为空")
        if not data.description:
            raise ProducerServiceError("包描述不能为空")
        self._validate_installation_clients(data.type.value, data.installation)

        # 同名 draft 包满足续接条件时幂等返回，条件见 _resumable_draft_package。
        existing = self.repository.find_package_by_name(data.name.strip())
        if existing is not None:
            resumed = self._resumable_draft_package(existing, data, submitter_id)
            if resumed is not None:
                return resumed
            raise ProducerServiceError(
                f"包名 '{data.name.strip()}' 已存在，请使用其他名称"
            )

        result = self.repository.create_package(
            name=data.name.strip(),
            type=data.type.value,
            description=data.description,
            submitter_id=submitter_id,
            license=data.license,
            keywords=data.keywords,
            category=data.category,
            homepage=_distinct_homepage(
                data.homepage,
                data.source.repository_url if data.source else None,
            ),
            icon_url=data.icon_url,
            author=data.author.model_dump(exclude_none=True) if data.author else None,
            permissions=data.permissions.model_dump() if data.permissions else None,
            use_cases=(
                [item.model_dump() for item in data.use_cases] if data.use_cases else None
            ),
            type_config=data.type_config,
            installation=data.installation.model_dump() if data.installation else None,
            dependencies=data.dependencies.model_dump() if data.dependencies else None,
            source=data.source.model_dump() if data.source else None,
            compatibility=self._normalize_compatibility(
                data.type.value, data.compatibility
            ),
            field_source=data.field_source,
        )
        return PackageResponse(
            id=result["id"],
            name=result["name"],
            type=result["type"],
            description=result["description"],
            status=result["status"],
            latest_version=result.get("latest_version"),
            license=result.get("license"),
            keywords=result.get("keywords", []),
            category=result.get("category"),
            author=result.get("author"),
            created_at=result.get("created_at"),
            updated_at=result.get("updated_at"),
        )

    # ── 创建版本 ──────────────────────────────────────────

    def _resumable_draft_package(
        self,
        existing: dict[str, object],
        data: CreatePackageRequest,
        submitter_id: str | None,
    ) -> PackageResponse | None:
        """中断续接：本人 draft 包 + 同源码地址时返回该包，否则 None。

        安全条件（全部满足才允许续接，防止同名劫持或误挂别的提交流程）：
        - 包状态为 draft 且 submitter_id 为当前用户；
        - 请求携带 source.repository_url（前端提交流程必然携带）；
        - 包下没有任何版本（刷新打断在建包之后、建版本之前），
          或存在 draft 版本且其 source.repository_url 与请求一致
          （刷新打断在建版本之后、submit 之前）。
        已提交/审核中的版本、或源码地址不匹配的 draft 包都不续接。
        """
        if existing.get("status") != "draft":
            return None
        if submitter_id is None or existing.get("submitter_id") != submitter_id:
            return None
        if data.source is None or not data.source.repository_url:
            return None
        request_url = _canonical_comparison_url(data.source.repository_url)
        if not request_url:
            return None
        package_id = str(existing.get("id") or "")
        if not package_id:
            return None
        versions = self.repository.list_package_versions(package_id)
        if not versions:
            return self._package_response(existing)
        for item in versions:
            if not isinstance(item, dict) or item.get("status") != "draft":
                continue
            version_row = self.repository.get_version(str(item.get("id") or ""))
            source = (
                version_row.get("source")
                if isinstance(version_row, dict)
                else None
            )
            version_url = (
                _canonical_comparison_url(
                    str(source.get("repository_url") or "")
                )
                if isinstance(source, dict)
                else ""
            )
            if version_url and version_url == request_url:
                return self._package_response(existing)
        return None

    @staticmethod
    def _package_response(data: dict[str, object]) -> PackageResponse:
        return PackageResponse(
            id=str(data["id"]),
            name=str(data["name"]),
            type=data["type"],  # type: ignore[arg-type]
            description=str(data["description"]),
            status=str(data.get("status") or "draft"),
            latest_version=data.get("latest_version"),
            license=data.get("license"),
            keywords=list(data.get("keywords") or []),
            category=data.get("category"),
            author=data.get("author"),  # type: ignore[arg-type]
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
        )

    def create_version(
        self, package_id: str, data: CreateVersionRequest, submitter_id: str | None = None
    ) -> dict[str, object]:
        # 校验包存在
        pkg = self.repository.get_package(package_id)
        if pkg is None:
            raise ProducerServiceError(f"包 {package_id} 不存在")
        package_type = str(pkg.get("type") or "skill")
        self._validate_installation_clients(package_type, data.installation)

        # 校验 SemVer
        if not _SEMVER_RE.match(data.version):
            raise ProducerServiceError(
                f"版本号 '{data.version}' 不符合 SemVer 规范（如 1.0.0）"
            )

        # 中断续接：本人 draft 版本按 (package, version) 命中时返回原版本；
        # 其余情况（他人/非 draft）明确报错，不再撞唯一约束 500。
        existing_version = self.repository.get_version_by_number(
            package_id, data.version
        )
        if isinstance(existing_version, dict) and existing_version.get("id"):
            if not (
                existing_version.get("status") == "draft"
                and submitter_id is not None
                and existing_version.get("submitter_id") == submitter_id
            ):
                raise ProducerServiceError(
                    f"包 '{pkg.get('name')}' 的版本 '{data.version}' 已存在"
                )
            return dict(existing_version)

        result = self.repository.create_version(
            package_id=package_id,
            version=data.version,
            submitter_id=submitter_id,
            repo_url=data.repo_url,
            description=data.description,
            author=data.author.model_dump(exclude_none=True) if data.author else None,
            license=data.license,
            source=data.source.model_dump() if data.source else None,
            integrity=data.integrity.model_dump() if data.integrity else None,
            permissions=data.permissions.model_dump() if data.permissions else None,
            use_cases=(
                [item.model_dump() for item in data.use_cases] if data.use_cases else None
            ),
            type_config=data.type_config,
            compatibility=self._normalize_compatibility(
                package_type, data.compatibility
            ),
            installation=data.installation.model_dump() if data.installation else None,
            dependencies=data.dependencies.model_dump() if data.dependencies else None,
            field_source=data.field_source,
        )
        return result

    # ── 提交审核 ──────────────────────────────────────────

    def submit_version(
        self,
        version_id: str,
        user_id: str | None = None,
        *,
        scan_task: dict[str, object],
    ) -> tuple[str, str | None, str]:
        """校验状态并触发扫描。

        Args:
            scan_task: 必填。仅 HTTP 路由调用此方法；内部不提供
                scan_task 的兜底路径，直接调用方必须携带完整任务身份，
                缺失即 TypeError（属 #132 清理的有意行为）。

        Returns:
            (repo_url_or_local_path, scan_id, next_status)
            next_status 恒为 "scanning"：版本行、扫描任务行与提交审计
            在同一次事务内落库。
        """
        version = self.repository.get_version(version_id)
        if version is None:
            raise ProducerServiceError(f"版本 {version_id} 不存在")

        current_status = version.get("status", "")

        if current_status in ("draft", "error"):
            validate_transition(current_status, "submitted")
        elif current_status in ("resubmitted", "changes_requested"):
            validate_transition(current_status, "scanning")
        else:
            if current_status in ("submitted", "scanning", "pending_review"):
                raise ProducerSubmissionConflict(
                    f"版本 '{version_id}' 已被其他请求提交，不能重复提交"
                )
            raise ProducerServiceError(
                f"无法提交审核：当前状态为 '{current_status}'，"
                f"仅 'draft'、'resubmitted'、'changes_requested' 或 'error' 状态可提交"
            )

        source = version.get("source")
        repo_url = (
            source.get("repository_url", "")
            if isinstance(source, dict)
            else ""
        )

        if not repo_url:
            raise ProducerServiceError(
                "版本缺少源码地址（source.repository_url），无法提交扫描"
            )

        scan_id = f"scan-{uuid.uuid4().hex[:12]}"
        owner_user_id = str(
            scan_task.get("owner_user_id") or user_id or ""
        )
        if not owner_user_id:
            raise ProducerServiceError(
                "缺少扫描任务所属用户，无法提交扫描"
            )
        existing_scan_id = str(
            scan_task.get("existing_scan_id") or ""
        ).strip()
        if existing_scan_id:
            try:
                self.repository.attach_scan_task_to_version(
                    scan_id=existing_scan_id,
                    version_id=version_id,
                    owner_user_id=owner_user_id,
                    expected_statuses={str(current_status)},
                    operator_id=user_id or "system",
                )
            except ValueError as exc:
                raise ProducerSubmissionConflict(str(exc)) from exc
            except LookupError as exc:
                raise ProducerServiceError(str(exc)) from exc
            except Exception as exc:
                raise ProducerPersistenceError(
                    "扫描任务与版本关联失败，版本状态未改变"
                ) from exc
            return repo_url, existing_scan_id, "scanning"

        client_request_id = str(
            scan_task.get("client_request_id")
            or f"producer:{version_id}:{scan_id}"
        )
        expires_at = scan_task.get("expires_at")
        if not isinstance(expires_at, datetime):
            expires_at = None
        source_ref = scan_task.get("source_ref")
        commit_hash = scan_task.get("commit_hash")
        source_subdirectory = scan_task.get("source_subdirectory")
        if (
            not isinstance(source_ref, str)
            or not source_ref.strip()
            or not isinstance(commit_hash, str)
            or not re.fullmatch(r"[0-9a-f]{40}", commit_hash.strip().lower())
        ):
            raise ProducerServiceError(
                "扫描任务缺少已解析的不可变源码提交身份"
            )
        if source_subdirectory is not None and not isinstance(
            source_subdirectory, str
        ):
            raise ProducerServiceError(
                "扫描任务的源码子目录无效"
            )
        try:
            self.repository.create_version_scan_task(
                version_id=version_id,
                scan_id=scan_id,
                owner_user_id=owner_user_id,
                client_request_id=client_request_id,
                repo_url=repo_url,
                source_ref=source_ref.strip(),
                commit_hash=commit_hash.strip().lower(),
                source_subdirectory=(
                    source_subdirectory.strip()
                    if isinstance(source_subdirectory, str)
                    and source_subdirectory.strip()
                    else None
                ),
                expected_statuses={str(current_status)},
                operator_id=user_id or "system",
                expires_at=expires_at,
            )
        except ValueError as exc:
            raise ProducerSubmissionConflict(str(exc)) from exc
        except LookupError as exc:
            raise ProducerServiceError(str(exc)) from exc
        except ScanTaskSourceConflictError as exc:
            raise ProducerSourceConflictError(
                "该源码已有扫描任务，不允许重复扫描；"
                "请先删除原扫描任务后再提交"
            ) from exc
        except Exception as exc:
            raise ProducerPersistenceError(
                "扫描任务持久化失败，版本状态未改变"
            ) from exc
        return repo_url, scan_id, "scanning"

    # ── 扫描完成回调 ──────────────────────────────────────

    def handle_scan_complete(
        self, version_id: str, full_report: dict[str, object]
    ) -> bool:
        """扫描流水线完成后回调：打包安装产物 + 写入扫描报告 + 更新状态。

        返回 ``True`` 仅表示完整报告已保存且版本状态已写入
        ``pending_review``；产物打包失败返回 ``False``，提交者可重新提交。
        """
        from src.services.artifacts import ArtifactError, build_artifact, force_rmtree

        scan_id = (
            str(full_report.get("scan_id")).strip()
            if full_report.get("scan_id") is not None
            else ""
        )
        completion_audit_key = (
            f"scan-complete:{scan_id}" if scan_id else None
        )
        # A callback can be replayed after the process dies between the
        # version update and the delivery marker.  Once this scan already
        # reached pending_review, only repair the idempotent audit record.
        if scan_id:
            existing_version = self.repository.get_version(version_id)
            existing_report = self.repository.get_scan_report(version_id)
            existing_scan_json = (
                existing_report.get("scan_json")
                if isinstance(existing_report, dict)
                else None
            )
            if (
                isinstance(existing_version, dict)
                and existing_version.get("status") == "pending_review"
                and isinstance(existing_scan_json, dict)
                and existing_scan_json.get("scan_id") == scan_id
            ):
                self.repository.create_audit_log(
                    action=AuditAction.SCAN_COMPLETE.value,
                    target_type="version",
                    target_id=version_id,
                    operator_id="system",
                    detail={"scan_id": scan_id},
                    idempotency_key=completion_audit_key,
                )
                return True

        raw_scan_report = full_report.get("scan_report", {})
        scan_report = (
            redact_report(raw_scan_report)
            if isinstance(raw_scan_report, dict)
            else {}
        )
        trust_score = full_report.get("trust_score", {})
        report_path = full_report.get("report_path", "")
        # 初始扫描保留的本地代码目录（打包产物时优先复用，不再重新拉取）
        local_source_dir = full_report.get("local_source_dir")
        source_reacquisition_attempted = (
            full_report.get("_source_reacquisition_attempted") is True
        )
        source_reacquisition_error = str(
            full_report.get("_source_reacquisition_error")
            or "无法按固定 commit 重新获取扫描源码"
        )
        acquisition_facts = full_report.get("acquisition_facts")
        package_claims = full_report.get("package_claims")

        # ── 生成安装产物（同步，失败则回退 error） ───────────
        version = self.repository.get_version(version_id)
        if version is None:
            if local_source_dir:
                force_rmtree(local_source_dir)
            # 版本行缺失同样是终态失败；此处已知 scan_id，直接终结扫描任务。
            if scan_id:
                self._terminalize_scan_task_on_packaging_failure(
                    scan_id,
                    "扫描版本记录不存在，请重新提交",
                )
            return False
        # Top-level integrity is a public server-owned projection. Clear
        # package-authored values before an install artifact is generated;
        # _apply_artifact_to_version writes the archive hash only for the
        # copy_directory path.
        provenance_updates: dict[str, object] = {"integrity": None}
        if isinstance(acquisition_facts, dict):
            safe_source = deepcopy(acquisition_facts.get("source") or {})
            provenance_updates.update(
                {
                    "source": safe_source,
                    "acquisition_facts": deepcopy(acquisition_facts),
                }
            )
        if isinstance(package_claims, dict):
            provenance_updates["provenance_claims"] = redact_report(
                deepcopy(package_claims)
            )
        self.repository.update_version_data(version_id, provenance_updates)
        version.update(provenance_updates)

        source = dict(version.get("source") or {})
        extracted_meta = full_report.get("package_metadata")
        acquired_source = None
        if isinstance(acquisition_facts, dict):
            acquired_source = acquisition_facts.get("source")
        if not isinstance(acquired_source, dict):
            acquired_source = (
                extracted_meta.get("source")
                if isinstance(extracted_meta, dict)
                else None
            )
        # Source identity is an acquisition fact.  It must supersede the
        # submitted URL/ref so the install manifest identifies the same
        # repository default branch and commit that were scanned.
        if isinstance(acquired_source, dict):
            for key in (
                "type",
                "repository_url",
                "owner",
                "repo",
                "ref_type",
                "ref",
                "commit_hash",
            ):
                value = acquired_source.get(key)
                if value not in (None, ""):
                    source[key] = value

        repo_url = str(source.get("repository_url", ""))
        commit_hash = full_report.get("commit_hash") or source.get(
            "commit_hash", ""
        )
        source_subdirectory = full_report.get("source_subdirectory") or (
            source.get("subdirectory", "")
        )
        if source_subdirectory:
            source["subdirectory"] = str(source_subdirectory)
        self.repository.update_version_data(version_id, {"source": source})
        version["source"] = source
        package = self.repository.get_package(version.get("package_id", ""))
        package_name = package.get("name", "") if package else ""
        pkg_version = version.get("version", "")
        install_method = str(
            (version.get("installation") or {}).get("method")
            or "copy_directory"
        )

        if install_method == "copy_directory":
            if repo_url and package_name and pkg_version:
                try:
                    if source_reacquisition_attempted and (
                        not isinstance(local_source_dir, str)
                        or not Path(local_source_dir).is_dir()
                    ):
                        raise ArtifactError(source_reacquisition_error)
                    artifact_kwargs = {
                        "repo_url": repo_url,
                        "commit_hash": str(commit_hash),
                        "package_name": package_name,
                        "version": str(pkg_version),
                        "local_source_dir": local_source_dir,
                    }
                    if source_subdirectory:
                        artifact_kwargs["source_subdirectory"] = str(source_subdirectory)
                    artifact = build_artifact(
                        **artifact_kwargs,
                    )
                    self._apply_artifact_to_version(
                        version_id,
                        artifact,
                        package_name,
                        pkg_version,
                        str(commit_hash),
                        str(source_subdirectory) if source_subdirectory else None,
                    )
                except ArtifactError as exc:
                    self.repository.update_version_status(
                        version_id, "error"
                    )
                    self.repository.update_version_data(
                        version_id,
                        {"scan_error": f"安装产物打包失败: {exc}"},
                    )
                    self.repository.create_audit_log(
                        action=AuditAction.SCAN_COMPLETE.value,
                        target_type="version",
                        target_id=version_id,
                        operator_id="system",
                        detail={
                            "scan_id": scan_id or None,
                            "error": f"artifact packaging failed: {exc}",
                        },
                        idempotency_key=completion_audit_key,
                    )
                    # Packaging failures are terminal and must not retry.
                    if scan_id:
                        self._terminalize_scan_task_on_packaging_failure(
                            scan_id,
                            f"安装产物打包失败: {exc}",
                        )
                    return False
        else:
            # npm/pip/docker/manual 不需要 ZIP 制品：
            # 按安装方式生成 manifest 步骤
            self._apply_installation_steps_to_version(
                version_id,
                package_name,
                pkg_version,
                install_method,
            )

        # 保存扫描报告
        scan_data: dict[str, object] = dict(scan_report) if isinstance(scan_report, dict) else {}
        scan_data.pop("file_contents", None)
        # 顶层 scan_id 统一为任务级 scan_id，与 SCAN_START / SCAN_COMPLETE
        # 审计日志的 detail.scan_id 一致，支持审计 → 报告全链路溯源
        task_scan_id = full_report.get("scan_id")
        if isinstance(task_scan_id, str) and task_scan_id:
            scan_data["scan_id"] = task_scan_id
        self.repository.save_scan_report(
            version_id=version_id,
            scan_json=scan_data,
            report_path=str(report_path) if report_path else None,
        )

        # 用扫描提取的真实 author/license 补齐版本元数据（手动值优先，占位值不写回）
        extracted_meta = full_report.get("package_metadata")
        if isinstance(extracted_meta, dict):
            _backfill_author_license(self.repository, version_id, extracted_meta)

        # 更新版本数据（附加完整信任评分信息）
        trust_data: dict[str, object] = trust_score if isinstance(trust_score, dict) else {}
        completed_at = datetime.now(timezone.utc).isoformat()
        self.repository.update_version_data(
            version_id,
            {
                "trust_score": trust_data,
                "submitted_at": completed_at,
                "trust_boundary": public_trust_boundary(
                    scan_data, scanned_at=completed_at
                ).model_dump(mode="json"),
            },
        )

        # 状态：scanning → pending_review
        try:
            self.repository.update_version_status(version_id, "pending_review")
            self.repository.create_audit_log(
                action=AuditAction.SCAN_COMPLETE.value,
                target_type="version",
                target_id=version_id,
                operator_id="system",
                detail={
                    "scan_id": scan_id or None,
                    "findings_count": (
                        scan_report.get("summary", {}).get("total", 0)
                        if isinstance(scan_report, dict)
                        else 0
                    ),
                    "trust_grade": trust_score.get("risk_summary", {}).get("grade")
                    if isinstance(trust_score, dict)
                    else None,
                    "llm_review": (
                        scan_report.get("llm_review", {}).get("labels_summary")
                        if isinstance(scan_report, dict)
                        else None
                    ),
                },
                idempotency_key=completion_audit_key,
            )
        except Exception as exc:
            error = f"扫描完成收尾失败: {type(exc).__name__}: {exc}"
            self._recover_scan_completion_failure(version_id, error)
            raise

        if local_source_dir:
            force_rmtree(local_source_dir)
        return True

    def _recover_scan_completion_failure(self, version_id: str, error: str) -> None:
        transition = getattr(
            self.repository,
            "transition_version_status_if_current",
            None,
        )
        expected_statuses = ("scanning", "pending_review")
        try:
            if callable(transition):
                transition(version_id, expected_statuses, "error")
            else:
                current = self.repository.get_version(version_id)
                if (
                    isinstance(current, dict)
                    and current.get("status") in expected_statuses
                ):
                    self.repository.update_version_status(version_id, "error")
        except Exception:
            logger.exception(
                "Could not compensate failed scan completion for %s",
                version_id,
            )
        try:
            self.repository.update_version_data(
                version_id,
                {"scan_error": error},
            )
        except Exception:
            logger.exception(
                "Could not persist failed scan completion for %s",
                version_id,
            )
        try:
            self.repository.create_audit_log(
                action=AuditAction.SCAN_COMPLETE.value,
                target_type="version",
                target_id=version_id,
                operator_id="system",
                detail={"error": error, "phase": "completion"},
            )
        except Exception:
            logger.exception(
                "Could not write failed scan completion audit for %s",
                version_id,
            )

    def _apply_artifact_to_version(
        self,
        version_id: str,
        artifact: dict[str, object],
        package_name: str,
        pkg_version: str,
        commit_hash: str,
        source_subdirectory: str | None = None,
    ) -> None:
        """把安装产物信息写回 version data（source/integrity/installation）。"""
        version = self.repository.get_version(version_id)
        if version is None:
            return
        data = dict(version)

        acquisition_facts = data.get("acquisition_facts")
        if isinstance(acquisition_facts, dict):
            source = dict(acquisition_facts.get("source") or {})
            integrity = dict(acquisition_facts.get("integrity") or {})
        else:
            source = dict(data.get("source") or {})
            integrity = {}
        source["download_url"] = artifact.get("download_url", "")
        if commit_hash and len(commit_hash) == 40:
            source["commit_hash"] = commit_hash
        if source_subdirectory:
            source["subdirectory"] = source_subdirectory
        data["source"] = source

        integrity["sha256"] = artifact.get("sha256", "")
        integrity["hash_scope"] = HASH_SCOPE_ARTIFACT_ARCHIVE
        integrity["is_complete"] = True
        integrity["download_size_bytes"] = artifact.get("download_size_bytes", 0)
        data["integrity"] = integrity

        package = self.repository.get_package(version.get("package_id", ""))
        package_type = str(package.get("type") or "skill") if package else "skill"
        allowed_clients = list(
            PACKAGE_TYPE_INSTALL_CLIENTS.get(package_type, ("claude-code",))
        )
        raw_compatibility = data.get("compatibility") or []
        if not isinstance(raw_compatibility, list):
            raw_compatibility = []
        compatibility = [
            str(c)
            for c in raw_compatibility
            if str(c) in allowed_clients
        ] or allowed_clients
        target_client = str(compatibility[0])
        data["compatibility"] = compatibility

        client_roots = PACKAGE_TYPE_INSTALL_ROOTS.get(
            package_type,
            PACKAGE_TYPE_INSTALL_ROOTS["skill"],
        )
        destination_root = client_roots.get(target_client, "~/.claude/skills/")
        archive_name = str(artifact.get("download_url", "")).rsplit("/", 1)[-1]
        data["installation"] = {
            "method": "copy_directory",
            "target_client": target_client,
            "targets": [
                {
                    "client": c,
                    "destination": f"{client_roots.get(c, '~/.claude/skills/')}{package_name}/",
                }
                for c in compatibility
            ],
            "steps": [
                {"action": "download", "url": artifact.get("download_url", "")},
                {"action": "verify", "algorithm": "sha256", "checksum": artifact.get("sha256", "")},
                {"action": "extract", "archive": archive_name},
                {"action": "copy", "source": package_name + "/", "destination": f"{destination_root}{package_name}/"},
            ],
            "pre_install_message": f"将安装 {package_name}@{pkg_version} 到 {target_client}",
            "post_install_message": "安装完成。请在客户端中确认工具可用。",
        }

        self.repository.update_version_data(version_id, data)

    def _apply_installation_steps_to_version(
        self,
        version_id: str,
        package_name: str,
        pkg_version: str,
        method: str,
    ) -> None:
        """为非 ZIP 安装方式生成 Manifest 安装步骤（npm/pip/docker/manual）。

        若提交的元数据已带同 action 的步骤，则保留；否则生成默认步骤。
        """
        version = self.repository.get_version(version_id)
        if version is None:
            return
        data = dict(version)
        installation = dict(data.get("installation") or {})
        existing_steps = installation.get("steps") or []
        if (
            existing_steps
            and isinstance(existing_steps[0], dict)
            and existing_steps[0].get("action") == method
        ):
            return

        target_client = (
            str(installation.get("target_client") or "")
            or str((data.get("compatibility") or ["claude-code"])[0])
        )
        if method == "npm_install":
            npm_package = str(installation.get("package") or package_name)
            step: dict[str, object] = {
                "action": "npm_install",
                "package": npm_package,
                "version": pkg_version,
                "registry": "https://registry.npmjs.org",
            }
        elif method == "pip_install":
            step = {
                "action": "pip_install",
                "package": package_name,
                "version": pkg_version,
                "index_url": "https://pypi.org/simple",
            }
        elif method == "docker_run":
            deps = data.get("dependencies") or {}
            docker_images = []
            if isinstance(deps, dict):
                docker = deps.get("docker") or []
                docker_images = [
                    str(item.get("image") or "")
                    for item in docker
                    if isinstance(item, dict) and item.get("image")
                ]
            image = docker_images[0] if docker_images else package_name
            step = {
                "action": "docker_run",
                "image": image,
                "tag": pkg_version,
                "ports": [],
                "volumes": [],
                "env": [],
            }
        else:  # manual_steps
            step = {
                "action": "manual_steps",
                "title": package_name,
                "text": (
                    str(installation.get("post_install_message") or "")
                    or f"请按 {package_name}@{pkg_version} 包说明手动安装"
                ),
            }

        installation["method"] = method
        installation["target_client"] = target_client
        installation["steps"] = [step]
        data["installation"] = installation
        self.repository.update_version_data(version_id, data)

    def handle_scan_error(
        self,
        version_id: str,
        error: str,
        *,
        scan_id: str | None = None,
    ) -> None:
        """扫描失败回调，支持按 scan_id 幂等重放。"""
        self.repository.update_version_status(version_id, "error")
        self.repository.update_version_data(
            version_id,
            {"scan_error": error},
        )
        self.repository.create_audit_log(
            action=AuditAction.SCAN_COMPLETE.value,
            target_type="version",
            target_id=version_id,
            operator_id="system",
            detail={"scan_id": scan_id, "error": error},
            idempotency_key=(
                f"scan-complete:{scan_id}" if scan_id else None
            ),
        )

    def _terminalize_scan_task_on_packaging_failure(
        self,
        scan_id: str,
        error: str,
    ) -> None:
        """Finalize a scan after a terminal completion-consumer failure."""
        from src.routers.trust import (
            _get_scan_task_repository,
            _remember_scan_info,
            _scan_retention_expiry,
            _update_scan_state,
        )

        repository = _get_scan_task_repository()
        if repository is not None:
            try:
                terminalized = repository.terminalize_scan_task_after_packaging_failure(
                    scan_id, error
                )
            except Exception:
                logger.exception(
                    "Failed to terminalize scan task %s after a packaging failure",
                    scan_id,
                )
                return
            if terminalized:
                task = repository.get_scan_task(scan_id)
                if task is not None:
                    from src.routers.trust import _scan_info_from_task

                    _remember_scan_info(_scan_info_from_task(task))
            return

        try:
            finished_at = datetime.now(timezone.utc)
            # 内存模式没有仓库层做原子降级；这里补上完成时间与保留期，
            # 与 terminalize_scan_task_after_packaging_failure 的语义对齐。
            _update_scan_state(
                scan_id,
                {
                    "status": "error",
                    "error": error,
                    "callback_status": "delivered",
                    "callback_next_attempt_at": None,
                    "callback_last_error": None,
                    "finished_at": finished_at.isoformat(),
                    "expires_at": _scan_retention_expiry(
                        finished_at.isoformat()
                    ),
                },
                required=True,
                allow_terminal_override=True,
            )
        except Exception:
            logger.exception(
                "Failed to terminalize in-memory scan task %s after a "
                "packaging failure",
                scan_id,
            )

    # ── 手动评级 ────────────────────────────────────────────

    def set_manual_grade(
        self,
        *,
        version_id: str,
        grade: str | None,
        reason: str,
        operator_id: str,
    ) -> dict[str, object]:
        """手动覆盖 / 修改 / 清除评级。

        grade 为 null 表示恢复自动评分。
        reason 必填。
        """
        if not reason or not reason.strip():
            raise ProducerServiceError("手动评级修改理由不能为空")

        valid_grades = {"A", "B", "C", "D", "E"}
        if grade is not None and grade.upper() not in valid_grades:
            raise ProducerServiceError(f"无效的评级: {grade}，允许: A/B/C/D/E")

        version = self.repository.get_version(version_id)
        if version is None:
            raise ProducerServiceError(f"版本 {version_id} 不存在")

        trust_data = version.get("trust_score", {})
        auto_grade = None
        if isinstance(trust_data, dict):
            risk_summary = trust_data.get("risk_summary", {})
            if isinstance(risk_summary, dict):
                auto_grade = risk_summary.get("grade")

        old_manual = self.repository.get_version(version_id)
        previous_manual_grade = None
        if old_manual:
            previous_manual_grade = old_manual.get("manual_grade")

        normalized_grade = grade.upper() if grade else None

        self.repository.set_manual_grade(
            version_id=version_id,
            grade=normalized_grade,
            operator_id=operator_id,
            reason=reason.strip(),
        )
        updated_version = self.repository.get_version(version_id) or {}
        manual_grade_at = updated_version.get("manual_grade_at")

        effective = normalized_grade or (auto_grade if isinstance(auto_grade, str) else None)

        # 如果已发布，同步 consumer 侧数据
        current_status = version.get("status", "")
        if current_status == "published" and effective:
            level = GRADE_TO_RISK_LEVEL.get(str(effective), "medium_risk")
            recommendation = GRADE_TO_RECOMMENDATION.get(str(effective), "caution")
            pkg_id = version.get("package_id", "")
            if pkg_id:
                self.repository.update_package_data(pkg_id, {
                    "grade": effective,
                    "risk_level": level,
                })
            model_version = (
                trust_data.get("model_version")
                if isinstance(trust_data, dict)
                else None
            )
            model_fingerprint = (
                trust_data.get("model_fingerprint")
                if isinstance(trust_data, dict)
                else None
            )
            self.repository.upsert_trust_level(
                version_id=version_id,
                level=level,
                recommendation=recommendation,
                model_version=model_version,
                model_fingerprint=model_fingerprint,
            )

        self.repository.create_audit_log(
            action="grade_override",
            target_type="version",
            target_id=version_id,
            operator_id=operator_id,
            detail={
                "previous_manual_grade": previous_manual_grade,
                "new_manual_grade": normalized_grade,
                "auto_grade": auto_grade,
                "reason": reason.strip(),
            },
        )

        return {
            "version_id": version_id,
            "auto_grade": auto_grade,
            "manual_grade": normalized_grade,
            "effective_grade": effective,
            "manual_grade_by": operator_id,
            "manual_grade_reason": reason.strip(),
            "manual_grade_at": manual_grade_at,
        }

    # ── 查询 ──────────────────────────────────────────────

    def get_package_detail(self, package_id: str) -> dict[str, object] | None:
        return self.repository.get_package(package_id)

    def get_version_detail(
        self,
        version_id: str,
        *,
        version: dict[str, object] | None = None,
        include_scan_report: bool = False,
        include_submitter_findings: bool = False,
    ) -> dict[str, object] | None:
        """Return version metadata with an authorized scan projection.

        ``include_scan_report`` is reserved for reviewer/admin consumers.
        ``include_submitter_findings`` is used only after the router has
        verified that the caller owns the version and returns a reduced,
        redacted finding projection.
        """
        if version is None:
            version = self.repository.get_version(version_id)
        if version is None:
            return None

        if not include_scan_report:
            for key in (
                "scan_report",
                "scan_file_contents",
                "findings",
                "source_snapshot_id",
                "acquisition_facts",
                "trust_score_refresh",
            ):
                version.pop(key, None)
            existing_summary = version.get("scan_summary")
            if isinstance(existing_summary, dict):
                legacy_findings = existing_summary.get("findings")
                version["scan_summary"] = {
                    key: value
                    for key, value in existing_summary.items()
                    if key != "findings"
                }
                if include_submitter_findings and isinstance(legacy_findings, list):
                    version["findings"] = _project_submitter_findings(
                        redact_report({"findings": legacy_findings})["findings"]
                    )

        # 附加扫描报告摘要
        scan = self.repository.get_scan_report(version_id)
        if scan:
            scan_json = scan.get("scan_json", {})
            if isinstance(scan_json, dict):
                safe_scan_json = redact_report(dict(scan_json))
                safe_scan_json.pop("file_contents", None)
                summary = safe_scan_json.get("summary", {})
                if isinstance(summary, dict):
                    # Exclude legacy embedded findings from the submitter summary.
                    version["scan_summary"] = {
                        key: value
                        for key, value in summary.items()
                        if key != "findings"
                    }
                report_findings = safe_scan_json.get("findings")
                if not isinstance(report_findings, list) and isinstance(summary, dict):
                    # Preserve findings from reports written before the field moved.
                    report_findings = summary.get("findings", [])
                if include_scan_report:
                    version["findings"] = (
                        report_findings if isinstance(report_findings, list) else []
                    )
                    version["source_snapshot_id"] = safe_scan_json.get(
                        "source_snapshot_id"
                    )
                    # Reviewers need the redacted report and its provenance metadata.
                    version["scan_report"] = safe_scan_json
                elif include_submitter_findings:
                    version["findings"] = _project_submitter_findings(
                        report_findings
                    )
        if isinstance(version.get("provenance_claims"), dict):
            # Redact claims persisted before write-time redaction was added.
            version["provenance_claims"] = redact_report(
                version["provenance_claims"]
            )
        # Submitters only need the status-page conclusion.
        if not version.get("trust_score"):
            version["trust_score"] = {"risk_summary": None}
        if not include_scan_report:
            version["trust_score"] = _project_submitter_trust_score(
                version.get("trust_score")
            )
        # 计算生效评级
        trust_data = version.get("trust_score", {})
        auto_grade = None
        if isinstance(trust_data, dict):
            risk_summary = trust_data.get("risk_summary", {})
            if isinstance(risk_summary, dict):
                auto_grade = risk_summary.get("grade")
        version["auto_grade"] = auto_grade
        version["effective_grade"] = version.get("manual_grade") or auto_grade
        return version

    def get_file_context(
        self,
        version_id: str,
        relative_path: str,
        *,
        line: int | None = None,
    ) -> dict[str, object]:
        """Load an authorized, redacted and bounded source context."""
        version = self.repository.get_version(version_id)
        if version is None:
            raise ProducerServiceError(f"版本 {version_id} 不存在")
        scan = self.repository.get_scan_report(version_id)
        scan_json = scan.get("scan_json", {}) if scan else {}
        snapshot_id = scan_json.get("source_snapshot_id") if isinstance(scan_json, dict) else None
        if not isinstance(snapshot_id, str) or not snapshot_id:
            raise ProducerServiceError("该版本没有可用的源码快照")

        # The HTTP route performs the version/package ownership check.  The
        # snapshot's owner_id remains audit metadata, but the attached
        # version is the authorization boundary so reviewer/admin access and
        # reused initial scans continue to work.
        context = _SOURCE_SNAPSHOT_STORE.load_context(
            snapshot_id,
            relative_path,
            line=line,
        )
        if context is None:
            raise ProducerServiceError("文件不存在、快照已过期或无权访问")
        return context

    def list_my_versions(
        self, submitter_id: str, limit: int = 50, offset: int = 0
    ) -> list[dict[str, object]]:
        """返回某个提交者的所有版本列表。"""
        return self.repository.list_versions_by_submitter(
            submitter_id, limit=limit, offset=offset
        )

    # ── 按状态筛选（审核员视图） ─────────────────────────

    _GRADE_LABELS: dict[str, str] = {
        "A": "高度可信", "B": "可信", "C": "需注意",
        "D": "有风险", "E": "高风险",
    }

    def list_versions_by_status(
        self,
        status: str | list[str] | None = None,
        grade: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, object]]:
        """按状态/风险等级/时间范围筛选版本列表（审核员视图用）。"""
        items = self.repository.list_versions_by_status(
            status=status,
            grade=grade,
            since=since,
            until=until,
            limit=limit,
            offset=offset,
        )
        for item in items:
            g = item.get("grade")
            item["grade_label"] = self._GRADE_LABELS.get(str(g)) if g else None
        return items

    def list_all_packages(
        self, limit: int = 200, offset: int = 0
    ) -> list[dict[str, object]]:
        """列出所有能力包（不限状态），供管理员查看。"""
        return self.repository.list_all_packages(limit=limit, offset=offset)

    def diff_versions(
        self, version_id: str, base_version_id: str | None = None
    ) -> dict[str, object]:
        current = self.repository.get_version(version_id)
        if current is None:
            raise ProducerServiceError(f"版本 {version_id} 不存在")

        current_data = {k: v for k, v in current.items() if k not in ("id", "created_at")}

        if base_version_id:
            base = self.repository.get_version(base_version_id)
            if base is None:
                raise ProducerServiceError(f"基准版本 {base_version_id} 不存在")
            if base.get("package_id") != current.get("package_id"):
                raise ProducerServiceError("两个版本不属于同一个包，无法对比")
        else:
            base = self.repository.get_previous_version(version_id)

        if base is None:
            return {
                "current": {
                    "version_id": current.get("id"),
                    "version": current.get("version"),
                    "source_url": (current.get("source", {}) or {}).get("repository_url", "")
                    if isinstance(current.get("source"), dict) else "",
                },
                "base": None,
                "diff": None,
                "code_diff": None,
                "message": "当前是该包唯一的版本（首版），无上一版本可对比。可通过 ?base={version_id} 显式指定基准版本。",
            }

        base_data = {k: v for k, v in base.items() if k not in ("id", "created_at")}
        diff_result = _deep_diff(base_data, current_data)

        current_files = _get_file_contents(self.repository, current.get("id", ""))
        base_files = _get_file_contents(self.repository, base.get("id", ""))
        code_diff = _compute_code_diff(base_files, current_files)

        return {
            "current": {
                "version_id": current.get("id"),
                "version": current.get("version"),
                "source_url": (current.get("source", {}) or {}).get("repository_url", "")
                if isinstance(current.get("source"), dict) else "",
            },
            "base": {
                "version_id": base.get("id"),
                "version": base.get("version"),
                "source_url": (base.get("source", {}) or {}).get("repository_url", "")
                if isinstance(base.get("source"), dict) else "",
            },
            "diff": diff_result,
            "code_diff": code_diff,
        }

    def review_version(
        self,
        *,
        version_id: str,
        conclusion: str,
        comment: str | None = None,
        reviewer_id: str = "system",
    ) -> "ReviewResponse":
        """审核员对版本提交审核结论。"""
        from src.models.producer import ReviewResponse

        version = self.repository.get_version(version_id)
        if version is None:
            raise ProducerServiceError(f"版本 {version_id} 不存在")

        current = version.get("status", "")
        # 确定目标状态
        from schema.constants import ReviewConclusion, AuditAction
        if conclusion == ReviewConclusion.APPROVED.value:
            target = "approved"
        elif conclusion == ReviewConclusion.REJECTED.value:
            target = "rejected"
        elif conclusion == ReviewConclusion.CHANGES_REQUESTED.value:
            target = "changes_requested"
        else:
            raise ProducerServiceError(
                f"未知审核结论 '{conclusion}'，允许：approved / rejected / changes_requested"
            )

        # 校验状态跳转
        validate_transition(current, target)

        # 驳回和要求修改时必须填写意见
        if conclusion in (ReviewConclusion.REJECTED.value, ReviewConclusion.CHANGES_REQUESTED.value):
            if not comment or not comment.strip():
                raise ProducerServiceError(
                    f"结论为 '{conclusion}' 时，审核意见不能为空"
                )

        # 写入审核记录
        self.repository.create_review_record(
            version_id=version_id,
            reviewer_id=reviewer_id,
            conclusion=conclusion,
            comment=comment,
        )

        # 更新版本状态
        self.repository.update_version_status(version_id, target)

        # 将审核结论写入版本 data JSON（供前端版本详情页直接读取）
        self.repository.update_version_data(version_id, {"review_conclusion": conclusion})

        # 写入审计日志：结论映射到 AuditAction 常量（approve / reject / request_changes），
        # 保证审计 action 与枚举和前端过滤器一致
        if conclusion == ReviewConclusion.APPROVED.value:
            audit_action = AuditAction.APPROVE.value
        elif conclusion == ReviewConclusion.REJECTED.value:
            audit_action = AuditAction.REJECT.value
        else:
            audit_action = AuditAction.REQUEST_CHANGES.value
        self.repository.create_audit_log(
            action=audit_action,
            target_type="version",
            target_id=version_id,
            operator_id=reviewer_id,
            detail={
                "conclusion": conclusion,
                "comment": comment,
                "previous_status": current,
            },
        )

        return ReviewResponse(
            version_id=version_id,
            conclusion=conclusion,
            new_status=target,
            message=f"审核完成：{target}",
        )

    def publish_version(
        self,
        *,
        version_id: str,
        operator_id: str = "system",
    ) -> "ReviewResponse":
        """管理员发布上线：approved → published，同时将包状态同步为 published。"""
        from src.models.producer import ReviewResponse
        from schema.constants import AuditAction

        version = self.repository.get_version(version_id)
        if version is None:
            raise ProducerServiceError(f"版本 {version_id} 不存在")

        current = version.get("status", "")
        target = "published"
        validate_transition(current, target)

        # ── Pre-publish install validation ────────────────────
        package = self.repository.get_package(version.get("package_id", ""))
        package_type = str(package.get("type") or "skill") if package else "skill"
        missing = _validate_install_readiness(version, package_type)
        if missing:
            # 兜底：安装资料缺失/产物丢失时尝试补打包
            if self._try_rebuild_artifact(version_id):
                version = self.repository.get_version(version_id)
                missing = _validate_install_readiness(version, package_type)
            if missing:
                raise ProducerServiceError(
                    f"版本安装资料不完整，无法发布。缺失字段: {', '.join(missing)}"
                )

        package_id = version.get("package_id", "")
        pkg_version = version.get("version", "")

        self.repository.update_version_status(version_id, target)
        self.repository.update_version_data(
            version_id,
            {"published_at": datetime.now(timezone.utc).isoformat()},
        )

        # 计算生效评级并同步到 consumer 侧
        trust_data = version.get("trust_score", {})
        auto_grade = None
        if isinstance(trust_data, dict):
            risk_summary = trust_data.get("risk_summary", {})
            if isinstance(risk_summary, dict):
                auto_grade = risk_summary.get("grade")
        effective_grade = version.get("manual_grade") or auto_grade

        # 从 effective_grade 计算 level 和 recommendation
        if effective_grade:
            level = GRADE_TO_RISK_LEVEL.get(str(effective_grade), "medium_risk")
            recommendation = GRADE_TO_RECOMMENDATION.get(str(effective_grade), "caution")
        else:
            level = "medium_risk"
            recommendation = "caution"

        # 同步更新包状态和最新版本号
        if package_id:
            self.repository.update_package_status(
                package_id, "published", latest_version=pkg_version,
            )
            # 同步 consumer 侧 packages.data.grade 和 risk_level
            if effective_grade:
                self.repository.update_package_data(
                    package_id, {
                        "grade": effective_grade,
                        "risk_level": level,
                    }
                )
            # 同步 consumer 侧 trust_levels
            model_version = (
                trust_data.get("model_version")
                if isinstance(trust_data, dict)
                else None
            )
            model_fingerprint = (
                trust_data.get("model_fingerprint")
                if isinstance(trust_data, dict)
                else None
            )
            self.repository.upsert_trust_level(
                version_id=version_id,
                level=level,
                recommendation=recommendation,
                model_version=model_version,
                model_fingerprint=model_fingerprint,
            )

        self.repository.create_audit_log(
            action=AuditAction.PUBLISH.value,
            target_type="version",
            target_id=version_id,
            operator_id=operator_id,
        )

        # 发布后使用真实审核信号重算信任评分
        # （manual_review / user_feedback 维度反映发布后的平台数据）
        try:
            from src.services.trust_refresh import TrustScoreRefreshService

            TrustScoreRefreshService(self.repository).refresh(version_id)
        except Exception:
            logger.exception(
                "trust score refresh failed after publish for %s",
                version_id,
            )

        return ReviewResponse(
            version_id=version_id,
            new_status=target,
            message="版本已发布上线",
        )

    def _try_rebuild_artifact(self, version_id: str) -> bool:
        """发布兜底：安装资料缺失/产物丢失时补打包。成功返回 True。"""
        from src.models.common import require_safe_source_subdirectory
        from src.routers.trust import (
            _acquire_repo_source,
            _normalized_commit_hash,
            _parse_github_url,
        )
        from src.services.artifacts import build_artifact, force_rmtree

        version = self.repository.get_version(version_id)
        if version is None:
            return False
        source = version.get("source", {})
        source = source if isinstance(source, dict) else {}
        acquisition_facts = version.get("acquisition_facts")
        acquired_source = (
            acquisition_facts.get("source")
            if isinstance(acquisition_facts, dict)
            else None
        )
        acquired_source = acquired_source if isinstance(acquired_source, dict) else {}
        repo_url = source.get("repository_url") or acquired_source.get("repository_url")
        commit_hash = source.get("commit_hash") or acquired_source.get("commit_hash")
        source_subdirectory = source.get("subdirectory")
        if source_subdirectory is None:
            source_subdirectory = acquired_source.get("subdirectory")
        if not isinstance(repo_url, str) or not repo_url.strip():
            return False
        normalized_commit = _normalized_commit_hash(commit_hash)
        if normalized_commit is None:
            return False
        if source_subdirectory in (None, "", "."):
            normalized_subdirectory = None
        elif isinstance(source_subdirectory, str):
            try:
                normalized_subdirectory = require_safe_source_subdirectory(
                    source_subdirectory.strip()
                )
            except ValueError:
                return False
        else:
            return False

        package = self.repository.get_package(version.get("package_id", ""))
        package_name = package.get("name", "") if package else ""
        pkg_version = version.get("version", "")
        if not package_name or not pkg_version:
            return False

        local_source_dir: str | None = None
        try:
            # Reuse the scanner's bounded, optionally authenticated GitHub
            # acquisition path. Supplying commit_hash is important: this
            # descriptor must never resolve a moving default branch again.
            parsed_source = _parse_github_url(repo_url)
            parsed_source.update(
                {
                    "tree_path": None,
                    "ref": normalized_commit,
                    "subdir": normalized_subdirectory,
                    "commit_hash": normalized_commit,
                    "repository_verified": True,
                    "repository_resolved": True,
                }
            )
            local_source_dir, _method, acquired_commit = _acquire_repo_source(
                parsed_source
            )
            if not local_source_dir or acquired_commit != normalized_commit:
                return False
            artifact_kwargs = {
                "repo_url": repo_url,
                "commit_hash": normalized_commit,
                "package_name": str(package_name),
                "version": str(pkg_version),
                "local_source_dir": local_source_dir,
            }
            if normalized_subdirectory:
                artifact_kwargs["source_subdirectory"] = normalized_subdirectory
            artifact = build_artifact(**artifact_kwargs)
        except Exception as exc:
            logger.warning(
                "artifact rebuild source acquisition failed for %s: %s",
                version_id,
                exc,
            )
            return False
        finally:
            if local_source_dir:
                force_rmtree(local_source_dir)

        self._apply_artifact_to_version(
            version_id,
            artifact,
            str(package_name),
            str(pkg_version),
            normalized_commit,
            normalized_subdirectory,
        )
        return True

    def cleanup_orphan_artifacts(self) -> int:
        """惰性清理 /artifacts 中的孤儿产物。

        保留集：非 rejected/error 状态版本引用的 zip（兼容 v2 和旧文件名）；
        删除：rejected/error 版本、已删除版本遗留的 zip。返回删除数量。
        """
        from src.services.artifacts import ARTIFACTS_ROOT

        keep: set[str] = set()
        for v in self.repository.list_artifact_versions():
            status = v.get("status", "")
            if status in ("rejected", "error"):
                continue
            source = v.get("source") or {}
            commit = source.get("commit_hash", "") if isinstance(source, dict) else ""
            name = v.get("package_name") or ""
            version = v.get("version") or ""
            if name and version and len(commit) >= 8:
                keep.add(f"{name}-{version}-{commit[:8]}-v2.zip")
                keep.add(f"{name}-{version}-{commit[:8]}.zip")
            if isinstance(source, dict):
                download_url = source.get("download_url")
                if isinstance(download_url, str):
                    referenced_name = urlparse(download_url).path.rsplit("/", 1)[-1]
                    if referenced_name.endswith(".zip"):
                        keep.add(referenced_name)

        deleted = 0
        if ARTIFACTS_ROOT.is_dir():
            for zip_path in ARTIFACTS_ROOT.glob("*.zip"):
                if zip_path.name not in keep:
                    try:
                        zip_path.unlink()
                        deleted += 1
                    except OSError:
                        pass
        return deleted

    def yank_version(
        self,
        *,
        version_id: str,
        operator_id: str = "system",
        reason: str | None = None,
    ) -> "ReviewResponse":
        """管理员下架：published → yanked。"""
        from src.models.producer import ReviewResponse
        from schema.constants import AuditAction

        version = self.repository.get_version(version_id)
        if version is None:
            raise ProducerServiceError(f"版本 {version_id} 不存在")

        current = version.get("status", "")
        target = "yanked"
        validate_transition(current, target)

        package_id = version.get("package_id", "")
        pkg_version = version.get("version", "")
        self.repository.update_version_status(version_id, target)
        self.repository.update_version_data(version_id, {"yank_reason": reason} if reason else {})
        # 下架的是当前最新版本时，同步包状态为 yanked，消费侧不再暴露该包
        if package_id:
            pkg = self.repository.get_package(package_id)
            if pkg and pkg.get("latest_version") == pkg_version:
                self.repository.update_package_status(package_id, "yanked")
        self.repository.create_audit_log(
            action=AuditAction.YANK.value,
            target_type="version",
            target_id=version_id,
            operator_id=operator_id,
            detail={"reason": reason} if reason else None,
        )

        return ReviewResponse(
            version_id=version_id,
            new_status=target,
            message=f"版本已下架{f'（原因：{reason}）' if reason else ''}",
        )

    def unyank_version(
        self,
        *,
        version_id: str,
        operator_id: str = "system",
    ) -> "ReviewResponse":
        """管理员撤销下架：yanked → published。"""
        from src.models.producer import ReviewResponse
        from schema.constants import AuditAction

        version = self.repository.get_version(version_id)
        if version is None:
            raise ProducerServiceError(f"版本 {version_id} 不存在")

        current = version.get("status", "")
        target = "published"
        validate_transition(current, target)

        package_id = version.get("package_id", "")
        pkg_version = version.get("version", "")
        self.repository.update_version_status(version_id, target)
        self.repository.update_version_data(version_id, {"yank_reason": None})
        # 撤销下架的版本仍是包的最新版本时，恢复包为 published
        if package_id:
            pkg = self.repository.get_package(package_id)
            if pkg and pkg.get("latest_version") == pkg_version:
                self.repository.update_package_status(package_id, "published")
        self.repository.create_audit_log(
            action=AuditAction.UNYANK.value if hasattr(AuditAction, 'UNYANK') else "unyank",
            target_type="version",
            target_id=version_id,
            operator_id=operator_id,
        )

        return ReviewResponse(
            version_id=version_id,
            new_status=target,
            message="版本已撤销下架，恢复为已发布",
        )

    def re_review_version(
        self,
        *,
        version_id: str,
        operator_id: str = "system",
    ) -> "ReviewResponse":
        """管理员将已发布版本退回审核队列：published → pending_review。"""
        from src.models.producer import ReviewResponse

        version = self.repository.get_version(version_id)
        if version is None:
            raise ProducerServiceError(f"版本 {version_id} 不存在")

        current = version.get("status", "")
        target = "pending_review"
        validate_transition(current, target)

        self.repository.update_version_status(version_id, target)
        self.repository.update_version_data(version_id, {"yank_reason": None})
        self.repository.create_audit_log(
            action="re_review",
            target_type="version",
            target_id=version_id,
            operator_id=operator_id,
        )

        return ReviewResponse(
            version_id=version_id,
            new_status=target,
            message="版本已退回审核队列",
        )

    def delete_version(
        self,
        *,
        version_id: str,
        operator_id: str = "system",
    ) -> "ReviewResponse":
        """管理员删除版本（不可逆）。"""
        from src.models.producer import ReviewResponse
        from schema.constants import AuditAction

        version = self.repository.get_version(version_id)
        if version is None:
            raise ProducerServiceError(f"版本 {version_id} 不存在")

        self.repository.delete_version(version_id)
        self.repository.create_audit_log(
            action="delete_version",
            target_type="version",
            target_id=version_id,
            operator_id=operator_id,
            detail={"version": version.get("version", ""), "package_name": version.get("package_name", "")},
        )

        return ReviewResponse(
            version_id=version_id,
            new_status="deleted",
            message="版本已删除",
        )


# ── 模块级函数 ──────────────────────────────────────────


def validate_transition(current: str, target: str) -> None:
    """校验状态跳转是否合法，不合法抛 ProducerServiceError。"""
    allowed = STATUS_TRANSITIONS.get(current, [])
    if target not in allowed:
        raise ProducerServiceError(
            f"状态跳转非法：'{current}' → '{target}' 不在允许的跳转列表中"
        )


def _get_file_contents(repo: ProducerRepository, version_id: str) -> dict[str, str]:
    """从独立 SourceSnapshotStore 加载版本源代码，绝不从 scan_json 读取。"""
    scan = repo.get_scan_report(version_id)
    if not scan:
        return {}
    scan_json = scan.get("scan_json", {})
    if not isinstance(scan_json, dict):
        return {}
    snapshot_id = scan_json.get("source_snapshot_id")
    if not isinstance(snapshot_id, str) or not snapshot_id:
        return {}
    return _SOURCE_SNAPSHOT_STORE.load_for_diff(snapshot_id)


def _compute_code_diff(
    base_files: dict[str, str],
    current_files: dict[str, str],
) -> dict[str, object]:
    """对比两个版本的 file_contents，返回代码级差异。

    Returns:
        {
            files_added: [str],
            files_removed: [str],
            files_modified: [{path, base_content, current_content, diff_hunks}],
            files_unchanged: int,
            summary: str,
        }
    """
    base_paths = set(base_files.keys())
    current_paths = set(current_files.keys())

    files_added = sorted(current_paths - base_paths)
    files_removed = sorted(base_paths - current_paths)
    files_common = sorted(base_paths & current_paths)

    files_modified: list[dict[str, object]] = []
    files_unchanged = 0

    for path in files_common:
        base_text = base_files.get(path, "")
        current_text = current_files.get(path, "")
        if base_text == current_text:
            files_unchanged += 1
            continue

        base_lines = base_text.splitlines(keepends=True)
        current_lines = current_text.splitlines(keepends=True)
        diff_lines = list(
            difflib.unified_diff(
                base_lines, current_lines,
                fromfile=f"a/{path}", tofile=f"b/{path}",
                lineterm="",
            )
        )
        files_modified.append({
            "path": path,
            "base_content": base_text,
            "current_content": current_text,
            "diff_hunks": diff_lines,
        })

    total_changes = len(files_added) + len(files_removed) + len(files_modified)
    summary_parts = []
    if files_added:
        summary_parts.append(f"{len(files_added)} 个文件新增")
    if files_removed:
        summary_parts.append(f"{len(files_removed)} 个文件删除")
    if files_modified:
        summary_parts.append(f"{len(files_modified)} 个文件修改")
    if not summary_parts:
        summary_parts.append("无变更")

    return {
        "files_added": files_added,
        "files_removed": files_removed,
        "files_modified": files_modified,
        "files_unchanged": files_unchanged,
        "summary": "，".join(summary_parts),
    }


def _deep_diff(
    base: dict[str, object],
    current: dict[str, object],
    prefix: str = "",
) -> dict[str, object]:
    """递归对比两个字典，返回 added / removed / changed。"""
    added: dict[str, object] = {}
    removed: dict[str, object] = {}
    changed: dict[str, object] = {}

    all_keys = set(base.keys()) | set(current.keys())

    for key in sorted(all_keys):
        full_key = f"{prefix}.{key}" if prefix else key
        in_base = key in base
        in_current = key in current

        if not in_base and in_current:
            added[full_key] = current[key]
        elif in_base and not in_current:
            removed[full_key] = base[key]
        elif in_base and in_current:
            bv = base[key]
            cv = current[key]
            if isinstance(bv, dict) and isinstance(cv, dict):
                sub = _deep_diff(bv, cv, prefix=full_key)
                if sub["added"]:
                    added.update(sub["added"])
                if sub["removed"]:
                    removed.update(sub["removed"])
                if sub["changed"]:
                    changed.update(sub["changed"])
            elif bv != cv:
                changed[full_key] = {"old": bv, "new": cv}

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "added_count": len(added),
        "removed_count": len(removed),
        "changed_count": len(changed),
    }


# ── Install readiness validation ──────────────────────────────

_REQUIRED_INSTALL_FIELDS = [
    ("compatibility", None),
    ("permissions", None),
    ("installation.method", "installation"),
    ("installation.target_client", "installation"),
    ("installation.steps", "installation"),
]


def _validate_install_readiness(
    version: dict[str, object],
    package_type: str = "skill",
) -> list[str]:
    """Check that a version has all required install-manifest fields.

    Returns a list of human-readable missing-field descriptions.
    """
    missing: list[str] = []
    installation = version.get("installation")
    method = (
        installation.get("method")
        if isinstance(installation, dict)
        else None
    )
    fields = list(_REQUIRED_INSTALL_FIELDS)
    # 仅目录复制方式需要可下载 ZIP 制品与完整性摘要；
    # npm/pip/docker/manual 由各自安装步骤承载。
    if method == "copy_directory":
        fields += [
            ("source.download_url", "source"),
            ("source.commit_hash", "source"),
            ("integrity.sha256", "integrity"),
            ("integrity.download_size_bytes", "integrity"),
        ]

    for field_path, parent_key in fields:
        if parent_key is None:
            # Top-level field
            val = version.get(field_path)
            if not val or (isinstance(val, list) and len(val) == 0):
                missing.append(field_path)
        else:
            parent = version.get(parent_key)
            if not isinstance(parent, dict):
                missing.append(field_path)
                continue
            field_name = field_path.split(".", 1)[1]
            val = parent.get(field_name)
            if val is None or val == "" or (isinstance(val, list) and len(val) == 0):
                missing.append(field_path)

    # compatibility must match the package type's allowed install clients
    compat = version.get("compatibility")
    if isinstance(compat, list):
        allowed = PACKAGE_TYPE_INSTALL_CLIENTS.get(package_type, ())
        invalid = [str(c) for c in compat if str(c) not in allowed]
        if invalid:
            missing.append(
                f"compatibility (type '{package_type}' 不允许: "
                f"{', '.join(invalid)})"
            )

    # effective_grade check
    auto_grade = None
    trust_data = version.get("trust_score", {})
    if isinstance(trust_data, dict):
        rs = trust_data.get("risk_summary", {})
        if isinstance(rs, dict):
            auto_grade = rs.get("grade")
    manual_grade = version.get("manual_grade")
    effective = manual_grade or auto_grade
    if effective == "E":
        missing.append("effective_grade=E (blocked)")

    return missing


# ── ProducerService: 审核与发布 ────────────────────────────


