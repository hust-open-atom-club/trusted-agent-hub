"""供给侧业务逻辑 — 状态机校验、扫描触发协调。"""

from __future__ import annotations

import difflib
import logging
import re
from copy import deepcopy
from datetime import datetime, timezone
from urllib.parse import urlparse

from src.repositories.producer_sqlalchemy import ProducerRepository
from src.services.source_snapshots import SourceSnapshotStore
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
    HASH_SCOPE_ARTIFACT_ARCHIVE,
)

_SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)

logger = logging.getLogger(__name__)
_SOURCE_SNAPSHOT_STORE = SourceSnapshotStore()


def _author_has_real_name(author: object) -> bool:
    """author 是否含真实姓名（缺失 / UNKNOWN 占位 → False）。"""
    if not isinstance(author, dict):
        return False
    name = str(author.get("name") or "").strip()
    return bool(name) and name.upper() != "UNKNOWN"


def _backfill_author_license(
    repository: ProducerRepository,
    version_id: str,
    extracted: dict[str, object],
) -> None:
    """用扫描提取的真实 author/license 补齐版本元数据。

    规则：手动值优先（已有真实值不覆盖）；提取器的占位兜底值
    （UNKNOWN / UNLICENSED / 空）不写回，避免污染数据。
    """
    version = repository.get_version(version_id)
    if not version:
        return

    updates: dict[str, object] = {}

    if not _author_has_real_name(version.get("author")):
        new_author = extracted.get("author")
        if _author_has_real_name(new_author):
            updates["author"] = new_author

    current_license = str(version.get("license") or "").strip()
    if not current_license or current_license.upper() in ("NONE", "UNLICENSED"):
        new_license = str(extracted.get("license") or "").strip()
        if new_license and new_license.upper() not in ("NONE", "UNLICENSED", "UNKNOWN"):
            updates["license"] = new_license

    if updates:
        repository.update_version_data(version_id, updates)


class ProducerServiceError(Exception):
    """供给侧业务逻辑错误。"""


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

    # ── 创建包 ────────────────────────────────────────────

    def create_package(
        self, data: CreatePackageRequest, submitter_id: str | None = None
    ) -> PackageResponse:
        if not data.name or not data.name.strip():
            raise ProducerServiceError("包名称不能为空")
        if not data.description:
            raise ProducerServiceError("包描述不能为空")

        # 检查包名重复
        if self.repository.package_name_exists(data.name.strip()):
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
            homepage=data.homepage,
            icon_url=data.icon_url,
            author=data.author.model_dump() if data.author else None,
            permissions=data.permissions.model_dump() if data.permissions else None,
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

    def create_version(
        self, package_id: str, data: CreateVersionRequest, submitter_id: str | None = None
    ) -> dict[str, object]:
        # 校验包存在
        pkg = self.repository.get_package(package_id)
        if pkg is None:
            raise ProducerServiceError(f"包 {package_id} 不存在")
        package_type = str(pkg.get("type") or "skill")

        # 校验 SemVer
        if not _SEMVER_RE.match(data.version):
            raise ProducerServiceError(
                f"版本号 '{data.version}' 不符合 SemVer 规范（如 1.0.0）"
            )

        result = self.repository.create_version(
            package_id=package_id,
            version=data.version,
            submitter_id=submitter_id,
            repo_url=data.repo_url,
            description=data.description,
            author=data.author.model_dump() if data.author else None,
            license=data.license,
            source=data.source.model_dump() if data.source else None,
            integrity=data.integrity.model_dump() if data.integrity else None,
            permissions=data.permissions.model_dump() if data.permissions else None,
            compatibility=self._normalize_compatibility(
                package_type, data.compatibility
            ),
            installation=data.installation.model_dump() if data.installation else None,
            dependencies=data.dependencies.model_dump() if data.dependencies else None,
            field_source=data.field_source,
        )
        return result

    # ── 提交审核 ──────────────────────────────────────────

    def submit_version(self, version_id: str, user_id: str | None = None) -> tuple[str, str | None, str]:
        """校验状态并触发扫描。

        Returns:
            (repo_url_or_local_path, scan_id, next_status)
            next_status 告知调用方当前版本所处的中间状态：
            - draft → "submitted"（需 router 进一步置为 scanning）
            - resubmitted / changes_requested / error → "scanning"（一跳直达）
        """
        version = self.repository.get_version(version_id)
        if version is None:
            raise ProducerServiceError(f"版本 {version_id} 不存在")

        current_status = version.get("status", "")

        # 统一走状态机校验；根据当前状态决定中间跳
        if current_status in ("draft", "error"):
            validate_transition(current_status, "submitted")
            next_status = "submitted"
        elif current_status in ("resubmitted", "changes_requested"):
            validate_transition(current_status, "scanning")
            next_status = "scanning"
        else:
            raise ProducerServiceError(
                f"无法提交审核：当前状态为 '{current_status}'，"
                f"仅 'draft'、'resubmitted'、'changes_requested' 或 'error' 状态可提交"
            )

        # 提取源码路径
        source = version.get("source", {})
        repo_url = source.get("repository_url", "") if isinstance(source, dict) else ""

        # 重新扫描只更新 auto_grade，保留 manual_grade
        # effective_grade 继续优先使用人工评级

        if not repo_url:
            raise ProducerServiceError(
                "版本缺少源码地址（source.repository_url），无法提交扫描"
            )

        # 更新状态
        self.repository.update_version_status(version_id, next_status)
        self.repository.create_audit_log(
            action=AuditAction.SUBMIT.value,
            target_type="version",
            target_id=version_id,
            operator_id=user_id or "system",
        )

        # 生成 scan_id（由 router 层传给 _run_scan_task）
        import uuid
        scan_id = f"scan-{uuid.uuid4().hex[:12]}"
        return repo_url, scan_id, next_status

    # ── 扫描完成回调 ──────────────────────────────────────

    def handle_scan_complete(
        self, version_id: str, full_report: dict[str, object]
    ) -> None:
        """扫描流水线完成后回调：打包安装产物 + 写入扫描报告 + 更新状态。

        打包失败视为提交流程失败：状态回退 error，提交者可重新提交。
        """
        from src.services.artifacts import ArtifactError, build_artifact, force_rmtree

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
        acquisition_facts = full_report.get("acquisition_facts")
        package_claims = full_report.get("package_claims")

        # ── 生成安装产物（同步，失败则回退 error） ───────────
        version = self.repository.get_version(version_id)
        if version is not None:
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
                                "error": f"artifact packaging failed: {exc}"
                            },
                        )
                        return
                    finally:
                        # 无论打包成功与否，扫描遗留的代码目录均已消费，清理之
                        if local_source_dir:
                            force_rmtree(local_source_dir)
                elif local_source_dir:
                    force_rmtree(local_source_dir)
            else:
                # npm/pip/docker/manual 不需要 ZIP 制品：
                # 按安装方式生成 manifest 步骤
                self._apply_installation_steps_to_version(
                    version_id,
                    package_name,
                    pkg_version,
                    install_method,
                )
                if local_source_dir:
                    force_rmtree(local_source_dir)

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
        self.repository.update_version_data(
            version_id,
            {
                "trust_score": trust_data,
                "submitted_at": datetime.now(timezone.utc).isoformat(),
            },
        )

        # 状态：scanning → pending_review
        self.repository.update_version_status(version_id, "pending_review")
        self.repository.create_audit_log(
            action=AuditAction.SCAN_COMPLETE.value,
            target_type="version",
            target_id=version_id,
            operator_id="system",
            detail={
                "scan_id": full_report.get("scan_id"),
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

        client_roots = {
            "claude-code": "~/.claude/skills/",
            "claude-code-plugin": "~/.claude/skills/",
            "cursor": "~/.cursor/skills/",
        }
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

    def handle_scan_error(self, version_id: str, error: str) -> None:
        """扫描失败回调。"""
        self.repository.update_version_status(version_id, "error")
        self.repository.update_version_data(version_id, {"scan_error": error})
        self.repository.create_audit_log(
            action=AuditAction.SCAN_COMPLETE.value,
            target_type="version",
            target_id=version_id,
            operator_id="system",
            detail={"error": error},
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
        }

    # ── 查询 ──────────────────────────────────────────────

    def get_package_detail(self, package_id: str) -> dict[str, object] | None:
        return self.repository.get_package(package_id)

    def get_version_detail(self, version_id: str) -> dict[str, object] | None:
        version = self.repository.get_version(version_id)
        if version is None:
            return None
        # 附加扫描报告摘要
        scan = self.repository.get_scan_report(version_id)
        if scan:
            scan_json = scan.get("scan_json", {})
            if isinstance(scan_json, dict):
                safe_scan_json = redact_report(dict(scan_json))
                safe_scan_json.pop("file_contents", None)
                version["scan_summary"] = safe_scan_json.get("summary", {})
                version["findings"] = safe_scan_json.get("findings", [])
                version["source_snapshot_id"] = safe_scan_json.get(
                    "source_snapshot_id"
                )
                # Expose the redacted consumer-facing scan report to the
                # review UI, including scan coverage and provenance metadata
                # without exposing source contents.
                version["scan_report"] = safe_scan_json
        if isinstance(version.get("provenance_claims"), dict):
            # Older rows may have been written before the persistence-side
            # redaction was added; never expose those claims verbatim.
            version["provenance_claims"] = redact_report(
                version["provenance_claims"]
            )
        # 确保 trust_score 存在
        if not version.get("trust_score"):
            version["trust_score"] = {"risk_summary": None}
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
    ) -> list[dict[str, object]]:
        """按状态/风险等级/时间范围筛选版本列表（审核员视图用）。"""
        items = self.repository.list_versions_by_status(
            status=status, grade=grade, since=since, until=until,
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
        from src.services.artifacts import ArtifactError, build_artifact

        version = self.repository.get_version(version_id)
        if version is None:
            return False
        source = version.get("source", {})
        repo_url = source.get("repository_url", "") if isinstance(source, dict) else ""
        commit_hash = source.get("commit_hash", "") if isinstance(source, dict) else ""
        source_subdirectory = source.get("subdirectory", "") if isinstance(source, dict) else ""
        if not repo_url or not commit_hash or len(commit_hash) != 40:
            return False
        package = self.repository.get_package(version.get("package_id", ""))
        package_name = package.get("name", "") if package else ""
        pkg_version = version.get("version", "")
        if not package_name or not pkg_version:
            return False
        try:
            artifact_kwargs = {
                "repo_url": repo_url,
                "commit_hash": str(commit_hash),
                "package_name": str(package_name),
                "version": str(pkg_version),
            }
            if source_subdirectory:
                artifact_kwargs["source_subdirectory"] = str(source_subdirectory)
            artifact = build_artifact(
                **artifact_kwargs,
            )
        except ArtifactError:
            return False
        self._apply_artifact_to_version(
            version_id,
            artifact,
            str(package_name),
            str(pkg_version),
            commit_hash,
            str(source_subdirectory) if source_subdirectory else None,
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


