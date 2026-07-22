"""供给侧业务逻辑 — 状态机校验、扫描触发协调。"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from src.repositories.producer_sqlalchemy import ProducerRepository
from src.models.producer import (
    CreatePackageRequest,
    CreateVersionRequest,
    PackageResponse,
    SubmitResponse,
    VersionResponse,
)

# 从 constants.py 导入状态常量
from schema.constants import STATUS_TRANSITIONS, VersionStatus, AuditAction

_SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)


class ProducerServiceError(Exception):
    """供给侧业务逻辑错误。"""


class ProducerService:
    """供给侧业务逻辑服务。"""

    def __init__(self, repository: ProducerRepository) -> None:
        self.repository = repository

    # ── 创建包 ────────────────────────────────────────────

    def create_package(
        self, data: CreatePackageRequest, submitter_id: str | None = None
    ) -> PackageResponse:
        if not data.name or not data.name.strip():
            raise ProducerServiceError("包名称不能为空")
        if not data.description:
            raise ProducerServiceError("包描述不能为空")

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
            source=data.source.model_dump() if data.source else None,
            compatibility=data.compatibility,
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
            installation=data.installation.model_dump() if data.installation else None,
            source=data.source.model_dump() if data.source else None,
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
        if current_status == "draft":
            validate_transition(current_status, "submitted")
            next_status = "submitted"
        elif current_status in ("resubmitted", "changes_requested", "error"):
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
        """扫描流水线完成后回调：写入扫描报告 + 更新状态。"""
        scan_report = full_report.get("scan_report", {})
        trust_score = full_report.get("trust_score", {})
        report_path = full_report.get("report_path", "")

        # 保存扫描报告
        self.repository.save_scan_report(
            version_id=version_id,
            scan_json=scan_report if isinstance(scan_report, dict) else {},
            report_path=str(report_path) if report_path else None,
        )

        # 更新版本数据（附加信任评分信息）
        self.repository.update_version_data(
            version_id,
            {
                "trust_score": {
                    "score": trust_score.get("score"),
                    "risk_summary": trust_score.get("risk_summary"),
                    "calculated_at": full_report.get("finished_at"),
                },
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
                "trust_score": trust_score.get("score"),
                "trust_grade": trust_score.get("risk_summary", {}).get("grade") if isinstance(trust_score, dict) else None,
                "llm_review": (
                    scan_report.get("llm_review", {}).get("labels_summary")
                    if isinstance(scan_report, dict)
                    else None
                ),
            },
        )

    def handle_scan_error(self, version_id: str, error: str) -> None:
        """扫描失败回调。"""
        self.repository.update_version_status(version_id, "error")
        self.repository.create_audit_log(
            action=AuditAction.SCAN_COMPLETE.value,
            target_type="version",
            target_id=version_id,
            operator_id="system",
            detail={"error": error},
        )

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
                version["scan_summary"] = scan_json.get("summary", {})
                version["findings"] = scan_json.get("findings", [])
                version["trust_score"] = version.get("trust_score") or {
                    "score": None,
                    "risk_summary": None,
                }
        return version

    def list_my_versions(self, submitter_id: str) -> list[dict[str, object]]:
        """返回某个提交者的所有版本列表。"""
        return self.repository.list_versions_by_submitter(submitter_id)

    # ── 按状态筛选（审核员视图） ─────────────────────────

    _GRADE_LABELS: dict[str, str] = {
        "A": "高度可信", "B": "可信", "C": "需注意",
        "D": "有风险", "E": "高风险", "F": "严重风险",
    }

    def list_versions_by_status(
        self,
        status: str | list[str] | None = None,
        grade: str | None = None,
    ) -> list[dict[str, object]]:
        """按状态/风险等级筛选版本列表（审核员视图用）。"""
        items = self.repository.list_versions_by_status(
            status=status, grade=grade
        )
        for item in items:
            g = item.get("grade")
            item["grade_label"] = self._GRADE_LABELS.get(str(g)) if g else None
        return items

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
                raise ProducerServiceError(
                    "该包只有一个版本，无可对比的基准版本。"
                    "可通过 ?base={version_id} 指定基准版本。"
                )

        base_data = {k: v for k, v in base.items() if k not in ("id", "created_at")}
        diff_result = _deep_diff(base_data, current_data)

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

        # 写入审计日志
        audit_action = AuditAction.REQUEST_CHANGES.value if conclusion == ReviewConclusion.CHANGES_REQUESTED.value else conclusion
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
        """管理员发布上线：approved → published。"""
        from src.models.producer import ReviewResponse
        from schema.constants import AuditAction

        version = self.repository.get_version(version_id)
        if version is None:
            raise ProducerServiceError(f"版本 {version_id} 不存在")

        current = version.get("status", "")
        target = "published"
        validate_transition(current, target)

        self.repository.update_version_status(version_id, target)
        self.repository.update_version_data(
            version_id,
            {"published_at": datetime.now(timezone.utc).isoformat()},
        )
        self.repository.create_audit_log(
            action=AuditAction.PUBLISH.value,
            target_type="version",
            target_id=version_id,
            operator_id=operator_id,
        )

        return ReviewResponse(
            version_id=version_id,
            new_status=target,
            message="版本已发布上线",
        )

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

        self.repository.update_version_status(version_id, target)
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


# ── 模块级函数 ──────────────────────────────────────────


def validate_transition(current: str, target: str) -> None:
    """校验状态跳转是否合法，不合法抛 ProducerServiceError。"""
    allowed = STATUS_TRANSITIONS.get(current, [])
    if target not in allowed:
        raise ProducerServiceError(
            f"状态跳转非法：'{current}' → '{target}' 不在允许的跳转列表中"
        )


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


# ── ProducerService: 审核与发布 ────────────────────────────


