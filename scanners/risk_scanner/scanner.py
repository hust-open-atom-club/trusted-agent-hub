"""
Risk Scanner — 自动风险扫描器 v0.8.0

遍历目标目录，运行 20 条静态分析规则，检测 Agent 能力包中的安全风险。
输出格式严格遵循 scan-report.schema.json。

规则列表:
  SR-001:  提示注入 + 反拒绝机制检测 (合并)
  SR-002:  危险 Shell 命令
  SR-003:  凭据访问
  SR-004:  硬编码密钥
  SR-005:  远程代码执行 (正则层)
  SR-005b: 远程代码执行 (AST 行为分析层)
  SR-006:  过度权限声明 + 自主决策检测
  SR-007:  网络访问无白名单
  SR-008:  供应链风险 (+ Typosquatting + OSV CVE)
  SR-009:  来源完整性
  SR-010:  元数据质量 + 结构校验
  SR-011:  输出处理风险
  SR-012:  系统提示泄漏
  SR-013:  记忆投毒
  SR-014:  SSRF (+ 防御上下文过滤)
  SR-015:  Agent 窥探
  SR-016:  工具滥用
  SR-017:  MCP 安全 (隐藏工具检测 + 非加密传输检测 + 工具描述投毒/语义漂移)
  SR-018:  Plugin 安全 (内联MCP命令 + Hook注入 + 组件路径遍历)
  SR-019:  Subagent 安全 (自主模式 + 危险工具 + 全局作用域 + 路径遍历)
  SR-020:  安装器安全 (生命周期脚本 + 破坏性安装操作)

用法:
    from scanners.risk_scanner.scanner import RiskScanner
    scanner = RiskScanner("/path/to/package")
    report = scanner.scan()
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanners.risk_scanner.common import (
    CODE_EXAMPLE_INDICATORS,
    CODE_FILE_EXTENSIONS,
    BINARY_EXTENSIONS,
    REQUIRED_FILES_BY_TYPE,
)
from scanners.risk_scanner.analyzers import analyze_snapshot
from scanners.risk_scanner.analyzers.source_integrity import verify_source_state
from scanners.risk_scanner.inventory import ScanInventory, build_inventory, load_text_files
from scanners.risk_scanner.policy import ScanPolicy
from scanners.risk_scanner.rule_runner import RULE_SPECS, RuleRunner
from scanners.risk_scanner.reporting import (
    aggregate_findings,
    build_advisory_summary,
    build_findings_summary,
    determine_scan_status,
)
from scanners.risk_scanner.dependency_parsers.osv_client import OSVClient
from scanners.risk_scanner.redaction import redact_report
from packages.schema.constants import HASH_SCOPE_SCANNED_SOURCE
from packages.schema.frontmatter import parse_frontmatter

logger = logging.getLogger(__name__)


SCANNER_VERSION = "0.12.0"

_DOCUMENTATION_BASENAME_PREFIXES = (
    "readme",
    "changelog",
    "release-notes",
    "notice",
    "license",
)
_DOCUMENTATION_EXTENSIONS = frozenset({"", ".md", ".markdown", ".txt", ".rst"})
_SEMANTIC_TEXT_EXTENSIONS = frozenset({".md", ".markdown", ".txt", ".rst"})
_SEMANTIC_VALIDATION_CATEGORIES = frozenset({
    "prompt_injection",
    "dangerous_shell",
    "credential_access",
    "remote_code_execution",
    "installation_security",
    "system_prompt_leakage",
    "memory_poisoning",
    "agent_snooping",
    "tool_misuse",
})
_ALWAYS_SEMANTIC_VALIDATION_CATEGORIES = frozenset({
    "prompt_injection",
    "system_prompt_leakage",
    "memory_poisoning",
    "agent_snooping",
})


class RiskScanner:
    """自动风险扫描器 — 静态分析 Agent 能力包目录。"""

    def __init__(
        self,
        target_dir: str | Path,
        *,
        source_commit_hash: str = "",
        policy: ScanPolicy | None = None,
    ) -> None:
        self.target_dir = Path(target_dir).resolve()
        self.source_commit_hash = source_commit_hash
        self.policy = policy or ScanPolicy()
        self.findings: list[dict[str, Any]] = []
        self.review_advisories: list[dict[str, Any]] = []
        self.scanned_files: list[str] = []
        self.discovered_files: list[str] = []
        self.analyzed_files: list[str] = []
        self._inventory: ScanInventory | None = None
        self.rule_runner = RuleRunner()
        self.osv_client = OSVClient(max_queries=self.policy.max_osv_queries)
        self.rule_execution: dict[str, Any] = {"total": len(RULE_SPECS), "succeeded": 0, "failed": 0, "skipped": 0, "results": []}
        self.scanner_errors: list[dict[str, Any]] = []
        self.findings_limit_exceeded = False
        self._package_metadata: dict[str, Any] | None = None
        self._package_claims: dict[str, Any] | None = None
        self._acquisition_facts: dict[str, Any] = {}
        self._file_contents: dict[str, str] = {}
        self.analysis = None
        self._content_tree_hash: str | None = None
        self._metadata_parse_errors: list[dict[str, str]] = []

    def scan(self) -> dict[str, Any]:
        self.findings = []
        self.review_advisories = []
        self.scanned_files = []
        self.discovered_files = []
        self.analyzed_files = []
        self._inventory = None
        self.rule_execution = {"total": len(RULE_SPECS), "succeeded": 0, "failed": 0, "skipped": 0, "results": []}
        self.scanner_errors = []
        self.findings_limit_exceeded = False
        self.dependency_scan = {"status": "complete", "dependencies_found": 0,
                                "dependencies_queried": 0, "query_failures": 0}
        self._file_contents = {}
        self.analysis = None
        self._content_tree_hash = None
        self._metadata_parse_errors = []
        self._package_metadata = None
        self._package_claims = None
        self._acquisition_facts = {}
        start = datetime.now(timezone.utc)

        self._inventory = build_inventory(self.target_dir, self.policy)
        self.discovered_files = [r.relative_path for r in self._inventory.files]
        self._file_contents = load_text_files(self._inventory, policy=self.policy)
        self.analyzed_files = [r.relative_path for r in self._inventory.files if r.read_status == "analyzed"]
        self.scanned_files = [r.relative_path for r in self._inventory.files
                              if r.read_status == "analyzed" and r.skip_reason != "general_rule_excluded"]
        self.dependency_scan: dict[str, Any] = {"status": "complete", "dependencies_found": 0,
                                                "dependencies_queried": 0, "query_failures": 0}
        self._load_metadata()
        # Keep the package-authored metadata available for audit/explanation,
        # but never use it as the source of acquisition provenance.
        self._package_claims = deepcopy(self._package_metadata)
        self.analysis = analyze_snapshot(
            self._file_contents,
            self.analyzed_files,
            self._package_metadata,
            target_dir=self.target_dir,
            inventory=self.inventory,
        )
        self._inject_acquired_source_integrity()

        rule_results = self.rule_runner.run_all(self)
        self.rule_execution["succeeded"] = sum(r.status == "succeeded" for r in rule_results)
        self.rule_execution["failed"] = sum(r.status == "failed" for r in rule_results)
        self.rule_execution["results"] = [r.as_dict() for r in rule_results]
        self.scanner_errors = [
            {"phase": "rule_execution", "rule_id": r.rule_id, "error_type": r.error_type,
             "message": r.error_message, "recoverable": True}
            for r in rule_results if r.status == "failed"
        ]
        self._record_source_integrity_changes()
        self._sync_acquisition_integrity_completeness()
        self._record_structured_analysis_errors()
        if self.dependency_scan.get("status") == "partial" and "dependency_scan_partial" not in self.inventory.limit_violations:
            self.inventory.limit_violations.append("dependency_scan_partial")

        self._downgrade_documentation_findings()
        self._mark_semantic_findings_for_llm_review()

        end = datetime.now(timezone.utc)
        duration_ms = int((end - start).total_seconds() * 1000)

        return self._build_report(start, duration_ms)

    @property
    def inventory(self) -> ScanInventory:
        if self._inventory is None:
            self._inventory = build_inventory(self.target_dir, self.policy)
        return self._inventory

    def _load_metadata(self) -> None:
        def load_json_object(path: str) -> dict[str, Any] | None:
            try:
                value = json.loads(self._file_contents[path])
            except json.JSONDecodeError as exc:
                self._metadata_parse_errors.append({
                    "file": path,
                    "message": f"invalid JSON: {exc.msg}",
                })
                return None
            if not isinstance(value, dict):
                self._metadata_parse_errors.append({
                    "file": path,
                    "message": "JSON root must be an object",
                })
                return None
            return value

        manifest_path = "manifest.json"
        if manifest_path in self._file_contents:
            metadata = load_json_object(manifest_path)
            if metadata is not None:
                self._package_metadata = metadata
                return

        plugin_path = "plugin.json"
        if plugin_path in self._file_contents:
            metadata = load_json_object(plugin_path)
            if metadata is not None:
                self._package_metadata = metadata
                return

        skill_path = "SKILL.md"
        if skill_path in self._file_contents:
            try:
                content = self._file_contents[skill_path]
                result = parse_frontmatter(content)
                if result.error:
                    self._metadata_parse_errors.append({
                        "file": skill_path,
                        "message": result.error,
                    })
                elif result.data:
                    self._package_metadata = result.data
            except UnicodeDecodeError:
                pass

        # 回退：package.json 补充 SKILL.md frontmatter 未声明的字段
        # （version/license/author 等常见于 npm 风格仓库的 package.json）
        pkg_json_path = "package.json"
        if pkg_json_path in self._file_contents:
            pkg_json = load_json_object(pkg_json_path)
            if pkg_json is not None:
                if not self._package_metadata:
                    self._package_metadata = pkg_json
                else:
                    for key in ("name", "version", "description", "license", "author"):
                        if not self._package_metadata.get(key) and pkg_json.get(key):
                            self._package_metadata[key] = pkg_json[key]

    def _inject_acquired_source_integrity(self) -> None:
        """Record facts established by acquisition without mutating claims.

        A repository's own metadata cannot safely attest to the bytes currently
        being scanned. The scanner therefore computes a bounded content hash
        from the inventory and accepts the commit only from the acquisition
        layer (``git rev-parse HEAD`` / GitHub zipball resolution).
        """
        # Calculate this once from the already bounded inventory.  The API may
        # request the hash again while persisting the source snapshot, but that
        # call is served from this cache and never walks or rereads the tree.
        content_hash = self._content_tree_sha256()
        self._acquisition_facts = {
            "source": {},
            "integrity": {
                "sha256": content_hash,
                "hash_scope": HASH_SCOPE_SCANNED_SOURCE,
                "is_complete": "content_hash_limited" not in self.inventory.limit_violations,
            },
            "verification": {
                "owner": False,
                "signature": False,
                "attestation": False,
                "sbom": False,
                # Internal marker used to ensure any future verifier result
                # is bound to this exact scanned content before persistence.
                "content_sha256": content_hash,
            },
        }

        if re.fullmatch(r"^[a-f0-9]{40}$", self.source_commit_hash):
            self._acquisition_facts["source"]["commit_hash"] = self.source_commit_hash

    @property
    def acquisition_facts(self) -> dict[str, Any]:
        """Return server-established source/integrity facts for scoring.

        The returned copy intentionally excludes package-authored provenance
        claims such as ``verified_owner`` and signature URLs.
        """
        return deepcopy(self._acquisition_facts)

    @property
    def package_claims(self) -> dict[str, Any] | None:
        """Return the package-authored metadata retained for audit purposes."""
        return deepcopy(self._package_claims)

    def _content_tree_sha256(self) -> str:
        """Return a bounded hash over the inventory's source snapshot."""
        if self._content_tree_hash is not None:
            return self._content_tree_hash

        digest = hashlib.sha256()
        inventory = self.inventory
        complete = (
            self.target_dir.is_dir()
            and not inventory.limit_violations
            and not inventory.discovered_at_least
        )
        max_file_bytes = max(self.policy.max_file_bytes, 0)
        max_total_bytes = max(self.policy.max_total_bytes, 0)
        total_bytes = 0
        for record in sorted(inventory.files, key=lambda item: item.relative_path):
            path = record.absolute_path
            rel = record.relative_path
            try:
                before = path.lstat()
            except OSError:
                complete = False
                continue

            if path.is_symlink() or not path.is_file():
                complete = False
                continue

            size = int(before.st_size)
            if size > max_file_bytes or total_bytes + size > max_total_bytes:
                complete = False
                continue

            digest.update(rel.encode("utf-8"))
            digest.update(b"\0")
            digest.update(str(size).encode("ascii"))
            digest.update(b"\0")
            bytes_read = 0
            try:
                with path.open("rb") as handle:
                    while bytes_read < size:
                        remaining = min(
                            size - bytes_read,
                            max_file_bytes - bytes_read,
                            max_total_bytes - total_bytes - bytes_read,
                        )
                        if remaining <= 0:
                            complete = False
                            break
                        chunk = handle.read(min(64 * 1024, remaining))
                        if not chunk:
                            break
                        digest.update(chunk)
                        bytes_read += len(chunk)
                after = path.lstat()
            except OSError:
                complete = False
                continue
            if (
                bytes_read != size
                or path.is_symlink()
                or int(after.st_size) != size
                or int(after.st_mtime_ns) != int(before.st_mtime_ns)
                or int(getattr(after, "st_ino", 0)) != int(getattr(before, "st_ino", 0))
            ):
                complete = False
            total_bytes += bytes_read
            digest.update(b"\0")

        if not complete and "content_hash_limited" not in self.inventory.limit_violations:
            self.inventory.limit_violations.append("content_hash_limited")
        self._content_tree_hash = digest.hexdigest()
        return self._content_tree_hash

    def _sync_acquisition_integrity_completeness(self) -> None:
        """Update the scan hash marker after the source re-check completes."""
        integrity = self._acquisition_facts.get("integrity")
        if not isinstance(integrity, dict):
            return
        integrity["is_complete"] = (
            integrity.get("hash_scope") == HASH_SCOPE_SCANNED_SOURCE
            and "content_hash_limited" not in self.inventory.limit_violations
        )

    def _read_file_content(self, rel_path: str) -> str:
        return self._file_contents.get(rel_path, "")

    def _record_source_integrity_changes(self) -> None:
        """Record files that changed or escaped the root during analysis."""
        source_snapshot = getattr(self.analysis, "source_integrity", None)
        issues = verify_source_state(self.target_dir, source_snapshot)
        if issues and "content_hash_limited" not in self.inventory.limit_violations:
            # A post-capture source mutation or an incomplete second pass
            # means the previously computed tree hash is not a complete
            # representation of the acquired source.
            self.inventory.limit_violations.append("content_hash_limited")
        for issue in issues:
            kind = issue["kind"]
            if kind not in self.inventory.limit_violations:
                self.inventory.limit_violations.append(kind)
            if kind == "source_state_check_limited":
                # This only says that the re-check could not cover the whole
                # tree. It is a scan-coverage signal, not evidence of a source
                # integrity violation.
                continue
            severity = "high" if kind == "symlink_outside_root" else "medium"
            description = f"扫描过程中检测到文件 {issue['file']} 存在 {kind}。"
            self._add_finding(
                rule_id="SR-009",
                severity=severity,
                category="source_integrity",
                title=f"源码完整性异常: {kind}",
                description=description,
                location={"file": issue["file"]},
                evidence="source state changed after inventory capture",
                remediation="固定扫描输入，在扫描期间禁止修改文件，并拒绝仓库外 symlink。",
            )

    def _record_structured_analysis_errors(self) -> None:
        """Expose parser failures as coverage signals, not security findings."""
        for error in getattr(self.analysis, "parse_errors", []) if self.analysis is not None else []:
            self.scanner_errors.append({
                "phase": "structured_analysis",
                "error_type": "ParseError",
                "message": str(error.get("error", "structured analysis failed"))[:200],
                "recoverable": True,
            })

    def _is_code_example(self, file_path: str, line_no: int) -> bool:
        content = self._read_file_content(file_path)
        if not content:
            return False
        ext = Path(file_path).suffix.lower()
        if ext not in (".md", ".markdown", ".txt", ".rst"):
            return False
        # Agent instructions and policy files are executable input to an agent,
        # even when a suspicious line is wrapped in a Markdown code block.
        # Only apply the code-example relaxation to files that are also
        # recognized as ordinary documentation.
        if not self._is_documentation_file(file_path):
            return False
        lines = content.split("\n")
        context_start = max(0, line_no - 6)
        context_end = min(len(lines), line_no + 5)
        context = "\n".join(lines[context_start:context_end])
        lower_context = context.lower()
        if "```" in context:
            return True
        for indicator in CODE_EXAMPLE_INDICATORS:
            if indicator in lower_context:
                return True
        return False

    @staticmethod
    def _is_instruction_or_policy_file(rel_path: str) -> bool:
        """Return whether *rel_path* is agent-executable instruction/policy input."""
        normalized = rel_path.replace("\\", "/").lower().strip("/")
        if not normalized:
            return False

        basename = normalized.rsplit("/", 1)[-1]
        if basename in {
            "agents.md",
            "claude.md",
            "gemini.md",
            "copilot-instructions.md",
            "prompt.md",
            "policy.md",
            "instructions.md",
            "skill.md",
            "system_prompt.md",
            "agent.json",
        }:
            return True
        if basename.endswith((".prompt.md", ".policy.md", ".instructions.md")):
            return True
        if normalized.startswith(".github/instructions/"):
            return True

        # Prompts and policies can be nested below another directory (for
        # example docs/prompts/foo.md), so inspect directory components rather
        # than only checking the repository root.
        directory_parts = normalized.split("/")[:-1]
        return any(
            part in {"prompts", "policies", "instructions"}
            for part in directory_parts
        )

    def _is_documentation_file(self, rel_path: str) -> bool:
        """Return whether *rel_path* is ordinary documentation.

        Only well-known repository documentation names are trusted. Generic
        Markdown below ``docs/`` can still be agent-consumed input.
        """
        normalized = rel_path.replace("\\", "/").lower()
        basename = normalized.rsplit("/", 1)[-1]
        if self._is_instruction_or_policy_file(normalized):
            return False
        if Path(basename).suffix.lower() not in _DOCUMENTATION_EXTENSIONS:
            return False
        return any(
            basename == prefix
            or basename.startswith((f"{prefix}.", f"{prefix}-", f"{prefix}_"))
            for prefix in _DOCUMENTATION_BASENAME_PREFIXES
        )

    def _downgrade_documentation_findings(self) -> None:
        """把说明性文档中的 critical/high/medium 发现降级为 low。

        真实仓库的 README/文档常包含示例命令、token 占位符、curl | sh 等字面量，
        这些不是可执行的能力内容，不应直接触发一票否决。
        """
        for finding in self.findings:
            location = finding.get("location") or {}
            file_path = str(location.get("file") or "")
            severity = finding.get("severity", "info")
            if (
                file_path
                and self._is_documentation_file(file_path)
                and severity in ("critical", "high", "medium")
            ):
                finding["severity"] = "low"
                finding["effective_severity"] = "low"
                finding["downgraded"] = "documentation"
                finding["title"] = f"{finding.get('title', '')} [文档示例/说明文本]"

    def _mark_semantic_findings_for_llm_review(self) -> None:
        """Mark findings that a guarded semantic review may adjudicate.

        A regex match in SKILL.md, a prompt, or a reference document is a
        semantic review candidate rather than proof of a vulnerability. Static
        and effective severities remain unchanged until a sufficiently audited
        multi-judge decision is applied by the API orchestration layer.
        """
        for finding in self.findings:
            severity = str(
                finding.get("static_severity") or finding.get("severity", "info")
            ).lower()
            if severity not in {"critical", "high", "medium"}:
                continue
            category = str(finding.get("category", ""))
            location = finding.get("location") or {}
            file_path = str(location.get("file") or "")
            is_text = Path(file_path).suffix.lower() in _SEMANTIC_TEXT_EXTENSIONS
            requires_semantic_review = (
                category in _ALWAYS_SEMANTIC_VALIDATION_CATEGORIES
                or (is_text and category in _SEMANTIC_VALIDATION_CATEGORIES)
            )
            contextual_finding = (
                finding.get("kind") == "context_dependent"
                or finding.get("disposition") == "needs_context"
            )
            semantic_code_candidate = (
                category in _SEMANTIC_VALIDATION_CATEGORIES
                and severity in {"critical", "high"}
            )
            confirmed_vulnerability = (
                finding.get("kind") == "vulnerability"
                and finding.get("disposition") == "confirmed_vulnerability"
            )
            adjudication_eligible = (
                requires_semantic_review
                or contextual_finding
                or semantic_code_candidate
            ) and not confirmed_vulnerability
            if not adjudication_eligible:
                continue
            finding["candidate_severity"] = severity
            finding["llm_adjudication_eligible"] = True
            finding["llm_adjudication_reason"] = (
                "semantic_text"
                if requires_semantic_review
                else "context_dependent_code"
                if contextual_finding
                else "semantic_code_candidate"
            )
            if requires_semantic_review:
                finding["requires_llm_validation"] = True
            finding["llm_review_state"] = "pending"
            finding["requires_manual_review"] = True

    def _add_finding(
        self,
        rule_id: str,
        severity: str,
        category: str,
        title: str,
        description: str,
        location: dict[str, Any] | None = None,
        evidence: str = "",
        remediation: str = "",
        cwe_id: str | None = None,
        requires_confirmation: bool = False,
        kind: str | None = None,
        disposition: str | None = None,
        sink_kind: str | None = None,
        sink_symbol: str | None = None,
        source_kind: str | None = None,
        source_symbol: str | None = None,
        source_control: str | None = None,
        reachability: str | None = None,
        activation: str | None = None,
        trust_boundary_crossed: bool | None = None,
        safeguards: list[str] | None = None,
        preconditions: list[str] | None = None,
        requires_manual_review: bool = False,
    ) -> None:
        if len(self.findings) >= self.policy.max_findings:
            self.findings_limit_exceeded = True
            if self._inventory is not None and "findings_limit_exceeded" not in self._inventory.limit_violations:
                self._inventory.limit_violations.append("findings_limit_exceeded")
            return
        finding: dict[str, Any] = {
            "id": f"finding-{uuid.uuid4().hex[:8]}",
            "rule_id": rule_id,
            "severity": severity,
            "static_severity": severity,
            "effective_severity": severity,
            "category": category,
            "title": title,
            "description": description,
        }
        if location:
            finding["location"] = location
        if evidence:
            finding["evidence"] = evidence
        if remediation:
            finding["remediation"] = remediation
        if cwe_id:
            finding["cwe_id"] = cwe_id
        if requires_confirmation:
            finding["requires_confirmation"] = True
        semantic_values: dict[str, Any] = {
            "kind": kind,
            "disposition": disposition,
            "sink_kind": sink_kind,
            "sink_symbol": sink_symbol,
            "source_kind": source_kind,
            "source_symbol": source_symbol,
            "source_control": source_control,
            "reachability": reachability,
            "activation": activation,
            "trust_boundary_crossed": trust_boundary_crossed,
        }
        for key, value in semantic_values.items():
            if value is not None:
                finding[key] = value
        if safeguards:
            finding["safeguards"] = list(safeguards)
        if preconditions:
            finding["preconditions"] = list(preconditions)
        if requires_manual_review:
            finding["requires_manual_review"] = True

        self.findings.append(finding)

    def _add_advisory(
        self,
        *,
        code: str,
        category: str,
        level: str,
        title: str,
        description: str,
        deduction: int = 0,
        affects_grade: bool = False,
        grade_downgrade_steps: int = 0,
        requires_manual_review: bool = False,
        evidence: str = "",
        location: dict[str, Any] | None = None,
    ) -> None:
        """Add a reviewer-facing warning that is not a security finding."""
        advisory: dict[str, Any] = {
            "id": f"advisory-{uuid.uuid4().hex[:8]}",
            "code": code,
            "category": category,
            "level": level,
            "title": title,
            "description": description,
            "deduction": max(0, int(deduction)),
            "affects_grade": bool(affects_grade),
            "grade_downgrade_steps": min(1, max(0, int(grade_downgrade_steps))),
            "requires_manual_review": bool(requires_manual_review),
        }
        if evidence:
            advisory["evidence"] = evidence
        if location:
            advisory["location"] = location
        self.review_advisories.append(advisory)

    def _deduplicate_findings(self) -> None:
        _SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        seen: dict[tuple, int] = {}

        def matched_text(finding: dict[str, Any]) -> str:
            """Return the scanner-produced match payload without parsing URL colons."""
            evidence = str(finding.get("evidence", ""))
            for prefix in ("匹配模式:", "匹配:"):
                if evidence.startswith(prefix):
                    return evidence[len(prefix):].strip()[:120]
            return evidence.strip()[:120]

        # 第一轮: 文件内去重 — 同规则+同匹配内容+同文件 → 保留最高严重度
        deduplicated: list[dict[str, Any]] = []
        for f in self.findings:
            rule_id = f.get("rule_id", "")
            loc = f.get("location", {}) or {}
            fname = loc.get("file", "")
            key = (rule_id, fname, matched_text(f))
            if key in seen:
                existing_idx = seen[key]
                existing_sev = deduplicated[existing_idx].get("severity", "info")
                current_sev = f.get("severity", "info")
                if _SEVERITY_RANK.get(current_sev, 0) > _SEVERITY_RANK.get(existing_sev, 0):
                    deduplicated[existing_idx] = f
            else:
                seen[key] = len(deduplicated)
                deduplicated.append(f)

        self.findings = deduplicated

        # 第二轮: 跨文件合并 — 同规则+同匹配内容出现在多个文件时只保留一条
        # （取最高严重度），其余文件位置记入 duplicates（清单最多 5 个，超出只计数）。
        cross_seen: dict[tuple, int] = {}
        removed: set[int] = set()
        for i, f in enumerate(self.findings):
            rule_id = f.get("rule_id", "")
            match_value = matched_text(f)
            if not match_value:
                continue
            key = (rule_id, match_value)
            if key in cross_seen:
                primary_idx = cross_seen[key]
                primary = self.findings[primary_idx]
                primary_sev = primary.get("severity", "info")
                current_sev = f.get("severity", "info")
                if _SEVERITY_RANK.get(current_sev, 0) > _SEVERITY_RANK.get(primary_sev, 0):
                    # 当前更严重 → 取代原 primary，并继承其 duplicates
                    self._promote_to_primary(f, primary)
                    removed.add(primary_idx)
                    cross_seen[key] = i
                else:
                    self._merge_duplicate_into(primary, f)
                    removed.add(i)
            else:
                cross_seen[key] = i

        if removed:
            self.findings = [f for idx, f in enumerate(self.findings) if idx not in removed]

        # 给合并后的 finding 追加人读提示（evidence 在审核页可见）
        for f in self.findings:
            dup = f.get("duplicates")
            if isinstance(dup, dict) and dup.get("count"):
                count = int(dup["count"])
                names = [d.get("file", "") for d in dup.get("files", []) if isinstance(d, dict)]
                shown = "、".join(n for n in names if n)
                note = f"另有 {count} 个文件存在相同问题: {shown}"
                if count > len(names):
                    note += " 等"
                f["evidence"] = f"{f.get('evidence', '')} | {note}"

    @staticmethod
    def _merge_duplicate_into(primary: dict[str, Any], other: dict[str, Any]) -> None:
        """把 other 的文件位置并入 primary.duplicates。"""
        dup = primary.setdefault("duplicates", {"count": 0, "files": []})
        files: list[dict[str, Any]] = dup.get("files", [])
        loc = other.get("location", {}) or {}
        if len(files) < 5:
            entry: dict[str, Any] = {"file": str(loc.get("file", "(unknown)"))}
            if loc.get("line"):
                entry["line"] = int(loc["line"])
            files.append(entry)
        dup["count"] = int(dup.get("count", 0)) + 1

    def _promote_to_primary(self, new_p: dict[str, Any], old_p: dict[str, Any]) -> None:
        """new_p 更严重，取代 old_p：继承其 duplicates 并把 old_p 位置并入。"""
        old_dup = old_p.get("duplicates")
        if isinstance(old_dup, dict):
            new_dup = new_p.setdefault("duplicates", {"count": 0, "files": []})
            merged: list[dict[str, Any]] = list(new_dup.get("files", []))
            for item in old_dup.get("files", []):
                if isinstance(item, dict) and len(merged) < 5:
                    merged.append(item)
            new_dup["files"] = merged
            new_dup["count"] = int(new_dup.get("count", 0)) + int(old_dup.get("count", 0))
        self._merge_duplicate_into(new_p, old_p)

    def _build_report(self, start_time: datetime, duration_ms: int) -> dict[str, Any]:
        report_findings = aggregate_findings(self.findings)
        summary = build_findings_summary(report_findings)
        effective_total = int(summary["effective_total"])

        pkg_name = "unknown"
        pkg_version = "0.0.0"
        if self._package_metadata:
            pkg_name = self._package_metadata.get("name", "unknown")
            pkg_version = self._package_metadata.get("version", "0.0.0")

        metadata_validation: dict[str, Any] = {"valid": True, "errors": []}
        if self._metadata_parse_errors:
            metadata_validation["valid"] = False
            metadata_validation["parse_errors"] = list(self._metadata_parse_errors)
            metadata_validation["errors"].extend(
                {
                    "field": item["file"],
                    "message": item["message"],
                }
                for item in self._metadata_parse_errors
            )
        if self._package_metadata:
            for field in ["name", "version", "description", "author", "license"]:
                if not self._package_metadata.get(field):
                    metadata_validation["valid"] = False
                    metadata_validation["errors"].append({
                        "field": field,
                        "message": f"Missing required field: {field}",
                    })
        else:
            metadata_validation["valid"] = False
            metadata_validation["errors"].append({
                "field": "*",
                "message": "No metadata file found",
            })

        structure_check: dict[str, Any] = {
            "valid": True,
            "missing_files": [],
            "extra_files": [],
        }
        if self._package_metadata:
            pkg_type = self._package_metadata.get("type", "")
            required = REQUIRED_FILES_BY_TYPE.get(pkg_type, [])
            for req_file in required:
                if not (self.target_dir / req_file).is_file():
                    structure_check["valid"] = False
                    structure_check["missing_files"].append(req_file)
        for fname in self.discovered_files:
            ext = Path(fname).suffix.lower()
            if ext in BINARY_EXTENSIONS:
                structure_check["valid"] = False
                structure_check["extra_files"].append(fname)

        dependency_check: dict[str, Any] = {
            "total_dependencies": 0,
            "known_vulnerabilities": 0,
            "unlocked_versions": 0,
            "suspicious_packages": [],
        }
        if self._package_metadata:
            deps = self._package_metadata.get("dependencies", {})
            if isinstance(deps, dict):
                for deps_list in deps.values():
                    if isinstance(deps_list, list):
                        dependency_check["total_dependencies"] += len(deps_list)
        cve_findings = [f for f in report_findings if "CVE" in f.get("title", "")]
        dependency_check["known_vulnerabilities"] = len(cve_findings)
        dependency_check["total_dependencies"] = int(self.dependency_scan.get("dependencies_found", dependency_check["total_dependencies"]))
        dependency_check["unlocked_versions"] = sum(
            1 for finding in self.findings if finding.get("rule_id") == "SR-008" and "版本未锁定" in finding.get("title", "")
        )

        complete = not self.inventory.limit_violations and not self.scanner_errors
        state = "complete" if complete else ("failed" if not self.target_dir.is_dir() else "partial")
        scan_status = determine_scan_status(
            target_valid=self.target_dir.is_dir(),
            limit_violations=self.inventory.limit_violations,
            scanner_errors=self.scanner_errors,
            effective_total=effective_total,
        )
        skipped = self.inventory.skipped_by_reason or {}
        return redact_report({
            "scan_id": f"scan-{uuid.uuid4().hex[:12]}",
            "package_name": pkg_name,
            "version": pkg_version,
            "scanned_at": start_time.isoformat(),
            "scanner_version": SCANNER_VERSION,
            "duration_ms": duration_ms,
            "scan_status": scan_status,
            "scan_limits": {
                "configured": self.policy.as_dict(),
                "observed": {
                    "discovered_files": self.inventory.discovered_files,
                    "discovered_count": self.inventory.discovered_count,
                    "discovered_at_least": self.inventory.discovered_at_least,
                    "analyzed_files": len(self.analyzed_files),
                    "discovered_bytes": self.inventory.discovered_bytes,
                    "analyzed_bytes": self.inventory.analyzed_bytes,
                },
                "exceeded": self.inventory.limit_violations,
                "skipped": {
                    "count": sum(skipped.values()),
                    "by_reason": skipped,
                    "samples": self.inventory.skipped_samples or [],
                },
            },
            "rule_execution": self.rule_execution,
            "scanner_errors": self.scanner_errors,
            "findings": report_findings,
            "summary": summary,
            "review_advisories": self.review_advisories,
            "advisory_summary": build_advisory_summary(self.review_advisories),
            "metadata_validation": metadata_validation,
            "structure_check": structure_check,
            "dependency_check": dependency_check,
            "dependency_scan": self.dependency_scan,
            "structural_analysis": self.analysis.as_report() if self.analysis is not None else {},
        })


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <target_directory> [--json]")
        sys.exit(1)

    target = sys.argv[1]
    scanner = RiskScanner(target)
    report = scanner.scan()

    if "--json" in sys.argv:
        sys.stdout.reconfigure(encoding="utf-8")
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        summary = report["summary"]
        print(f"\n  Scan Report: {report['package_name']} v{report['version']}")
        print(f"  {'─' * 50}")
        print(f"  Findings: {summary['total']} total")
        print(f"    Critical: {summary['critical']}")
        print(f"    High:     {summary['high']}")
        print(f"    Medium:   {summary['medium']}")
        print(f"    Low:      {summary['low']}")
        print(f"    Info:     {summary['info']}")
        print(f"  Duration:  {report['duration_ms']}ms")
        print()
