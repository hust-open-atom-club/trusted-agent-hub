"""
Risk Scanner — 自动风险扫描器 v0.4.0

遍历目标目录，运行 19 条静态分析规则，检测 Agent 能力包中的安全风险。
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

用法:
    from scanners.risk_scanner.scanner import RiskScanner
    scanner = RiskScanner("/path/to/package")
    report = scanner.scan()
"""

from __future__ import annotations

import hashlib
import importlib
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanners.risk_scanner.common import (
    CODE_EXAMPLE_INDICATORS,
    CODE_FILE_EXTENSIONS,
    DANGEROUS_EXTENSIONS,
    KNOWN_SAFE_FILES,
    REQUIRED_FILES_BY_TYPE,
    SKIP_READ_EXTENSIONS,
    SUSPICIOUS_EXTENSIONS,
)
from scanners.risk_scanner.weights import SEVERITY_POINTS

logger = logging.getLogger(__name__)


_RULE_MODULES: list[str] = [
    "scanners.risk_scanner.rules.prompt_injection",
    "scanners.risk_scanner.rules.dangerous_shell",
    "scanners.risk_scanner.rules.credential_access",
    "scanners.risk_scanner.rules.hardcoded_secrets",
    "scanners.risk_scanner.rules.rce",
    "scanners.risk_scanner.rules.behavioral_ast",
    "scanners.risk_scanner.rules.excessive_permissions",
    "scanners.risk_scanner.rules.network",
    "scanners.risk_scanner.rules.supply_chain",
    "scanners.risk_scanner.rules.source_integrity",
    "scanners.risk_scanner.rules.metadata_quality",
    "scanners.risk_scanner.rules.output_handling",
    "scanners.risk_scanner.rules.system_prompt_leak",
    "scanners.risk_scanner.rules.memory_poisoning",
    "scanners.risk_scanner.rules.ssrf",
    "scanners.risk_scanner.rules.agent_snooping",
    "scanners.risk_scanner.rules.tool_misuse",
    "scanners.risk_scanner.rules.mcp_security",
    "scanners.risk_scanner.rules.plugin_security",
    "scanners.risk_scanner.rules.subagent_security",
]

SCANNER_VERSION = "0.4.0"


class RiskScanner:
    """自动风险扫描器 — 静态分析 Agent 能力包目录。"""

    def __init__(
        self,
        target_dir: str | Path,
        *,
        source_commit_hash: str = "",
    ) -> None:
        self.target_dir = Path(target_dir).resolve()
        self.source_commit_hash = source_commit_hash
        self.findings: list[dict[str, Any]] = []
        self.scanned_files: list[str] = []
        self._package_metadata: dict[str, Any] | None = None
        self._file_contents: dict[str, str] = {}

    def scan(self) -> dict[str, Any]:
        self.findings = []
        self.scanned_files = []
        self._file_contents = {}
        start = datetime.now(timezone.utc)

        self._collect_files()
        self._load_metadata()
        self._inject_acquired_source_integrity()

        for rule_module in _RULE_MODULES:
            try:
                mod = importlib.import_module(rule_module)
                mod.run(self)
            except (ModuleNotFoundError, AttributeError) as e:
                logger.warning("Rule module %s failed to load: %s", rule_module, e)

        self._downgrade_documentation_findings()
        self._deduplicate_findings()

        end = datetime.now(timezone.utc)
        duration_ms = int((end - start).total_seconds() * 1000)

        return self._build_report(start, duration_ms)

    def _collect_files(self) -> None:
        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d != ".git"]
            for fname in files:
                fpath = Path(root) / fname
                ext = fpath.suffix.lower()
                if ext in SKIP_READ_EXTENSIONS:
                    continue
                if fname in KNOWN_SAFE_FILES:
                    continue
                try:
                    rel_path = str(fpath.relative_to(self.target_dir)).replace("\\", "/")
                    self.scanned_files.append(rel_path)
                    content = fpath.read_text(encoding="utf-8-sig", errors="ignore")
                    if len(content) == 0:
                        continue
                    self._file_contents[rel_path] = content
                except (OSError, UnicodeDecodeError):
                    continue

    def _load_metadata(self) -> None:
        manifest_path = self.target_dir / "manifest.json"
        if manifest_path.is_file():
            try:
                with manifest_path.open(encoding="utf-8-sig") as f:
                    self._package_metadata = json.load(f)
                return
            except (json.JSONDecodeError, OSError):
                pass

        plugin_path = self.target_dir / "plugin.json"
        if plugin_path.is_file():
            try:
                with plugin_path.open(encoding="utf-8-sig") as f:
                    self._package_metadata = json.load(f)
                return
            except (json.JSONDecodeError, OSError):
                pass

        skill_path = self.target_dir / "SKILL.md"
        if skill_path.is_file():
            try:
                content = skill_path.read_text(encoding="utf-8-sig")
                fm = _parse_frontmatter(content)
                if fm:
                    self._package_metadata = fm
            except (OSError, UnicodeDecodeError):
                pass

        # 回退：package.json 补充 SKILL.md frontmatter 未声明的字段
        # （version/license/author 等常见于 npm 风格仓库的 package.json）
        pkg_json_path = self.target_dir / "package.json"
        if pkg_json_path.is_file():
            try:
                with pkg_json_path.open(encoding="utf-8-sig") as f:
                    pkg_json = json.load(f)
                if not self._package_metadata:
                    self._package_metadata = pkg_json
                else:
                    for key in ("name", "version", "description", "license", "author"):
                        if not self._package_metadata.get(key) and pkg_json.get(key):
                            self._package_metadata[key] = pkg_json[key]
            except (json.JSONDecodeError, OSError):
                pass

    def _inject_acquired_source_integrity(self) -> None:
        """Attach facts established by acquisition instead of trusting manifests.

        A repository's own metadata cannot safely attest to the bytes currently
        being scanned.  The scanner therefore computes the canonical content
        tree digest itself and accepts the commit only from the acquisition
        layer (``git rev-parse HEAD`` / GitHub zipball resolution).
        """
        if not self._package_metadata:
            return

        integrity = self._package_metadata.get("integrity")
        if not isinstance(integrity, dict):
            integrity = {}
        integrity["sha256"] = self._content_tree_sha256()
        self._package_metadata["integrity"] = integrity

        if re.fullmatch(r"^[a-f0-9]{40}$", self.source_commit_hash):
            source = self._package_metadata.get("source")
            if not isinstance(source, dict):
                source = {}
            source["commit_hash"] = self.source_commit_hash
            self._package_metadata["source"] = source

    def _content_tree_sha256(self) -> str:
        """Return the canonical package tree hash used by package manifests."""
        digest = hashlib.sha256()
        entries: list[tuple[str, Path]] = []
        for base, dirs, files in os.walk(self.target_dir):
            dirs[:] = sorted(d for d in dirs if d != ".git")
            for name in sorted(files):
                path = Path(base) / name
                rel = path.relative_to(self.target_dir).as_posix()
                # A manifest cannot include its own digest without recursion.
                if rel == "manifest.json":
                    continue
                entries.append((rel, path))

        for rel, path in sorted(entries):
            try:
                data = path.read_bytes()
            except OSError:
                continue
            if b"\0" not in data:
                data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            digest.update(rel.encode("utf-8"))
            digest.update(b"\0")
            digest.update(data)
            digest.update(b"\0")
        return digest.hexdigest()

    def _read_file_content(self, rel_path: str) -> str:
        if rel_path in self._file_contents:
            return self._file_contents[rel_path]
        fpath = self.target_dir / rel_path
        try:
            content = fpath.read_text(encoding="utf-8-sig", errors="ignore")
            self._file_contents[rel_path] = content
            return content
        except OSError:
            return ""

    def _is_code_example(self, file_path: str, line_no: int) -> bool:
        content = self._read_file_content(file_path)
        if not content:
            return False
        ext = Path(file_path).suffix.lower()
        if ext not in (".md", ".markdown", ".txt", ".rst"):
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

    def _is_documentation_file(self, rel_path: str) -> bool:
        """判断文件是否为说明性文档（README/docs/CHANGELOG 等）。

        真正的能力内容（SKILL.md、*.prompt.md、system_prompt.md、agent.json）
        不视为文档，避免削弱提示注入等专项检测。
        """
        normalized = rel_path.replace("\\", "/").lower()
        basename = normalized.rsplit("/", 1)[-1]
        if basename in {
            "skill.md",
            "system_prompt.md",
            "agent.json",
        } or basename.endswith(".prompt.md"):
            return False
        if normalized.startswith("docs/"):
            return True
        if basename.startswith(("readme", "changelog", "release-notes", "notice", "license")):
            return True
        return basename.endswith((".md", ".markdown", ".txt", ".rst"))

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
                finding["downgraded"] = "documentation"
                finding["title"] = f"{finding.get('title', '')} [文档示例/说明文本]"
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
    ) -> None:
        finding: dict[str, Any] = {
            "id": f"finding-{uuid.uuid4().hex[:8]}",
            "rule_id": rule_id,
            "severity": severity,
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

        self.findings.append(finding)

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
        severity_counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        for f in self.findings:
            sev = f.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1

        total = len(self.findings)
        effective_total = sum(
            severity_counts[s] for s in ("critical", "high", "medium", "low")
        )

        # 扫描通过率（0-100）：按严重度罚分，与评分引擎 _compute_pass_rate 同公式
        penalty = sum(
            SEVERITY_POINTS.get(sev, 0) * severity_counts[sev]
            for sev in ("critical", "high", "medium", "low")
        )
        pass_rate = (
            100.0 if effective_total == 0
            else max(0.0, round(100.0 - penalty, 1))
        )

        pkg_name = "unknown"
        pkg_version = "0.0.0"
        if self._package_metadata:
            pkg_name = self._package_metadata.get("name", "unknown")
            pkg_version = self._package_metadata.get("version", "0.0.0")

        metadata_validation: dict[str, Any] = {"valid": True, "errors": []}
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
        for fname in self.scanned_files:
            ext = Path(fname).suffix.lower()
            if ext in DANGEROUS_EXTENSIONS:
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
        cve_findings = [f for f in self.findings if "CVE" in f.get("title", "")]
        dependency_check["known_vulnerabilities"] = len(cve_findings)

        return {
            "scan_id": f"scan-{uuid.uuid4().hex[:12]}",
            "package_name": pkg_name,
            "version": pkg_version,
            "scanned_at": start_time.isoformat(),
            "scanner_version": SCANNER_VERSION,
            "duration_ms": duration_ms,
            "findings": self.findings,
            "summary": {
                "total": total,
                "effective_total": effective_total,
                "critical": severity_counts["critical"],
                "high": severity_counts["high"],
                "medium": severity_counts["medium"],
                "low": severity_counts["low"],
                "info": severity_counts["info"],
                "pass_rate": pass_rate,
            },
            "metadata_validation": metadata_validation,
            "structure_check": structure_check,
            "dependency_check": dependency_check,
        }


def _parse_frontmatter(content: str) -> dict[str, Any] | None:
    if not content.startswith("---"):
        return None

    end_idx = content.find("---", 3)
    if end_idx == -1:
        return None

    fm_text = content[3:end_idx].strip()
    result: dict[str, Any] = {}
    current_key: str | None = None
    current_list: list[str] = []

    for line in fm_text.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("- ") and current_key:
            current_list.append(stripped[2:].strip())
            continue

        if current_key and current_list:
            result[current_key] = current_list
            current_list = []
            current_key = None

        if ":" in stripped:
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            current_key = key
            if value.lower() == "true":
                result[key] = True
            elif value.lower() == "false":
                result[key] = False
            else:
                try:
                    result[key] = int(value)
                except ValueError:
                    try:
                        result[key] = float(value)
                    except ValueError:
                        result[key] = value

    if current_key and current_list:
        result[current_key] = current_list

    return result if result else None


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
