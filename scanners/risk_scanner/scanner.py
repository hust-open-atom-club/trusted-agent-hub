"""
Risk Scanner — 自动风险扫描器 v0.2.0

遍历目标目录，运行 17 条静态分析规则，检测 Agent 能力包中的安全风险。
输出格式严格遵循 scan-report.schema.json。

规则列表:
  SR-001:  提示注入检测
  SR-001b: 反拒绝机制检测
  SR-002:  危险 Shell 命令
  SR-003:  凭据访问
  SR-004:  硬编码密钥
  SR-005:  远程代码执行
  SR-006:  过度权限声明
  SR-007:  网络访问无白名单
  SR-008:  供应链风险
  SR-009:  来源完整性
  SR-010:  元数据质量 + 结构校验
  SR-011:  输出处理风险
  SR-012:  系统提示泄漏
  SR-013:  记忆投毒
  SR-014:  SSRF
  SR-015:  Agent 窥探
  SR-016:  工具滥用
  SR-017:  MCP 安全 (占位符)

用法:
    from scanners.risk_scanner.scanner import RiskScanner
    scanner = RiskScanner("/path/to/package")
    report = scanner.scan()
"""

from __future__ import annotations

import importlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanners.risk_scanner.common import DANGEROUS_EXTENSIONS, REQUIRED_FILES_BY_TYPE


_RULE_MODULES: list[str] = [
    "scanners.risk_scanner.rules.prompt_injection",
    "scanners.risk_scanner.rules.anti_refusal",
    "scanners.risk_scanner.rules.dangerous_shell",
    "scanners.risk_scanner.rules.credential_access",
    "scanners.risk_scanner.rules.hardcoded_secrets",
    "scanners.risk_scanner.rules.rce",
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
    "scanners.risk_scanner.rules.mcp_placeholder",
]

SCANNER_VERSION = "0.2.0"


class RiskScanner:
    """自动风险扫描器 — 静态分析 Agent 能力包目录。"""

    def __init__(self, target_dir: str | Path) -> None:
        self.target_dir = Path(target_dir).resolve()
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

        for rule_module in _RULE_MODULES:
            try:
                mod = importlib.import_module(rule_module)
                mod.run(self)
            except (ModuleNotFoundError, AttributeError) as e:
                pass

        end = datetime.now(timezone.utc)
        duration_ms = int((end - start).total_seconds() * 1000)

        return self._build_report(start, duration_ms)

    def _collect_files(self) -> None:
        for root, dirs, files in os.walk(self.target_dir):
            dirs[:] = [d for d in dirs if d != ".git"]
            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix.lower() in DANGEROUS_EXTENSIONS:
                    try:
                        self.scanned_files.append(str(fpath.relative_to(self.target_dir)))
                    except ValueError:
                        pass
                    continue
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    if len(content) == 0:
                        continue
                    rel_path = str(fpath.relative_to(self.target_dir)).replace("\\", "/")
                    self.scanned_files.append(rel_path)
                    self._file_contents[rel_path] = content
                except (OSError, UnicodeDecodeError):
                    continue

    def _load_metadata(self) -> None:
        manifest_path = self.target_dir / "manifest.json"
        if manifest_path.is_file():
            try:
                self._package_metadata = json.loads(manifest_path.open(encoding="utf-8"))
                return
            except (json.JSONDecodeError, OSError):
                pass

        plugin_path = self.target_dir / "plugin.json"
        if plugin_path.is_file():
            try:
                self._package_metadata = json.loads(plugin_path.open(encoding="utf-8"))
                return
            except (json.JSONDecodeError, OSError):
                pass

        skill_path = self.target_dir / "SKILL.md"
        if skill_path.is_file():
            try:
                content = skill_path.read_text(encoding="utf-8")
                fm = _parse_frontmatter(content)
                if fm:
                    self._package_metadata = fm
            except (OSError, UnicodeDecodeError):
                pass

    def _read_file_content(self, rel_path: str) -> str:
        if rel_path in self._file_contents:
            return self._file_contents[rel_path]
        fpath = self.target_dir / rel_path
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
            self._file_contents[rel_path] = content
            return content
        except OSError:
            return ""

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

    def _build_report(self, start_time: datetime, duration_ms: int) -> dict[str, Any]:
        severity_counts: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
        }
        for f in self.findings:
            sev = f.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1

        total = len(self.findings)

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
                "critical": severity_counts["critical"],
                "high": severity_counts["high"],
                "medium": severity_counts["medium"],
                "low": severity_counts["low"],
                "info": severity_counts["info"],
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
