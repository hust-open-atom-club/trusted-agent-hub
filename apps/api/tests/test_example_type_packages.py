"""验证 examples/subagents|commands|prompts 三种新类型示例包。

覆盖三个层面（与 test_real_world_manifests.py 互补）：
1. manifest 符合 agent-package.schema.json；
2. integrity.sha256 与包内容树哈希一致；
3. 扫描器检出效果：风险样例必须命中目标规则（SR-019/SR-002/SR-001/SR-012），
   规范样例不得出现 critical/high 真实风险（允许 SR-009 签名/SBOM 提示，与 real-world 官方包同级）。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = PROJECT_ROOT / "packages" / "schema" / "agent-package.schema.json"
EXAMPLES_DIR = PROJECT_ROOT / "examples"

sys.path.insert(0, str(PROJECT_ROOT))
from scripts.compute_package_hash import tree_hash
from scanners.risk_scanner.scanner import RiskScanner

# 三种新类型的包目录（规范 + 风险）
_TYPE_DIRS = ["subagents", "commands", "prompts"]

# 风险样例的目标规则：该规则必须出现在扫描结果中
_RISK_EXPECTATIONS: dict[str, set[str]] = {
    "risky-subagent-exfil": {"SR-019", "SR-003"},
    "risky-command-wipe": {"SR-002"},
    "risky-prompt-injection-2": {"SR-001", "SR-012"},
}


def _manifests() -> list[Path]:
    """examples/{subagents,commands,prompts}/**/manifest.json"""
    return sorted(
        p
        for d in _TYPE_DIRS
        for p in (EXAMPLES_DIR / d).rglob("manifest.json")
    )


@pytest.mark.parametrize(
    "manifest_path",
    _manifests(),
    ids=lambda p: p.parent.name,
)
def test_type_package_manifest_schema(manifest_path: Path) -> None:
    """新类型示例包必须符合 agent-package.schema.json。"""
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    jsonschema.validate(data, schema)


@pytest.mark.parametrize(
    "manifest_path",
    _manifests(),
    ids=lambda p: p.parent.name,
)
def test_type_package_integrity(manifest_path: Path) -> None:
    """manifest 声明的 integrity.sha256 必须与包内容树哈希一致。"""
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = data["integrity"]["sha256"]
    assert tree_hash(manifest_path.parent) == expected


@pytest.mark.parametrize(
    "manifest_path",
    _manifests(),
    ids=lambda p: p.parent.name,
)
def test_type_package_scan_profile(manifest_path: Path) -> None:
    """扫描器检出效果：
    - 风险样例必须命中其目标规则；
    - 规范样例不得出现 critical/high 的真实风险。
    """
    pkg_name = manifest_path.parent.name
    report = RiskScanner(manifest_path.parent).scan()
    rule_ids = {f.get("rule_id") for f in report["findings"]}
    sev = {f.get("severity") for f in report["findings"]}

    if pkg_name in _RISK_EXPECTATIONS:
        for expected_rule in _RISK_EXPECTATIONS[pkg_name]:
            assert expected_rule in rule_ids, (
                f"{pkg_name} 未命中预期规则 {expected_rule}，实际: {sorted(rule_ids)}"
            )
    else:
        # 规范样例: 不允许 critical/high 发现（SR-009 medium 签名/SBOM 提示可接受）
        assert "critical" not in sev, f"{pkg_name} 出现 critical 发现: {report['findings']}"
        assert "high" not in sev, f"{pkg_name} 出现 high 发现: {report['findings']}"
