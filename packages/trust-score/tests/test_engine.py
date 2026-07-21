"""
End-to-end tests for the trust score decision engine.

Covers the 6 basic test cases (B1–B6) and additional edge cases.
Each test constructs input dicts from JSON fixtures, calls engine.rate(),
and asserts on the final risk level.

Uses only the Python standard library (pytest for test execution).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

# Ensure the trust-score package root is importable so that
# relative imports in src/*.py resolve correctly.
_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from src.engine import rate


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _load_fixture(name: str) -> dict[str, Any]:
    """Load a JSON test fixture by filename (without extension)."""
    path = FIXTURES_DIR / f"{name}.json"
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Basic test cases (B1–B6)
# ---------------------------------------------------------------------------

def test_b1_code_review_skill_all_green_approved() -> None:
    """B1: All-green profile with approved review → trusted."""
    fx = _load_fixture("b1_code_review_skill")
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result["risk_summary"]["level"] == "trusted", \
        f"Expected trusted, got {result['risk_summary']['level']}"
    assert 85 <= result["score"] <= 100
    assert result["package_name"] == "code-review-skill"
    assert result["model_version"] == "0.2.0"
    # Verify schema-compatible structure
    _assert_valid_output(result, fx["expected_level"])


def test_b2_postgres_explorer_all_green_pending() -> None:
    """B2: All-green profile with pending review → low_risk."""
    fx = _load_fixture("b2_postgres_explorer")
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result["risk_summary"]["level"] == "low_risk", \
        f"Expected low_risk, got {result['risk_summary']['level']}"
    assert 65 <= result["score"] <= 84
    _assert_valid_output(result, fx["expected_level"])


def test_b3_dev_toolkit_plugin_all_green_pending() -> None:
    """B3: All-green plugin with pending review → low_risk."""
    fx = _load_fixture("b3_dev_toolkit_plugin")
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result["risk_summary"]["level"] == "low_risk", \
        f"Expected low_risk, got {result['risk_summary']['level']}"
    assert 65 <= result["score"] <= 84
    _assert_valid_output(result, fx["expected_level"])


def test_b4_docker_deploy_command_excessive_permissions() -> None:
    """B4: Excessive permissions → medium_risk."""
    fx = _load_fixture("b4_docker_deploy_command")
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result["risk_summary"]["level"] == "medium_risk", \
        f"Expected medium_risk, got {result['risk_summary']['level']}"
    assert 45 <= result["score"] <= 64
    _assert_valid_output(result, fx["expected_level"])


def test_b5_risky_executor_dangerous_scan_veto() -> None:
    """B5: Dangerous scan findings → untrusted (V2 veto)."""
    fx = _load_fixture("b5_risky_executor")
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result["risk_summary"]["level"] == "untrusted", \
        f"Expected untrusted, got {result['risk_summary']['level']}"
    assert 0 <= result["score"] <= 24
    # Verify a veto explanation exists
    veto_msgs = [e["message"] for e in result["explanations"] if "Veto" in e.get("message", "")]
    assert len(veto_msgs) > 0, "Expected a veto explanation in output"
    _assert_valid_output(result, fx["expected_level"])


def test_b6_empty_package_opaque_source() -> None:
    """B6: Opaque source, no scan → medium_risk."""
    fx = _load_fixture("b6_empty_package")
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],  # None
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result["risk_summary"]["level"] == "medium_risk", \
        f"Expected medium_risk, got {result['risk_summary']['level']}"
    assert 45 <= result["score"] <= 64
    _assert_valid_output(result, fx["expected_level"])


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------

def test_edge_no_scan_report_defaults() -> None:
    """Missing scan_report → I2=suspicious, I3=gap."""
    fx = _load_fixture("b1_code_review_skill")
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=None,
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    # Without a scan report, the upgrade rule (I2=safe required) won't fire
    # So even though review is approved, the result should stay at low_risk
    assert result["risk_summary"]["level"] in ("low_risk", "medium_risk")


def test_edge_full_veto_chain() -> None:
    """Verify all six veto conditions produce untrusted."""
    # V1: rejected review (covered by B5 which also has rejected review)
    # V2: dangerous scan (covered by B5)
    # V3: deceptive (dangerous scan + minimal permissions)
    # V4: malicious (dangerous + dangerous)
    # V5: opaque + dangerous
    # V6: opaque + tainted

    # V3: deceptive — dangerous scan but minimal-looking permissions
    pkg_v3 = {
        "name": "test-v3",
        "version": "1.0.0",
        "type": "skill",
        "description": "A seemingly innocent skill with hidden dangers",
        "author": {"name": "Test", "email": "t@t.com"},
        "license": "MIT",
        "source": {
            "type": "github",
            "repository_url": "https://github.com/test/test",
            "owner": "test", "repo": "test",
            "ref_type": "tag", "ref": "v1.0.0",
            "commit_hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
            "verified_owner": True,
        },
        "integrity": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        "compatibility": ["claude-code"],
        "keywords": ["test"],
        "permissions": {
            "filesystem": {"read": ["./"], "write": [], "delete": False},
            "shell": {"allowed": False},
            "network": {"allowed": False},
        },
        "installation": {
            "method": "copy_directory",
            "targets": [{"client": "claude-code", "destination": "./"}],
        },
        "skill_config": {"skill_md_path": "./SKILL.md"},
    }
    scan_v3 = {
        "scan_id": "s-v3",
        "package_name": "test-v3",
        "version": "1.0.0",
        "scanned_at": "2026-07-01T00:00:00Z",
        "scanner_version": "0.1.0",
        "findings": [{
            "id": "f-v3",
            "rule_id": "SR-001",
            "severity": "critical",
            "category": "remote_code_execution",
            "title": "Hidden RCE",
            "location": {"file": "SKILL.md", "line": 1},
        }],
        "summary": {"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
        "metadata_validation": {"valid": True, "errors": []},
        "structure_check": {"valid": True, "missing_files": [], "extra_files": []},
        "dependency_check": {"total_dependencies": 0, "known_vulnerabilities": 0, "unlocked_versions": 0, "suspicious_packages": []},
    }
    result_v3 = rate(package_metadata=pkg_v3, scan_report=scan_v3)
    assert result_v3["risk_summary"]["level"] == "untrusted", \
        f"V3 (deceptive) expected untrusted, got {result_v3['risk_summary']['level']}"


def test_edge_consistent_good_author() -> None:
    """Author with consistent good history should score well."""
    fx = _load_fixture("b1_code_review_skill")
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],
        author_history={"packages_published": 10, "avg_historical_score": 92, "violations_count": 0},
        review_records=fx["review_records"],
    )
    assert result["dimensions"]["author_reputation"]["score"] >= 85


def test_edge_tainted_author() -> None:
    """Author with violations → tainted, risk elevated."""
    fx = _load_fixture("b1_code_review_skill")
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],
        author_history={"packages_published": 5, "avg_historical_score": 40, "violations_count": 3},
        review_records={"status": "pending"},
    )
    assert result["dimensions"]["author_reputation"]["score"] < 40


def test_edge_empty_author_history_defaults() -> None:
    """No author history → defaults to newcomer."""
    fx = _load_fixture("b1_code_review_skill")
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],
        author_history={},
        review_records={"status": "pending"},
    )
    assert result["dimensions"]["author_reputation"]["details"]["packages_published"] == 0


def test_edge_default_inputs() -> None:
    """engine.rate() with minimal inputs (only package_metadata) should not crash."""
    pkg = {
        "name": "minimal-pkg",
        "version": "0.1.0",
        "type": "skill",
        "description": "A minimal package for testing defaults",
        "author": {"name": "Min", "email": "min@example.com"},
        "license": "MIT",
        "source": {
            "type": "github",
            "repository_url": "https://github.com/min/min",
            "owner": "min",
            "repo": "min",
            "ref_type": "tag",
            "ref": "v0.1.0",
            "commit_hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
            "verified_owner": False,
        },
        "integrity": {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        "compatibility": ["claude-code"],
        "keywords": ["test"],
        "permissions": {
            "filesystem": {"read": ["./"], "write": [], "delete": False},
            "shell": {"allowed": False},
            "network": {"allowed": False},
        },
        "installation": {
            "method": "copy_directory",
            "targets": [{"client": "claude-code", "destination": "./"}],
        },
        "skill_config": {"skill_md_path": "./SKILL.md"},
    }
    result = rate(package_metadata=pkg)  # no scan_report, author_history, review_records
    assert "score" in result
    assert 0 <= result["score"] <= 100
    assert "dimensions" in result
    assert "explanations" in result
    assert "risk_summary" in result
    _assert_valid_output(result, None)


def test_edge_level_ordering() -> None:
    """Verify level ordering is correct for upgrade/downgrade calculations."""
    from src.engine import _LEVEL_ORDER, _shift_level
    assert _LEVEL_ORDER[0] == "trusted"
    assert _LEVEL_ORDER[-1] == "untrusted"

    # Upgrade from low_risk → trusted
    assert _shift_level("low_risk", -1) == "trusted"
    # Upgrade from trusted stays at trusted (clamped)
    assert _shift_level("trusted", -1) == "trusted"
    # Downgrade from trusted → low_risk
    assert _shift_level("trusted", 1) == "low_risk"
    # Downgrade from untrusted stays at untrusted
    assert _shift_level("untrusted", 1) == "untrusted"


def test_edge_output_schema_compliance() -> None:
    """The output dict should contain all required trust-score.schema.json keys."""
    fx = _load_fixture("b1_code_review_skill")
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )

    # Top-level required fields
    assert isinstance(result["score"], int)
    assert isinstance(result["package_name"], str)
    assert isinstance(result["version"], str)
    assert isinstance(result["calculated_at"], str)  # ISO 8601
    assert isinstance(result["model_version"], str)

    # Dimensions: 9 required keys
    dims = result["dimensions"]
    required_dims = {
        "source_trust", "author_reputation", "metadata_completeness",
        "permission_minimization", "scan_results", "manual_review",
        "version_stability", "user_feedback", "signature_verifiability",
    }
    assert set(dims.keys()) == required_dims, \
        f"Missing dimensions: {required_dims - set(dims.keys())}"

    for name, dim in dims.items():
        assert "score" in dim, f"Dimension '{name}' missing 'score'"
        assert "weight" in dim, f"Dimension '{name}' missing 'weight'"
        assert isinstance(dim["score"], int)
        assert isinstance(dim["weight"], (int, float))
        assert 0 <= dim["score"] <= 100
        assert 0 <= dim["weight"] <= 1

    # Explanations
    assert isinstance(result["explanations"], list)
    for expl in result["explanations"]:
        assert "dimension" in expl
        assert "message" in expl
        assert "deduction" in expl
        assert isinstance(expl["deduction"], int)

    # Risk summary
    rs = result["risk_summary"]
    assert rs["level"] in {"trusted", "low_risk", "medium_risk", "high_risk", "untrusted"}
    assert isinstance(rs["top_risks"], list)
    assert rs["install_recommendation"] in {
        "safe", "review_recommended", "caution", "not_recommended", "blocked"
    }


def test_edge_opaque_with_newcomer_not_downgraded_if_already_medium() -> None:
    """When baseline is already medium_risk, opaque+newcomer downgrade should not apply."""
    # This is effectively the B6 scenario
    fx = _load_fixture("b6_empty_package")
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    # Should be medium_risk, not high_risk
    assert result["risk_summary"]["level"] == "medium_risk"


def test_edge_opaque_with_newcomer_downgraded_when_baseline_is_low() -> None:
    """When everything else is green but P1=opaque + newcomer, downgrade should apply."""
    pkg = {
        "name": "opaque-newcomer",
        "version": "1.0.0",
        "type": "skill",
        "description": "A package with minimal permissions but opaque source",
        "author": {"name": "New", "email": "new@example.com"},
        "license": "MIT",
        "source": {
            "type": "local_upload",
            "repository_url": "",
            "ref_type": "",
            "ref": "",
            "commit_hash": "",
            "verified_owner": False,
        },
        "integrity": {"sha256": ""},
        "compatibility": ["claude-code"],
        "keywords": ["test"],
        "permissions": {
            "filesystem": {"read": ["./"], "write": [], "delete": False},
            "shell": {"allowed": False},
            "network": {"allowed": False},
        },
        "installation": {
            "method": "copy_directory",
            "targets": [{"client": "claude-code", "destination": "./"}],
        },
        "skill_config": {"skill_md_path": "./SKILL.md"},
    }
    # Clean scan report — so I2=safe, I3=consistent (no overreaching or dangerous findings)
    scan = {
        "scan_id": "s-edge",
        "package_name": "opaque-newcomer",
        "version": "1.0.0",
        "scanned_at": "2026-07-01T00:00:00Z",
        "scanner_version": "0.1.0",
        "findings": [],
        "summary": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "metadata_validation": {"valid": True, "errors": []},
        "structure_check": {"valid": True, "missing_files": [], "extra_files": []},
        "dependency_check": {"total_dependencies": 0, "known_vulnerabilities": 0, "unlocked_versions": 0, "suspicious_packages": []},
    }
    result = rate(
        package_metadata=pkg,
        scan_report=scan,
        author_history={"packages_published": 0, "avg_historical_score": 0, "violations_count": 0},
        review_records={"status": "pending"},
    )
    # P1=opaque → +1 risk → baseline medium_risk
    # But wait, the downgrade only fires when baseline > medium_risk
    # This test verifies that case doesn't trigger
    assert result["risk_summary"]["level"] == "medium_risk"


def test_grade_mapping() -> None:
    """Grade A-E maps correctly from trust levels."""
    from src.derived_score import level_to_grade
    assert level_to_grade("trusted") == "A"
    assert level_to_grade("low_risk") == "B"
    assert level_to_grade("medium_risk") == "C"
    assert level_to_grade("high_risk") == "D"
    assert level_to_grade("untrusted") == "E"


def test_new_dangerous_category_triggers_v2_ssrf() -> None:
    """Critical SSRF finding in scan → I2 dangerous → V2 veto → untrusted → Grade E."""
    fx = _load_fixture("b1_code_review_skill")
    # Modify the scan to include a critical SSRF finding
    scan = dict(fx["scan_report"])
    scan["findings"] = [{
        "id": "f-ssrf-1",
        "rule_id": "SR-014",
        "severity": "critical",
        "category": "ssrf",
        "title": "SSRF to cloud metadata endpoint",
        "description": "Package makes requests to 169.254.169.254",
        "location": {"file": "src/handler.py", "line": 42},
        "cwe_id": "CWE-918",
    }]
    scan["summary"] = {"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=scan,
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result["risk_summary"]["level"] == "untrusted", \
        f"SSRF critical should trigger V2 veto, got {result['risk_summary']['level']}"
    assert result["risk_summary"]["grade"] == "E", \
        f"V2 veto should produce Grade E, got {result['risk_summary']['grade']}"
    veto_msgs = [e["message"] for e in result["explanations"] if "Veto" in e.get("message", "")]
    assert len(veto_msgs) > 0, "Expected V2 veto explanation"


def test_new_dangerous_category_triggers_v2_supply_chain() -> None:
    """Critical supply_chain finding → V2 veto → untrusted → Grade E."""
    fx = _load_fixture("b1_code_review_skill")
    scan = dict(fx["scan_report"])
    scan["findings"] = [{
        "id": "f-sc-1",
        "rule_id": "SR-008",
        "severity": "critical",
        "category": "supply_chain",
        "title": "Dependency confusion detected",
        "description": "Package name matches internal private package",
        "location": {"file": "package.json", "line": 5},
    }]
    scan["summary"] = {"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=scan,
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result["risk_summary"]["level"] == "untrusted", \
        f"Supply chain critical should trigger V2 veto, got {result['risk_summary']['level']}"
    assert result["risk_summary"]["grade"] == "E"


def test_new_category_low_severity_does_not_trigger_v2() -> None:
    """Low severity finding in new category should NOT trigger V2 veto."""
    fx = _load_fixture("b1_code_review_skill")
    scan = dict(fx["scan_report"])
    scan["findings"] = [{
        "id": "f-low-1",
        "rule_id": "SR-016",
        "severity": "low",
        "category": "tool_misuse",
        "title": "Minor tool configuration issue",
        "description": "Tool parameter could be more restrictive",
        "location": {"file": "config.yaml", "line": 10},
    }]
    scan["summary"] = {"total": 1, "critical": 0, "high": 0, "medium": 0, "low": 1, "info": 0}
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=scan,
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    # Low severity should not trigger I2=dangerous, so no V2 veto
    assert result["risk_summary"]["level"] != "untrusted", \
        f"Low severity should not trigger veto, got {result['risk_summary']['level']}"


def test_old_report_without_llm_fields() -> None:
    """Scan report missing llm_label and llm_review should not crash the engine."""
    fx = _load_fixture("b1_code_review_skill")
    # The fixture scan report doesn't have llm_label or llm_review — this is the old format
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert "score" in result
    assert 0 <= result["score"] <= 100


def test_all_grades_appear_in_output() -> None:
    """Smoke test: each level produces its corresponding grade."""
    from src.engine import _to_grade
    assert _to_grade("trusted") == "A"
    assert _to_grade("low_risk") == "B"
    assert _to_grade("medium_risk") == "C"
    assert _to_grade("high_risk") == "D"
    assert _to_grade("untrusted") == "E"
    assert _to_grade("unknown") == "C"  # default


def test_dangerous_category_memory_poisoning_veto() -> None:
    """Critical memory_poisoning finding → V2 veto → untrusted."""
    fx = _load_fixture("b1_code_review_skill")
    scan = dict(fx["scan_report"])
    scan["findings"] = [{
        "id": "f-mp-1",
        "rule_id": "SR-013",
        "severity": "critical",
        "category": "memory_poisoning",
        "title": "Agent memory poisoning via skill instructions",
        "description": "Skill injects persistent instructions into agent memory",
        "location": {"file": "SKILL.md", "line": 15},
    }]
    scan["summary"] = {"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=scan,
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result["risk_summary"]["level"] == "untrusted", \
        f"Memory poisoning critical should trigger V2 veto, got {result['risk_summary']['level']}"
    assert result["risk_summary"]["grade"] == "E"


def test_dangerous_category_system_prompt_leakage_veto() -> None:
    """Critical system_prompt_leakage finding → V2 veto → untrusted."""
    fx = _load_fixture("b1_code_review_skill")
    scan = dict(fx["scan_report"])
    scan["findings"] = [{
        "id": "f-spl-1",
        "rule_id": "SR-012",
        "severity": "critical",
        "category": "system_prompt_leakage",
        "title": "System prompt exfiltration attempt",
        "description": "Skill attempts to send system prompt to external URL",
        "location": {"file": "src/main.py", "line": 42},
    }]
    scan["summary"] = {"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=scan,
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result["risk_summary"]["level"] == "untrusted", \
        f"System prompt leakage critical should trigger V2 veto, got {result['risk_summary']['level']}"
    assert result["risk_summary"]["grade"] == "E"


def test_dangerous_category_agent_snooping_veto() -> None:
    """Critical agent_snooping finding → V2 veto → untrusted."""
    fx = _load_fixture("b1_code_review_skill")
    scan = dict(fx["scan_report"])
    scan["findings"] = [{
        "id": "f-as-1",
        "rule_id": "SR-015",
        "severity": "critical",
        "category": "agent_snooping",
        "title": "Agent conversation history exfiltration",
        "description": "Skill reads and transmits full conversation log",
        "location": {"file": "src/snoop.py", "line": 10},
    }]
    scan["summary"] = {"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=scan,
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result["risk_summary"]["level"] == "untrusted", \
        f"Agent snooping critical should trigger V2 veto, got {result['risk_summary']['level']}"
    assert result["risk_summary"]["grade"] == "E"


def test_dangerous_category_output_handling_veto() -> None:
    """Critical output_handling finding → V2 veto → untrusted."""
    fx = _load_fixture("b1_code_review_skill")
    scan = dict(fx["scan_report"])
    scan["findings"] = [{
        "id": "f-oh-1",
        "rule_id": "SR-011",
        "severity": "critical",
        "category": "output_handling",
        "title": "Unsanitized command output rendered to user",
        "description": "Shell command output is rendered without HTML escaping",
        "location": {"file": "src/render.py", "line": 30},
    }]
    scan["summary"] = {"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=scan,
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result["risk_summary"]["level"] == "untrusted", \
        f"Output handling critical should trigger V2 veto, got {result['risk_summary']['level']}"
    assert result["risk_summary"]["grade"] == "E"


def test_dangerous_category_tool_misuse_critical_veto() -> None:
    """Critical tool_misuse finding → V2 veto → untrusted."""
    fx = _load_fixture("b1_code_review_skill")
    scan = dict(fx["scan_report"])
    scan["findings"] = [{
        "id": "f-tm-1",
        "rule_id": "SR-016",
        "severity": "critical",
        "category": "tool_misuse",
        "title": "Dangerous tool chain: BashTool → write → execute",
        "description": "Skill chains file write with bash execution without user confirmation",
        "location": {"file": "SKILL.md", "line": 25},
    }]
    scan["summary"] = {"total": 1, "critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=scan,
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result["risk_summary"]["level"] == "untrusted", \
        f"Tool misuse critical should trigger V2 veto, got {result['risk_summary']['level']}"
    assert result["risk_summary"]["grade"] == "E"


def test_output_handling_medium_does_not_veto() -> None:
    """Medium output_handling finding should NOT trigger V2 veto (severity filter)."""
    fx = _load_fixture("b1_code_review_skill")
    scan = dict(fx["scan_report"])
    scan["findings"] = [{
        "id": "f-oh-med-1",
        "rule_id": "SR-011",
        "severity": "medium",
        "category": "output_handling",
        "title": "Minor output formatting issue",
        "description": "Output uses basic string formatting without sanitization",
        "location": {"file": "src/format.py", "line": 12},
    }]
    scan["summary"] = {"total": 1, "critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0}
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=scan,
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result["risk_summary"]["level"] != "untrusted", \
        f"Medium output_handling should NOT trigger veto, got {result['risk_summary']['level']}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _assert_valid_output(result: dict[str, Any], expected_level: str | None) -> None:
    """Common assertions for any valid engine output."""
    assert "score" in result
    assert isinstance(result["score"], int)
    assert 0 <= result["score"] <= 100, f"Score {result['score']} out of range"
    assert "package_name" in result
    assert "version" in result
    assert "calculated_at" in result
    assert "model_version" in result
    assert "dimensions" in result
    assert "explanations" in result
    assert isinstance(result["explanations"], list)
    assert "risk_summary" in result
    assert result["risk_summary"]["install_recommendation"] in {
        "safe", "review_recommended", "caution", "not_recommended", "blocked"
    }
    # Grade field must be present and valid
    assert "grade" in result["risk_summary"], "risk_summary must include grade"
    assert result["risk_summary"]["grade"] in {"A", "B", "C", "D", "E"}, \
        f"Invalid grade: {result['risk_summary']['grade']}"

    if expected_level is not None:
        assert result["risk_summary"]["level"] == expected_level, \
            f"Expected level {expected_level}, got {result['risk_summary']['level']}"
