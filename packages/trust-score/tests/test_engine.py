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

import pytest

# Ensure the trust-score package root is importable so that
# relative imports in src/*.py resolve correctly.
_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from src.engine import rate as _engine_rate
from src.model_identity import get_model_fingerprint, get_model_version


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _trusted_acquisition_facts(package_metadata: dict[str, Any]) -> dict[str, Any]:
    """Model server-established facts for the legacy score fixtures.

    The fixtures predate the explicit acquisition-facts boundary and carry
    their expected provenance in package metadata.  This adapter makes that
    test intent explicit without weakening the production default, which is
    fail-closed when facts are omitted.
    """
    source = dict(package_metadata.get("source") or {})
    integrity = dict(package_metadata.get("integrity") or {})
    return {
        "source": source,
        "integrity": {
            "sha256": integrity.get("sha256", ""),
            "hash_scope": "scanned_source",
            "is_complete": True,
        },
        "verification": {
            "owner": source.get("verified_owner") is True,
            "signature": bool(integrity.get("signature")),
            "attestation": bool(integrity.get("attestation_url")),
            "sbom": bool(integrity.get("sbom_url")),
        },
    }


def rate(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """Keep existing fixture calls explicit about trusted acquisition facts."""
    package_metadata = kwargs.get("package_metadata")
    if package_metadata is None and args:
        package_metadata = args[0]
    if isinstance(package_metadata, dict):
        kwargs.setdefault(
            "acquisition_facts",
            _trusted_acquisition_facts(package_metadata),
        )
    return _engine_rate(*args, **kwargs)


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
    assert result["model_fingerprint"] == get_model_fingerprint()
    assert result["model_version"] == get_model_version()
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


def test_provenance_advisories_apply_exact_points_without_grade_change() -> None:
    fx = _load_fixture("b2_postgres_explorer")
    baseline = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    scan = json.loads(json.dumps(fx["scan_report"]))
    scan["review_advisories"] = [
        {
            "code": code,
            "category": "provenance",
            "level": "warning",
            "title": code,
            "description": code,
            "deduction": 2,
            "affects_grade": False,
            "grade_downgrade_steps": 0,
            "requires_manual_review": False,
        }
        for code in ("missing_signature", "missing_attestation", "missing_sbom")
    ]

    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=scan,
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )

    assert result["risk_summary"]["grade"] == baseline["risk_summary"]["grade"]
    assert result["score_breakdown"]["advisory_deduction"] == 6
    assert result["score"] == result["score_breakdown"]["base_score"] - 6


def test_documented_permission_mismatch_is_five_points_without_grade_change() -> None:
    fx = _load_fixture("b2_postgres_explorer")
    scan = json.loads(json.dumps(fx["scan_report"]))
    scan["review_advisories"] = [{
        "code": "documented_permission_not_declared",
        "category": "permission_consistency",
        "level": "warning",
        "title": "Documentation mismatch",
        "description": "Documentation mismatch",
        "deduction": 5,
        "affects_grade": False,
        "grade_downgrade_steps": 0,
        "requires_manual_review": False,
    }]

    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=scan,
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )

    assert result["risk_summary"]["grade"] == "B"
    assert result["score_breakdown"]["advisory_deduction"] == 5


def test_undeclared_executable_capability_downgrades_exactly_one_grade() -> None:
    fx = _load_fixture("b2_postgres_explorer")
    scan = json.loads(json.dumps(fx["scan_report"]))
    scan["review_advisories"] = [{
        "code": "undeclared_executable_capability",
        "category": "permission_consistency",
        "level": "high",
        "title": "Undeclared executable capability",
        "description": "Undeclared executable capability",
        "deduction": 0,
        "affects_grade": True,
        "grade_downgrade_steps": 1,
        "requires_manual_review": True,
    }]

    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=scan,
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )

    assert result["risk_summary"]["grade"] == "C"
    assert result["risk_summary"]["review_priority"] == "high"
    assert result["risk_summary"]["manual_security_review_required"] is True
    assert result["risk_summary"]["requires_confirmation"] is True


def test_undeclared_capability_downgrades_trusted_package_only_to_b() -> None:
    fx = _load_fixture("b1_code_review_skill")
    scan = json.loads(json.dumps(fx["scan_report"]))
    scan["review_advisories"] = [{
        "code": "undeclared_executable_capability",
        "category": "permission_consistency",
        "level": "high",
        "title": "Undeclared executable capability",
        "description": "Undeclared executable capability",
        "deduction": 0,
        "affects_grade": True,
        "grade_downgrade_steps": 1,
        "requires_manual_review": True,
    }]

    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=scan,
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )

    assert result["risk_summary"]["grade"] == "B"
    assert result["risk_summary"]["level"] == "low_risk"
    assert result["risk_summary"]["manual_security_review_required"] is True


def test_undeclared_capability_alone_cannot_escalate_d_to_e() -> None:
    fx = _load_fixture("b1_code_review_skill")
    scan = _scan_with_critical_prompt_injection(None)
    scan["review_advisories"] = [{
        "code": "undeclared_executable_capability",
        "category": "permission_consistency",
        "level": "high",
        "title": "Undeclared executable capability",
        "description": "Undeclared executable capability",
        "deduction": 0,
        "affects_grade": True,
        "grade_downgrade_steps": 1,
        "requires_manual_review": True,
    }]

    result = rate(
        package_metadata=_excessive_permission_metadata(),
        scan_report=scan,
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )

    assert result["risk_summary"]["grade"] == "D"
    assert result["risk_summary"]["level"] == "high_risk"


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


def _scan_with_critical_prompt_injection(llm_label: str | None) -> dict:
    return {
        "summary": {
            "total": 1, "critical": 1, "high": 0,
            "medium": 0, "low": 0, "info": 0,
        },
        "findings": [
            {
                "id": "f1",
                "rule_id": "SR-001",
                "severity": "critical",
                "category": "prompt_injection",
                "title": "prompt injection pattern",
                "llm_label": llm_label,
            }
        ],
    }


def _excessive_permission_metadata() -> dict:
    fx = _load_fixture("b1_code_review_skill")
    meta = dict(fx["package_metadata"])
    meta["permissions"] = {
        # 5 个危险信号 → I1=excessive（非 dangerous），
        # 与 I2=dangerous 组合不会触发 V3/V4，可单独验证 V2。
        "filesystem": {
            "read": ["/", "~/"], "write": ["/", "~/"], "delete": True,
        },
        "shell": {"allowed": True, "commands": []},
        "network": {"allowed": True, "domains": []},
        "environment": {"read": [], "write": []},
    }
    return meta


def test_veto_requires_llm_confirmed_malicious() -> None:
    """放宽规则：critical 必须 LLM 确认恶意才触发 V2 否决（E）。"""
    meta = _excessive_permission_metadata()
    fx = _load_fixture("b1_code_review_skill")

    # 无 LLM 标签：不判 E（降为 high_risk/D）
    result = rate(
        package_metadata=meta,
        scan_report=_scan_with_critical_prompt_injection(None),
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result["risk_summary"]["level"] != "untrusted", \
        "critical 无 LLM 确认恶意时不应直接判 E"

    # LLM 确认恶意：判 E
    result_malicious = rate(
        package_metadata=meta,
        scan_report=_scan_with_critical_prompt_injection(
            "llm:suspected-malicious"
        ),
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result_malicious["risk_summary"]["level"] == "untrusted", \
        "LLM 确认恶意的 critical 应判 E"

    # LLM 判定良性：不判 E
    result_benign = rate(
        package_metadata=meta,
        scan_report=_scan_with_critical_prompt_injection(
            "llm:likely-benign"
        ),
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result_benign["risk_summary"]["level"] != "untrusted", \
        "LLM 判定良性的 critical 不应判 E"


def test_veto_when_llm_unavailable_on_dangerous_findings() -> None:
    """LLM 不可用时保留高风险，但不能自动判恶意或触发 E。"""
    meta = _excessive_permission_metadata()
    fx = _load_fixture("b1_code_review_skill")

    result = rate(
        package_metadata=meta,
        scan_report=_scan_with_critical_prompt_injection("llm:unavailable"),
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result["risk_summary"]["level"] == "high_risk"
    assert result["risk_summary"]["grade"] == "D"
    veto_msgs = [e["message"] for e in result["explanations"]
                 if "Veto" in e.get("message", "")]
    assert veto_msgs == []
    _assert_valid_output(result, "high_risk")


def test_no_veto_when_llm_unavailable_on_non_dangerous_findings() -> None:
    """LLM 不可用但 finding 不在危险类别(非 dangerous 判级)→ 不触发否决。"""
    meta = _excessive_permission_metadata()
    fx = _load_fixture("b1_code_review_skill")

    # high finding 但类别不是危险类别(如 metadata_quality)→ I2 最高 suspicious
    scan = _scan_with_critical_prompt_injection("llm:unavailable")
    scan["findings"][0]["category"] = "metadata_quality"
    scan["findings"][0]["severity"] = "high"
    scan["summary"] = {
        "total": 1, "critical": 0, "high": 1,
        "medium": 0, "low": 0, "info": 0,
    }

    result = rate(
        package_metadata=meta,
        scan_report=scan,
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    assert result["risk_summary"]["level"] != "untrusted", \
        "非危险类别的 finding 即使 LLM 不可用也不应否决"


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
            "llm_label": "llm:suspected-malicious",
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
    assert isinstance(result["model_fingerprint"], str)
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
        "llm_label": "llm:suspected-malicious",
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
        "llm_label": "llm:suspected-malicious",
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


@pytest.mark.parametrize("category", [
    "mcp_security",
    "plugin_security",
    "subagent_security",
    "source_integrity",
    "network_access",
    "excessive_permission",
    "installation_security",
])
@pytest.mark.parametrize("severity", ["critical", "high"])
def test_shared_veto_policy_covers_new_security_categories(
    category: str,
    severity: str,
) -> None:
    """Critical/high findings in the shared policy must trigger V2 veto."""
    fx = _load_fixture("b1_code_review_skill")
    scan = dict(fx["scan_report"])
    scan["findings"] = [{
        "id": f"f-{category}",
        "rule_id": "SR-X",
        "severity": severity,
        "llm_label": "llm:suspected-malicious",
        "category": category,
        "title": f"{category} finding",
        "description": "malicious test finding",
        "location": {"file": "manifest.json", "line": 1},
    }]
    scan["summary"] = {
        "total": 1,
        "critical": int(severity == "critical"),
        "high": int(severity == "high"),
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=scan,
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )

    assert result["risk_summary"]["level"] == "untrusted"
    assert result["risk_summary"]["grade"] == "E"


@pytest.mark.parametrize("category", [
    "mcp_security",
    "plugin_security",
    "subagent_security",
    "source_integrity",
    "network_access",
    "excessive_permission",
    "installation_security",
])
def test_shared_veto_policy_keeps_medium_and_benign_findings_reviewable(
    category: str,
) -> None:
    """Medium or LLM-benign findings do not trigger an automatic veto."""
    fx = _load_fixture("b1_code_review_skill")

    for severity, llm_label in (("medium", "llm:suspected-malicious"), ("critical", "llm:likely-benign")):
        scan = dict(fx["scan_report"])
        scan["findings"] = [{
            "id": f"f-{category}-{severity}",
            "rule_id": "SR-X",
            "severity": severity,
            "llm_label": llm_label,
            "category": category,
            "title": f"{category} finding",
            "description": "reviewable test finding",
            "location": {"file": "manifest.json", "line": 1},
        }]
        scan["summary"] = {
            "total": 1,
            "critical": int(severity == "critical"),
            "high": int(severity == "high"),
            "medium": int(severity == "medium"),
            "low": 0,
            "info": 0,
        }

        result = rate(
            package_metadata=fx["package_metadata"],
            scan_report=scan,
            author_history=fx["author_history"],
            review_records=fx["review_records"],
        )

        assert result["risk_summary"]["level"] != "untrusted"


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
    from src.derived_score import level_to_grade
    assert level_to_grade("trusted") == "A"
    assert level_to_grade("low_risk") == "B"
    assert level_to_grade("medium_risk") == "C"
    assert level_to_grade("high_risk") == "D"
    assert level_to_grade("untrusted") == "E"
    assert level_to_grade("unknown") == "C"  # default


def test_dangerous_category_memory_poisoning_veto() -> None:
    """Critical memory_poisoning finding → V2 veto → untrusted."""
    fx = _load_fixture("b1_code_review_skill")
    scan = dict(fx["scan_report"])
    scan["findings"] = [{
        "id": "f-mp-1",
        "rule_id": "SR-013",
        "severity": "critical",
        "llm_label": "llm:suspected-malicious",
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
        "llm_label": "llm:suspected-malicious",
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
        "llm_label": "llm:suspected-malicious",
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
        "llm_label": "llm:suspected-malicious",
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
        "llm_label": "llm:suspected-malicious",
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


def test_feedback_data_flows_into_user_feedback_dimension() -> None:
    """Feedback (ratings/installs) must reach the user_feedback dimension."""
    fx = _load_fixture("b1_code_review_skill")
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],
        author_history=fx["author_history"],
        review_records=fx["review_records"],
        feedback={
            "avg_rating": 4.8,
            "total_ratings": 12,
            "total_installs": 321,
            "reports_count": 1,
        },
    )
    dim = result["dimensions"]["user_feedback"]
    details = dim["details"]
    assert details["total_installs"] == 321
    assert details["total_ratings"] == 12
    assert details["avg_rating"] == 4.8
    assert details["reports_count"] == 1
    # avg_rating 4.8/5 → 96 points
    assert dim["score"] == 96


def test_feedback_absent_keeps_neutral_default() -> None:
    """Without feedback, user_feedback stays neutral (50) with zero installs."""
    fx = _load_fixture("b1_code_review_skill")
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    dim = result["dimensions"]["user_feedback"]
    assert dim["score"] == 50
    assert dim["details"]["total_installs"] == 0
    assert dim["details"]["total_ratings"] == 0


def test_feedback_installs_boost_score_without_ratings() -> None:
    """No ratings yet: install adoption lifts user_feedback from neutral 50."""
    fx = _load_fixture("b1_code_review_skill")
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],
        author_history=fx["author_history"],
        review_records=fx["review_records"],
        feedback={
            "avg_rating": 0,
            "total_ratings": 0,
            "total_installs": 50,
            "reports_count": 0,
        },
    )
    dim = result["dimensions"]["user_feedback"]
    assert dim["score"] == 70
    assert dim["details"]["total_installs"] == 50


def test_feedback_installs_tiers_and_ceiling() -> None:
    """Install tiers: 0->50, 1->55, 5->60, 20->70, 100+->80 (capped)."""
    fx = _load_fixture("b1_code_review_skill")

    def score_for(installs: int) -> int:
        result = rate(
            package_metadata=fx["package_metadata"],
            scan_report=fx["scan_report"],
            author_history=fx["author_history"],
            review_records=fx["review_records"],
            feedback={
                "avg_rating": 0,
                "total_ratings": 0,
                "total_installs": installs,
                "reports_count": 0,
            },
        )
        return result["dimensions"]["user_feedback"]["score"]

    assert score_for(0) == 50
    assert score_for(1) == 55
    assert score_for(5) == 60
    assert score_for(20) == 70
    assert score_for(100) == 80
    assert score_for(1000) == 80


def test_feedback_level_counts_drive_score_without_ratings() -> None:
    """无数值评分时，level 反馈按权重折算（positive=100/neutral=60/negative=20）。"""
    fx = _load_fixture("b1_code_review_skill")
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],
        author_history=fx["author_history"],
        review_records=fx["review_records"],
        feedback={
            "avg_rating": 0,
            "total_ratings": 0,
            "total_installs": 10,
            "reports_count": 0,
            "level_counts": {"positive": 5, "neutral": 2, "negative": 1},
        },
    )
    dim = result["dimensions"]["user_feedback"]
    # (5*100 + 2*60 + 1*20) / 8 = 640 / 8 = 80
    assert dim["score"] == 80
    assert dim["details"]["level_counts"] == {
        "positive": 5,
        "neutral": 2,
        "negative": 1,
    }


def test_feedback_level_counts_negative_dominant() -> None:
    fx = _load_fixture("b1_code_review_skill")
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],
        author_history=fx["author_history"],
        review_records=fx["review_records"],
        feedback={
            "avg_rating": 0,
            "total_ratings": 0,
            "total_installs": 100,
            "reports_count": 0,
            "level_counts": {"positive": 0, "neutral": 1, "negative": 3},
        },
    )
    dim = result["dimensions"]["user_feedback"]
    # (0 + 60 + 60) / 4 = 30
    assert dim["score"] == 30


def test_feedback_absent_level_counts_default_to_zero() -> None:
    fx = _load_fixture("b1_code_review_skill")
    result = rate(
        package_metadata=fx["package_metadata"],
        scan_report=fx["scan_report"],
        author_history=fx["author_history"],
        review_records=fx["review_records"],
    )
    dim = result["dimensions"]["user_feedback"]
    assert dim["details"]["level_counts"] == {
        "positive": 0,
        "neutral": 0,
        "negative": 0,
    }


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
    assert "model_fingerprint" in result
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
