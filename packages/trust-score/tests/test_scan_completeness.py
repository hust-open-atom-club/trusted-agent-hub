from src.intent import assess_prompt_safety
from src.engine import rate


def test_partial_scan_without_dangerous_findings_is_suspicious():
    result = assess_prompt_safety({}, {
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "findings": [],
        "scan_status": {"state": "partial", "conclusion": "inconclusive", "complete": False,
                        "reasons": ["max_file_bytes"]},
    })
    assert result["level"] == "suspicious"
    assert result["scan_complete"] is False
    assert any("max_file_bytes" in item for item in result["evidence"])


def test_engine_does_not_return_trusted_for_partial_scan():
    result = rate(
        package_metadata={"name": "demo", "version": "1.0.0", "permissions": {}},
        scan_report={
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "findings": [],
            "scan_status": {"state": "partial", "conclusion": "inconclusive", "complete": False,
                            "reasons": ["rule_execution_errors"]},
            "rule_execution": {"results": [{"rule_id": "SR-017", "status": "failed"}]},
            "scan_limits": {"skipped": {"count": 2}},
        },
    )
    assert result["dimensions"]["scan_results"]["details"]["scan_complete"] is False
    assert result["dimensions"]["scan_results"]["details"]["failed_rules"] == ["SR-017"]
    assert result["risk_summary"]["level"] != "trusted"
