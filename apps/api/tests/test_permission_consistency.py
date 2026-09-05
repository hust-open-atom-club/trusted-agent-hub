from scanners.risk_scanner.permission_consistency import (
    build_permission_advisories,
    reconcile_permission_advisories,
)


def _evidence(
    capability: str,
    status: str,
    source: str,
    confidence: float = 0.95,
) -> dict[str, object]:
    return {
        "capability": capability,
        "status": status,
        "source": source,
        "confidence": confidence,
        "file": "SKILL.md" if source == "docs" else "src/main.py",
        "evidence": capability,
    }


def test_observed_code_without_declaration_is_one_high_advisory() -> None:
    advisories = build_permission_advisories([
        _evidence("shell", "observed", "code"),
        _evidence("network", "observed", "code"),
        _evidence("filesystem.write", "observed", "code"),
    ])

    assert len(advisories) == 1
    advisory = advisories[0]
    assert advisory["code"] == "undeclared_executable_capability"
    assert advisory["level"] == "high"
    assert advisory["grade_downgrade_steps"] == 1
    assert advisory["deduction"] == 0
    assert advisory["requires_manual_review"] is True


def test_explicit_root_declaration_covers_nested_code_evidence() -> None:
    advisories = build_permission_advisories([
        _evidence("filesystem", "declared", "manifest", 1.0),
        _evidence("filesystem.write", "observed", "code"),
    ])

    assert advisories == []


def test_read_declaration_does_not_cover_observed_write() -> None:
    advisories = build_permission_advisories([
        _evidence("filesystem.read", "declared", "manifest", 1.0),
        _evidence("filesystem.write", "observed", "code"),
    ])

    assert [item["code"] for item in advisories] == [
        "undeclared_executable_capability"
    ]


def test_documentation_mismatch_is_fixed_five_point_non_grading_advisory() -> None:
    advisories = build_permission_advisories([
        _evidence("shell", "conditional", "docs", 0.6),
        _evidence("network", "conditional", "docs", 0.6),
        _evidence("filesystem.write", "conditional", "docs", 0.65),
    ])

    assert len(advisories) == 1
    advisory = advisories[0]
    assert advisory["code"] == "documented_permission_not_declared"
    assert advisory["deduction"] == 5
    assert advisory["affects_grade"] is False
    assert advisory["grade_downgrade_steps"] == 0
    assert advisory["requires_manual_review"] is False


def test_low_confidence_mentions_do_not_create_advisory() -> None:
    assert build_permission_advisories([
        _evidence("network", "mentioned", "docs", 0.3),
        _evidence("shell", "observed", "code", 0.5),
    ]) == []


def test_package_owned_cleanup_does_not_require_broad_delete_declaration() -> None:
    assert build_permission_advisories([
        _evidence("filesystem.delete_own_state", "observed", "code"),
    ]) == []


def test_reconciliation_preserves_other_advisories_and_refreshes_summary() -> None:
    report = {
        "findings": [],
        "review_advisories": [{
            "id": "proof",
            "code": "missing_sbom",
            "category": "provenance",
            "level": "warning",
            "title": "Missing SBOM",
            "description": "Missing SBOM",
            "deduction": 2,
            "affects_grade": False,
            "grade_downgrade_steps": 0,
            "requires_manual_review": False,
        }],
    }

    reconcile_permission_advisories(
        report,
        [_evidence("network", "conditional", "docs", 0.6)],
    )

    assert [item["code"] for item in report["review_advisories"]] == [
        "missing_sbom",
        "documented_permission_not_declared",
    ]
    assert report["advisory_summary"]["deduction_total"] == 7
    assert report["advisory_summary"]["grade_downgrade_steps"] == 0
