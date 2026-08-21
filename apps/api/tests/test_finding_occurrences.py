from scanners.risk_scanner.reporting import aggregate_findings


def test_occurrences_keep_all_locations_without_deleting_raw_findings():
    raw = [
        {"id": "a", "rule_id": "SR-013", "severity": "high", "evidence": "匹配: x", "location": {"file": "a.py", "line": 10}},
        {"id": "b", "rule_id": "SR-013", "severity": "high", "evidence": "匹配: x", "location": {"file": "b.py", "line": 18}},
        {"id": "c", "rule_id": "SR-013", "severity": "high", "evidence": "匹配: x", "location": {"file": "c.py", "line": 22}},
    ]
    report_findings = aggregate_findings(raw)
    assert len(raw) == 3
    assert len(report_findings) == 1
    assert report_findings[0]["occurrences"] == {
        "count": 3,
        "items": [
            {"file": "a.py", "line": 10},
            {"file": "b.py", "line": 18},
            {"file": "c.py", "line": 22},
        ],
        "truncated": False,
    }
