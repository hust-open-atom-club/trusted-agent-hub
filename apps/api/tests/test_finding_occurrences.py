from scanners.risk_scanner.reporting import aggregate_findings, build_findings_summary


def test_distinct_locations_remain_distinct_root_causes_without_deleting_raw_findings():
    raw = [
        {"id": "a", "rule_id": "SR-013", "severity": "high", "evidence": "匹配: x", "location": {"file": "a.py", "line": 10}},
        {"id": "b", "rule_id": "SR-013", "severity": "high", "evidence": "匹配: x", "location": {"file": "b.py", "line": 18}},
        {"id": "c", "rule_id": "SR-013", "severity": "high", "evidence": "匹配: x", "location": {"file": "c.py", "line": 22}},
    ]
    report_findings = aggregate_findings(raw)
    assert len(raw) == 3
    assert len(report_findings) == 3
    assert len(raw) == 3
    assert all(item["occurrences"]["count"] == 1 for item in report_findings)


def test_cross_rule_hits_on_same_sink_form_one_scoring_root_cause():
    raw = [
        {
            "id": "rce",
            "rule_id": "SR-005",
            "severity": "high",
            "category": "remote_code_execution",
            "title": "dynamic exec",
            "sink_kind": "shell_exec",
            "sink_symbol": "cp.exec",
            "source_kind": "environment",
            "evidence": "match: cp.exec(process.env.OPEN_CMD + url)",
            "location": {
                "file": "server.cjs",
                "line": 40,
                "snippet": "cp.exec(process.env.OPEN_CMD + url)",
            },
        },
        {
            "id": "output",
            "rule_id": "SR-011",
            "severity": "medium",
            "category": "output_handling",
            "title": "concatenated command",
            "evidence": "match: exec(process.env.OPEN_CMD + url)",
            "location": {
                "file": "server.cjs",
                "line": 40,
                "snippet": "cp.exec(process.env.OPEN_CMD + url)",
            },
        },
    ]

    roots = aggregate_findings(raw)
    summary = build_findings_summary(roots)

    assert len(roots) == 1
    assert roots[0]["detector_ids"] == ["SR-005", "SR-011"]
    assert roots[0]["static_severity"] == "high"
    assert roots[0]["effective_severity"] == "high"
    assert roots[0]["severity"] == "high"
    assert roots[0]["occurrences"]["count"] == 1
    assert len(roots[0]["detector_hits"]) == 2
    assert summary["root_cause_total"] == 1
    assert summary["detector_hit_total"] == 2
    assert summary["high"] == 1


def test_root_id_is_stable_across_detector_input_order():
    first = {
        "id": "a",
        "rule_id": "SR-005",
        "severity": "high",
        "category": "remote_code_execution",
        "title": "translated title A",
        "location": {"file": "run.js", "line": 7, "snippet": "cp.exec(cmd)"},
    }
    second = {
        "id": "b",
        "rule_id": "SR-011",
        "severity": "medium",
        "category": "output_handling",
        "title": "translated title B",
        "location": {"file": "run.js", "line": 7, "snippet": "cp.exec(cmd)"},
    }

    forward = aggregate_findings([first, second])
    reverse = aggregate_findings([second, first])

    assert forward[0]["root_cause_id"] == reverse[0]["root_cause_id"]
    assert forward[0]["detector_ids"] == reverse[0]["detector_ids"]


def test_static_and_effective_severity_are_kept_separate():
    roots = aggregate_findings([{
        "id": "semantic",
        "rule_id": "SR-001",
        "severity": "info",
        "candidate_severity": "critical",
        "category": "prompt_injection",
        "title": "semantic candidate",
        "location": {"file": "SKILL.md", "line": 4},
        "requires_llm_validation": True,
    }])

    assert roots[0]["static_severity"] == "critical"
    assert roots[0]["effective_severity"] == "info"
    assert roots[0]["severity"] == "info"
