from benchmarks.runner import _benchmark_check_failures


def test_benchmark_check_rejects_regressions_and_incomplete_scans():
    failures = _benchmark_check_failures({
        "overall": {"fp": 1, "fn": 2},
        "coverage": {"incomplete_scan_ratio": 0.5, "rule_exception_ratio": 0.25},
    })

    assert failures == [
        "unexpected rule findings (fp=1)",
        "missing expected rule findings (fn=2)",
        "benchmark contains incomplete scans",
        "benchmark contains rule execution failures",
    ]


def test_benchmark_check_accepts_clean_result():
    assert _benchmark_check_failures({
        "overall": {"fp": 0, "fn": 0},
        "coverage": {"incomplete_scan_ratio": 0, "rule_exception_ratio": 0},
    }) == []
