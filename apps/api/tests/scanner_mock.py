"""Scanner rule test fixtures — provides a mock scanner object for unit testing rules."""

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class MockScanner:
    """Mock RiskScanner that captures findings for rule unit testing."""

    files: dict[str, str] = field(default_factory=dict)
    code_example_predicate: Callable[[str, int], bool] = lambda f, ln: False
    findings: list[dict[str, Any]] = field(default_factory=list)
    review_advisories: list[dict[str, Any]] = field(default_factory=list)
    _package_metadata: dict[str, Any] | None = None
    _acquisition_facts: dict[str, Any] | None = None
    target_dir: Path = field(default_factory=lambda: Path("."))

    @property
    def scanned_files(self) -> list[str]:
        return list(self.files.keys())

    def _read_file_content(self, file_path: str) -> str:
        return self.files.get(file_path, "")

    def _is_code_example(self, file_path: str, line_no: int) -> bool:
        return self.code_example_predicate(file_path, line_no)

    def _add_finding(
        self,
        rule_id: str = "",
        severity: str = "info",
        category: str = "",
        title: str = "",
        description: str = "",
        location: dict[str, Any] | None = None,
        evidence: str = "",
        remediation: str = "",
        cwe_id: str | None = None,
        requires_confirmation: bool = False,
        kind: str | None = None,
        disposition: str | None = None,
        sink_kind: str | None = None,
        sink_symbol: str | None = None,
        source_kind: str | None = None,
        source_symbol: str | None = None,
        source_control: str | None = None,
        reachability: str | None = None,
        activation: str | None = None,
        trust_boundary_crossed: bool | None = None,
        safeguards: list[str] | None = None,
        preconditions: list[str] | None = None,
        requires_manual_review: bool = False,
    ) -> None:
        finding = {
            "rule_id": rule_id,
            "severity": severity,
            "static_severity": severity,
            "effective_severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "location": location or {},
            "evidence": evidence,
            "remediation": remediation,
            "cwe_id": cwe_id,
        }
        if requires_confirmation:
            finding["requires_confirmation"] = True
        semantic_values = {
            "kind": kind,
            "disposition": disposition,
            "sink_kind": sink_kind,
            "sink_symbol": sink_symbol,
            "source_kind": source_kind,
            "source_symbol": source_symbol,
            "source_control": source_control,
            "reachability": reachability,
            "activation": activation,
            "trust_boundary_crossed": trust_boundary_crossed,
        }
        finding.update({key: value for key, value in semantic_values.items() if value is not None})
        if safeguards:
            finding["safeguards"] = list(safeguards)
        if preconditions:
            finding["preconditions"] = list(preconditions)
        if requires_manual_review:
            finding["requires_manual_review"] = True
        self.findings.append(finding)

    def _add_advisory(
        self,
        *,
        code: str,
        category: str,
        level: str,
        title: str,
        description: str,
        deduction: int = 0,
        affects_grade: bool = False,
        grade_downgrade_steps: int = 0,
        requires_manual_review: bool = False,
        evidence: str = "",
        location: dict[str, Any] | None = None,
    ) -> None:
        self.review_advisories.append({
            "id": f"advisory-{len(self.review_advisories) + 1}",
            "code": code,
            "category": category,
            "level": level,
            "title": title,
            "description": description,
            "deduction": deduction,
            "affects_grade": affects_grade,
            "grade_downgrade_steps": grade_downgrade_steps,
            "requires_manual_review": requires_manual_review,
            "evidence": evidence,
            "location": location or {},
        })
