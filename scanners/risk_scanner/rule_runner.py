"""Isolated execution of scanner rules."""

from __future__ import annotations

import importlib
import logging
import re
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    module: str
    required: bool = True


@dataclass
class RuleExecutionResult:
    rule_id: str
    status: str
    duration_ms: int
    findings_added: int
    error_type: str | None = None
    error_message: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "status": self.status,
            "duration_ms": self.duration_ms,
            "findings_added": self.findings_added,
            "error_type": self.error_type,
            "error_message": self.error_message,
        }


RULE_SPECS: tuple[RuleSpec, ...] = tuple(
    RuleSpec(rule_id, f"scanners.risk_scanner.rules.{module}")
    for rule_id, module in (
        ("SR-001", "prompt_injection"),
        ("SR-002", "dangerous_shell"),
        ("SR-003", "credential_access"),
        ("SR-004", "hardcoded_secrets"),
        ("SR-005", "rce"),
        ("SR-005b", "behavioral_ast"),
        ("SR-006", "excessive_permissions"),
        ("SR-007", "network"),
        ("SR-008", "supply_chain"),
        ("SR-009", "source_integrity"),
        ("SR-010", "metadata_quality"),
        ("SR-011", "output_handling"),
        ("SR-012", "system_prompt_leak"),
        ("SR-013", "memory_poisoning"),
        ("SR-014", "ssrf"),
        ("SR-015", "agent_snooping"),
        ("SR-016", "tool_misuse"),
        ("SR-017", "mcp_security"),
        ("SR-018", "plugin_security"),
        ("SR-019", "subagent_security"),
        ("SR-020", "installation_security"),
    )
)


def _safe_error_message(exc: Exception) -> str:
    message = str(exc).replace("\r", " ").replace("\n", " ").strip()
    # Never expose local paths or environment-like assignments in the report.
    message = re.sub(r"[A-Za-z]:\\[^ ]+", "<path>", message)
    message = re.sub(r"(?<![A-Za-z0-9_])/(?:[^ ]+/)+[^ ]*", "<path>", message)
    message = re.sub(r"\b[A-Z_][A-Z0-9_]+=\S+", "<redacted>", message)
    return message[:200] or "rule execution failed"


class RuleRunner:
    def __init__(self, specs: tuple[RuleSpec, ...] = RULE_SPECS) -> None:
        self.specs = specs

    def run_all(self, scanner: Any) -> list[RuleExecutionResult]:
        results: list[RuleExecutionResult] = []
        for spec in self.specs:
            started = time.perf_counter()
            before = len(scanner.findings)
            try:
                module = importlib.import_module(spec.module)
                run = getattr(module, "run")
                run(scanner)
                results.append(RuleExecutionResult(
                    spec.rule_id, "succeeded", _elapsed_ms(started), len(scanner.findings) - before
                ))
            except Exception as exc:
                # Deliberately catch Exception only: KeyboardInterrupt/SystemExit propagate.
                logger.exception("Rule %s failed", spec.rule_id)
                results.append(RuleExecutionResult(
                    spec.rule_id, "failed", _elapsed_ms(started), len(scanner.findings) - before,
                    type(exc).__name__, _safe_error_message(exc)
                ))
        return results


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)
