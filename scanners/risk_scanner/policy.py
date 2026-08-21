"""Explicit, immutable resource limits for risk scanning."""

from __future__ import annotations

from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class ScanPolicy:
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_files: int = 5000
    max_depth: int = 32
    max_findings: int = 10000
    max_osv_queries: int = 10
    max_skipped_samples: int = 20

    def __post_init__(self) -> None:
        if self.max_osv_queries < 1:
            raise ValueError("max_osv_queries must be at least 1")

    def as_dict(self) -> dict[str, int]:
        return asdict(self)
