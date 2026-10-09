"""Explicit, immutable resource limits for risk scanning."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True)
class ScanPolicy:
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_files: int = 5000
    max_depth: int = 32
    max_findings: int = 10000
    # Large enough for normal lockfiles, while still providing an explicit
    # operator-owned ceiling for unusually large or adversarial manifests.
    max_osv_queries: int = 5000
    max_skipped_samples: int = 20
    # Inherit LICENSE files only within an explicitly supplied repository_root.
    # Without that boundary, scanning is package-local. False also disables
    # inheritance when a repository_root is supplied.
    allow_parent_license_files: bool = True

    def __post_init__(self) -> None:
        if self.max_osv_queries < 1:
            raise ValueError("max_osv_queries must be at least 1")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
