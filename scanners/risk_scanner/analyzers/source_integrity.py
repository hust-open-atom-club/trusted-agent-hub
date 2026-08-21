"""Acquisition snapshot checks for symlinks and in-scan source mutation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scanners.risk_scanner.inventory import build_inventory
from scanners.risk_scanner.policy import ScanPolicy


@dataclass
class SourceState:
    size: int
    mtime_ns: int
    is_symlink: bool
    resolved: str


@dataclass
class SourceIntegritySnapshot:
    states: dict[str, SourceState] = field(default_factory=dict)
    policy: ScanPolicy | None = None
    coverage_limited: bool = False


def _coverage_limited(inventory: Any) -> bool:
    """Whether an inventory cannot represent the complete path set."""
    violations = set(getattr(inventory, "limit_violations", []) or [])
    return bool(
        getattr(inventory, "discovered_at_least", False)
        or "max_files" in violations
        or "max_depth" in violations
        or "invalid_root" in violations
    )


def capture_source_state(target_dir: Path, inventory: Any) -> SourceIntegritySnapshot:
    snapshot = SourceIntegritySnapshot(
        policy=getattr(inventory, "policy", None) or ScanPolicy(),
        coverage_limited=_coverage_limited(inventory),
    )
    for record in inventory.files:
        try:
            stat = record.absolute_path.lstat()
            resolved = str(record.absolute_path.resolve())
            snapshot.states[record.relative_path] = SourceState(
                size=int(stat.st_size),
                mtime_ns=int(stat.st_mtime_ns),
                is_symlink=record.is_symlink,
                resolved=resolved,
            )
        except OSError:
            snapshot.states[record.relative_path] = SourceState(0, 0, record.is_symlink, "")
    return snapshot


def verify_source_state(target_dir: Path, snapshot: SourceIntegritySnapshot | None) -> list[dict[str, str]]:
    if snapshot is None:
        return []
    issues: list[dict[str, str]] = []
    root = target_dir.resolve()
    for relative_path, before in snapshot.states.items():
        path = target_dir / relative_path
        if before.is_symlink:
            try:
                resolved = path.resolve()
                if root not in resolved.parents and resolved != root:
                    issues.append({"kind": "symlink_outside_root", "file": relative_path})
            except OSError:
                issues.append({"kind": "symlink_unreadable", "file": relative_path})
        try:
            stat = path.lstat()
        except OSError:
            issues.append({"kind": "source_removed_during_scan", "file": relative_path})
            continue
        if int(stat.st_size) != before.size or int(stat.st_mtime_ns) != before.mtime_ns:
            issues.append({"kind": "source_changed_during_scan", "file": relative_path})

    # Reuse the exact same bounded inventory policy for the second pass.  An
    # unrestricted os.walk here would make max_files/max_depth advisory only.
    current_inventory = build_inventory(target_dir, snapshot.policy or ScanPolicy())
    current = {record.relative_path for record in current_inventory.files}
    for relative_path in sorted(current - set(snapshot.states)):
        issues.append({"kind": "source_added_during_scan", "file": relative_path})

    if snapshot.coverage_limited or _coverage_limited(current_inventory):
        issues.append({
            "kind": "source_state_check_limited",
            "file": "<scan tree>",
        })
    return issues
