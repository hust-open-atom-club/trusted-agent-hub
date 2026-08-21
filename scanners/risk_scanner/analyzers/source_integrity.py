"""Acquisition snapshot checks for symlinks and in-scan source mutation."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SourceState:
    size: int
    mtime_ns: int
    is_symlink: bool
    resolved: str


@dataclass
class SourceIntegritySnapshot:
    states: dict[str, SourceState] = field(default_factory=dict)


def capture_source_state(target_dir: Path, inventory: Any) -> SourceIntegritySnapshot:
    snapshot = SourceIntegritySnapshot()
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

    current: set[str] = set()
    for base, dirs, files in os.walk(target_dir, topdown=True, followlinks=False):
        dirs[:] = [name for name in dirs if name != ".git" and not (Path(base) / name).is_symlink()]
        for name in files:
            current.add((Path(base) / name).relative_to(target_dir).as_posix())
    for relative_path in sorted(current - set(snapshot.states)):
        issues.append({"kind": "source_added_during_scan", "file": relative_path})
    return issues
