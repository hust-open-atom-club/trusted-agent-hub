"""Deterministic file inventory and bounded text loading."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from scanners.risk_scanner.common import (
    GENERAL_RULE_EXCLUDED_FILES,
    NON_TEXT_EXTENSIONS,
    infer_file_type,
)
from scanners.risk_scanner.policy import ScanPolicy


@dataclass
class FileRecord:
    relative_path: str
    absolute_path: Path
    size_bytes: int
    extension: str
    kind: str
    depth: int
    is_symlink: bool
    read_status: str
    skip_reason: str | None = None
    stat_mtime_ns: int | None = None
    stat_inode: int | None = None
    bytes_read: int = 0
    content_truncated: bool = False
    changed_during_scan: bool = False


@dataclass
class ScanInventory:
    files: list[FileRecord]
    discovered_bytes: int
    analyzed_bytes: int
    limit_violations: list[str]
    discovered_files: int = 0
    skipped_by_reason: dict[str, int] | None = None
    skipped_samples: list[str] | None = None
    discovered_count: int = 0
    discovered_at_least: bool = False
    sample_limit: int = 20
    policy: ScanPolicy | None = None


def _depth(relative_path: str) -> int:
    return len(Path(relative_path).parts) - 1


def _read_priority(relative_path: str) -> tuple[int, str]:
    name = Path(relative_path).name.lower()
    if name in {"manifest.json", "plugin.json", "agent.json", "skill.md"}:
        return (0, relative_path)
    if Path(relative_path).suffix.lower() in {".py", ".js", ".ts", ".sh", ".ps1", ".rb", ".go", ".rs", ".php"}:
        return (1, relative_path)
    if Path(relative_path).suffix.lower() in {".json", ".yaml", ".yml", ".toml"}:
        return (2, relative_path)
    if name.startswith(("readme", "changelog", "license", "notice")) or name.endswith((".md", ".txt", ".rst")):
        return (4, relative_path)
    return (3, relative_path)


def build_inventory(target_dir: Path, policy: ScanPolicy) -> ScanInventory:
    records: list[FileRecord] = []
    violations: list[str] = []
    skipped: dict[str, int] = {}
    samples: list[str] = []
    discovered_bytes = 0
    analyzed_bytes = 0
    discovered_files = 0
    discovered_at_least = False
    total_budget = 0

    if not target_dir.is_dir():
        return ScanInventory([], 0, 0, ["invalid_root"], 0, {}, [], policy=policy)

    def add_violation(reason: str) -> None:
        if reason not in violations:
            violations.append(reason)

    def add_skipped(reason: str, relative_path: str | None = None) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1
        if relative_path is not None and len(samples) < policy.max_skipped_samples:
            samples.append(relative_path)

    for root, dirs, files in os.walk(target_dir, topdown=True, followlinks=False):
        root_path = Path(root)
        dirs[:] = sorted(d for d in dirs if d != ".git")
        # Do not descend through directory symlinks, including links outside root.
        dirs[:] = [d for d in dirs if not (root_path / d).is_symlink()]

        relative_root = root_path.relative_to(target_dir)
        root_depth = 0 if relative_root == Path(".") else len(relative_root.parts)
        if root_depth >= policy.max_depth and dirs:
            add_violation("max_depth")
            for directory in dirs[: policy.max_skipped_samples]:
                add_skipped(
                    "max_depth_exceeded",
                    (relative_root / directory).as_posix()
                    if relative_root != Path(".")
                    else directory,
                )
            dirs[:] = []

        # Keep discovery bounded.  Sorting by read priority preserves the old
        # preference for manifests and source files without collecting an
        # unbounded candidate list first.
        relative_names = [
            ((relative_root / name).as_posix() if relative_root != Path(".") else name, name)
            for name in files
        ]
        for rel, name in sorted(relative_names, key=lambda item: _read_priority(item[0])):
            if len(records) >= max(policy.max_files, 0):
                discovered_at_least = True
                add_violation("max_files")
                records.sort(key=lambda record: record.relative_path)
                return ScanInventory(
                    records,
                    discovered_bytes,
                    analyzed_bytes,
                    violations,
                    discovered_files,
                    skipped,
                    samples,
                    discovered_files,
                    discovered_at_least,
                    policy.max_skipped_samples,
                    policy,
                )

            path = root_path / name
            discovered_files += 1
            try:
                stat = path.lstat()
                size = stat.st_size if not path.is_symlink() else 0
                stat_mtime_ns = getattr(stat, "st_mtime_ns", None)
                stat_inode = getattr(stat, "st_ino", None)
            except OSError:
                size = 0
                stat_mtime_ns = None
                stat_inode = None
            discovered_bytes += size
            ext = path.suffix.lower()
            depth = _depth(rel)
            is_symlink = path.is_symlink()
            reason: str | None = None
            if is_symlink:
                try:
                    if target_dir not in path.resolve().parents:
                        reason = "symlink_outside_root"
                    else:
                        reason = "symlink"
                except OSError:
                    reason = "symlink_unreadable"
            elif size > policy.max_file_bytes:
                reason = "file_too_large"
                add_violation("max_file_bytes")
            elif ext in NON_TEXT_EXTENSIONS:
                reason = "binary" if ext in {".exe", ".dll", ".so", ".bin", ".dylib"} else "known_non_text"
            elif total_budget + size > policy.max_total_bytes:
                reason = "total_budget_exceeded"
                add_violation("max_total_bytes")
            elif path.name in GENERAL_RULE_EXCLUDED_FILES:
                reason = "general_rule_excluded"

            special = reason == "general_rule_excluded"
            record = FileRecord(
                rel,
                path,
                size,
                ext,
                infer_file_type(rel),
                depth,
                is_symlink,
                "special_pending" if special else ("skipped" if reason else "eligible"),
                reason,
                stat_mtime_ns,
                stat_inode,
            )
            records.append(record)
            if reason:
                add_skipped(reason, rel)
            elif not special:
                total_budget += size
                analyzed_bytes += size
                record.read_status = "pending"
            else:
                # Lock/manifests are parsed by dedicated analyzers, never generic regex rules.
                total_budget += size
                analyzed_bytes += size

            if len(records) >= max(policy.max_files, 0):
                discovered_at_least = True
                add_violation("max_files")
                records.sort(key=lambda record: record.relative_path)
                return ScanInventory(
                    records,
                    discovered_bytes,
                    analyzed_bytes,
                    violations,
                    discovered_files,
                    skipped,
                    samples,
                    discovered_files,
                    discovered_at_least,
                    policy.max_skipped_samples,
                    policy,
                )

    records.sort(key=lambda record: record.relative_path)
    return ScanInventory(records, discovered_bytes, analyzed_bytes, violations,
                         discovered_files, skipped, samples,
                         discovered_files, discovered_at_least,
                         policy.max_skipped_samples, policy)


def _record_read_event(inventory: ScanInventory, record: FileRecord, reason: str) -> None:
    record.skip_reason = reason
    skipped = inventory.skipped_by_reason if inventory.skipped_by_reason is not None else {}
    inventory.skipped_by_reason = skipped
    skipped[reason] = skipped.get(reason, 0) + 1
    samples = inventory.skipped_samples if inventory.skipped_samples is not None else []
    inventory.skipped_samples = samples
    if len(samples) < inventory.sample_limit:
        samples.append(record.relative_path)
    if reason not in inventory.limit_violations:
        inventory.limit_violations.append(reason)


def load_text_files(
    inventory: ScanInventory,
    encoding: str = "utf-8-sig",
    *,
    policy: ScanPolicy | None = None,
) -> dict[str, str]:
    """Read inventory files with the same byte budgets used during discovery.

    Files are read in bounded binary chunks so a file that grows after lstat()
    cannot bypass either the per-file or aggregate read budget.
    """
    contents: dict[str, str] = {}
    policy = policy or inventory.policy or ScanPolicy()
    total_read = 0
    for record in sorted(inventory.files, key=lambda item: _read_priority(item.relative_path)):
        if record.read_status not in {"pending", "special_pending"}:
            continue
        remaining = max(policy.max_total_bytes - total_read, 0)
        byte_budget = min(max(policy.max_file_bytes, 0), remaining)
        if byte_budget <= 0:
            record.read_status = "skipped"
            _record_read_event(inventory, record, "read_budget_exhausted")
            continue
        try:
            chunks: list[bytes] = []
            bytes_remaining = byte_budget
            with record.absolute_path.open("rb") as handle:
                while bytes_remaining:
                    chunk = handle.read(min(64 * 1024, bytes_remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    bytes_remaining -= len(chunk)
            data = b"".join(chunks)
            record.bytes_read = len(data)
            total_read += len(data)

            try:
                contents[record.relative_path] = data.decode(encoding)
            except UnicodeDecodeError:
                record.read_status = "unreadable"
                _record_read_event(inventory, record, "decode_error")
                continue

            current_size: int | None = None
            try:
                current = record.absolute_path.lstat()
                current_size = current.st_size
                changed = (
                    record.stat_mtime_ns is not None
                    and getattr(current, "st_mtime_ns", None) != record.stat_mtime_ns
                ) or (
                    record.stat_inode is not None
                    and getattr(current, "st_ino", None) != record.stat_inode
                ) or current.st_size != record.size_bytes
            except OSError:
                changed = True
            record.changed_during_scan = changed
            budget_exhausted = bytes_remaining == 0
            record.content_truncated = budget_exhausted and (
                record.size_bytes > len(data)
                or (current_size is not None and current_size > len(data))
            )
            record.read_status = "analyzed"
            if changed:
                _record_read_event(inventory, record, "source_changed_during_scan")
            if record.content_truncated:
                _record_read_event(inventory, record, "content_truncated")
        except OSError:
            record.read_status = "unreadable"
            _record_read_event(inventory, record, "read_error")
    inventory.analyzed_bytes = sum(
        r.bytes_read for r in inventory.files if r.read_status == "analyzed"
    )
    return contents
