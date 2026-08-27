"""Deterministic file inventory and bounded text loading."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath

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


def _normalize_relative_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        return None
    if value.startswith("/") or (
        len(value) >= 2 and value[0].isalpha() and value[1] == ":"
    ):
        return None
    if any(part in {"", ".", ".."} for part in value.split("/")):
        return None
    return PurePosixPath(value).as_posix()


def _normalize_relative_paths(paths: Iterable[str] | None) -> set[str]:
    """Normalize safe POSIX paths used for metadata-priority reads."""
    return {
        normalized
        for value in paths or set()
        if (normalized := _normalize_relative_path(value)) is not None
    }


def _normalize_relative_path_order(paths: Iterable[str] | None) -> list[str]:
    """Normalize an ordered list of safe POSIX paths without duplicates."""
    normalized: list[str] = []
    seen: set[str] = set()
    for value in paths or []:
        relative_path = _normalize_relative_path(value)
        if relative_path is None:
            continue
        if relative_path not in seen:
            seen.add(relative_path)
            normalized.append(relative_path)
    return normalized


def build_inventory(
    target_dir: Path,
    policy: ScanPolicy,
    *,
    priority_paths: Iterable[str] | None = None,
    priority_order: Iterable[str] | None = None,
) -> ScanInventory:
    """Build a bounded inventory, admitting selected metadata paths first."""
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

    raw_priority_paths = list(priority_paths or [])
    priority_paths = _normalize_relative_paths(raw_priority_paths)
    priority_path_order = [
        path
        for path in _normalize_relative_path_order(priority_order)
        if path in priority_paths
    ]
    ordered_paths = set(priority_path_order)
    priority_path_order.extend(sorted(priority_paths - ordered_paths))

    def resolve_priority_candidate(
        relative_path: str,
    ) -> Path | None:
        parts = PurePosixPath(relative_path).parts
        if len(parts) - 1 > policy.max_depth or ".git" in parts[:-1]:
            return None

        current = target_dir
        for part in parts[:-1]:
            current /= part
            try:
                if current.is_symlink() or not current.is_dir():
                    return None
            except (OSError, ValueError):
                return None

        candidate = current / parts[-1]
        try:
            candidate.lstat()
            is_symlink = candidate.is_symlink()
            if (is_symlink and candidate.is_dir()) or (
                not is_symlink and not candidate.is_file()
            ):
                return None
        except (OSError, ValueError):
            return None
        return candidate

    priority_candidates: dict[str, Path] = {}
    for relative_path in priority_path_order:
        candidate = resolve_priority_candidate(relative_path)
        if candidate is not None:
            priority_candidates[relative_path] = candidate

    def add_violation(reason: str) -> None:
        if reason not in violations:
            violations.append(reason)

    def add_skipped(reason: str, relative_path: str | None = None) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1
        if relative_path is not None and len(samples) < policy.max_skipped_samples:
            samples.append(relative_path)

    max_files = max(policy.max_files, 0)

    def iter_files(current_dir: Path, relative_root: Path):
        """Yield files without materializing a directory's full file list."""
        root_depth = 0 if relative_root == Path(".") else len(relative_root.parts)

        # Scan one priority bucket at a time.  Each scandir iterator is bounded
        # by the OS directory handle rather than by the number of entries.
        for priority in range(5):
            try:
                with os.scandir(current_dir) as entries:
                    for entry in entries:
                        try:
                            is_symlink = entry.is_symlink()
                            if entry.is_dir(follow_symlinks=True) and is_symlink:
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                continue
                            relative_path = (
                                relative_root / entry.name
                            ).as_posix() if relative_root != Path(".") else entry.name
                            if _read_priority(relative_path)[0] == priority:
                                yield relative_path, Path(entry.path)
                        except OSError:
                            continue
            except OSError:
                return

        if root_depth >= policy.max_depth:
            try:
                with os.scandir(current_dir) as entries:
                    for entry in entries:
                        try:
                            if entry.name == ".git" or entry.is_symlink():
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                add_violation("max_depth")
                                relative_path = (
                                    relative_root / entry.name
                                ).as_posix() if relative_root != Path(".") else entry.name
                                add_skipped("max_depth_exceeded", relative_path)
                        except OSError:
                            continue
            except OSError:
                pass
            return

        try:
            with os.scandir(current_dir) as entries:
                for entry in entries:
                    try:
                        if entry.name == ".git" or entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            child_root = (
                                relative_root / entry.name
                            ) if relative_root != Path(".") else Path(entry.name)
                            yield from iter_files(Path(entry.path), child_root)
                    except OSError:
                        continue
        except OSError:
            return

    def iter_inventory_files():
        yielded_priority_candidates: set[str] = set()
        for relative_path in priority_path_order:
            candidate = priority_candidates.get(relative_path)
            if candidate is not None:
                yielded_priority_candidates.add(
                    os.path.normcase(os.path.abspath(candidate))
                )
                yield relative_path, candidate
        for relative_path, candidate in iter_files(target_dir, Path(".")):
            if (
                os.path.normcase(os.path.abspath(candidate))
                not in yielded_priority_candidates
            ):
                yield relative_path, candidate

    for rel, path in iter_inventory_files():
        # The limit is exclusive: reaching max_files is valid.  Only a
        # further candidate proves that the tree contains more files than
        # the configured bound.  Keep the extra candidate out of the
        # inventory so memory and downstream work remain bounded.
        if len(records) >= max_files and (max_files == 0 or records):
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
    priority_paths: Iterable[str] | None = None,
    priority_order: Iterable[str] | None = None,
    only_paths: Iterable[str] | None = None,
    existing_contents: dict[str, str] | None = None,
) -> dict[str, str]:
    """Read inventory files with the same byte budgets used during discovery.

    Files are read in bounded binary chunks so a file that grows after lstat()
    cannot bypass either the per-file or aggregate read budget.  ``only_paths``
    supports a small first pass (for example, reading only the root manifest),
    while ``priority_paths`` makes selected metadata files win the next pass.
    ``priority_order`` preserves an explicit order among those files when the
    aggregate budget cannot accommodate all of them.  ``existing_contents``
    lets those passes share one bounded snapshot.
    """
    priority_paths = _normalize_relative_paths(priority_paths)
    priority_order = [
        path
        for path in _normalize_relative_path_order(priority_order)
        if path in priority_paths
    ]
    priority_ranks = {path: index for index, path in enumerate(priority_order)}
    only_paths = (
        _normalize_relative_paths(only_paths)
        if only_paths is not None
        else None
    )
    contents: dict[str, str] = dict(existing_contents or {})
    policy = policy or inventory.policy or ScanPolicy()
    total_read = sum(record.bytes_read for record in inventory.files)

    def read_priority(record: FileRecord) -> tuple[int, tuple[int, str]]:
        if record.relative_path in priority_paths:
            if record.relative_path in priority_ranks:
                return (0, (priority_ranks[record.relative_path], record.relative_path))
            return (0, _read_priority(record.relative_path))
        return (1, _read_priority(record.relative_path))

    for record in sorted(inventory.files, key=read_priority):
        if only_paths is not None and record.relative_path not in only_paths:
            continue
        if record.relative_path in contents:
            continue
        is_priority = record.relative_path in priority_paths
        loadable_status = record.read_status in {"pending", "special_pending"}
        recoverable_total_skip = (
            is_priority and record.read_status == "skipped"
            and record.skip_reason == "total_budget_exceeded"
        )
        if not loadable_status and not recoverable_total_skip:
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
