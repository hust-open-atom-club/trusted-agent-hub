"""Deterministic file inventory and bounded text loading."""

from __future__ import annotations

from dataclasses import dataclass
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


@dataclass
class ScanInventory:
    files: list[FileRecord]
    discovered_bytes: int
    analyzed_bytes: int
    limit_violations: list[str]
    discovered_files: int = 0
    skipped_by_reason: dict[str, int] | None = None
    skipped_samples: list[str] | None = None


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
    total_budget = 0

    if not target_dir.is_dir():
        return ScanInventory([], 0, 0, ["invalid_root"], 0, {}, [])

    candidates: list[tuple[str, Path]] = []
    for root, dirs, files in __import__("os").walk(target_dir, topdown=True, followlinks=False):
        root_path = Path(root)
        dirs[:] = sorted(d for d in dirs if d != ".git")
        # Do not descend through directory symlinks, including links outside root.
        dirs[:] = [d for d in dirs if not (root_path / d).is_symlink()]
        for name in sorted(files):
            path = root_path / name
            rel = path.relative_to(target_dir).as_posix()
            candidates.append((rel, path))

    for rel_path, path in sorted(candidates, key=lambda item: _read_priority(item[0])):
        discovered_files += 1
        try:
            stat = path.lstat()
            size = stat.st_size if not path.is_symlink() else 0
        except OSError:
            size = 0
        discovered_bytes += size
        ext = path.suffix.lower()
        depth = _depth(rel_path)
        is_symlink = path.is_symlink()
        reason: str | None = None
        if len(records) >= policy.max_files:
            reason = "max_files_exceeded"
            if "max_files" not in violations:
                violations.append("max_files")
        elif depth > policy.max_depth:
            reason = "max_depth_exceeded"
            if "max_depth" not in violations:
                violations.append("max_depth")
        elif is_symlink:
            try:
                if target_dir not in path.resolve().parents:
                    reason = "symlink_outside_root"
                else:
                    reason = "symlink"
            except OSError:
                reason = "symlink_unreadable"
        elif size > policy.max_file_bytes:
            reason = "file_too_large"
            if "max_file_bytes" not in violations:
                violations.append("max_file_bytes")
        elif ext in NON_TEXT_EXTENSIONS:
            reason = "binary" if ext in {".exe", ".dll", ".so", ".bin", ".dylib"} else "known_non_text"
        elif total_budget + size > policy.max_total_bytes:
            reason = "total_budget_exceeded"
            if "max_total_bytes" not in violations:
                violations.append("max_total_bytes")
        elif path.name in GENERAL_RULE_EXCLUDED_FILES:
            reason = "general_rule_excluded"

        special = reason == "general_rule_excluded"
        record = FileRecord(rel_path, path, size, ext, infer_file_type(rel_path), depth,
                            is_symlink, "special_pending" if special else ("skipped" if reason else "eligible"), reason)
        records.append(record)
        if reason:
            skipped[reason] = skipped.get(reason, 0) + 1
            if len(samples) < policy.max_skipped_samples:
                samples.append(rel_path)
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
                         discovered_files, skipped, samples)


def load_text_files(inventory: ScanInventory, encoding: str = "utf-8-sig") -> dict[str, str]:
    contents: dict[str, str] = {}
    for record in sorted(inventory.files, key=lambda item: _read_priority(item.relative_path)):
        if record.read_status not in {"pending", "special_pending"}:
            continue
        try:
            contents[record.relative_path] = record.absolute_path.read_text(encoding=encoding, errors="ignore")
            record.read_status = "analyzed"
        except (OSError, UnicodeError):
            record.read_status = "unreadable"
            record.skip_reason = "unreadable"
    inventory.analyzed_bytes = sum(
        r.size_bytes for r in inventory.files if r.read_status == "analyzed"
    )
    return contents
