"""Independent, expiring source storage used only for version diffs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
import time
import uuid
from collections import OrderedDict
from concurrent.futures import Future
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any

from scanners.risk_scanner.evidence import normalize_file_path
from scanners.risk_scanner.redaction import credential_redactions, redact_text
from scanners.risk_scanner.credentials import LiteralRedactions, mask_literals
from src.settings import get_settings


_SNAPSHOT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DEFAULT_TTL_SECONDS = 7 * 24 * 3600
_DEFAULT_ROOT = Path(__file__).resolve().parents[2] / "data" / "source-snapshots"
_CONTEXT_CACHE_MAX_BYTES = 16 * 1024 * 1024
_CONTEXT_CACHE_MAX_ENTRIES = 128


@dataclass(frozen=True)
class _RedactedSource:
    content_sha256: str
    lines: tuple[str, ...]
    size_bytes: int
    literal_redactions: LiteralRedactions = field(repr=False)


class SourceSnapshotStore:
    """Bounded, private source storage used only for review diffs/contexts.

    Production deployments should set SOURCE_SNAPSHOT_DIR to a persistent,
    shared volume (or replace this service with object storage).  The local
    default is deliberately outside the system temp directory so worker
    restarts do not silently erase review data.
    """

    def __init__(self, root: str | Path | None = None, ttl_seconds: int | None = None) -> None:
        settings = get_settings()
        configured_root = settings.source_snapshot_dir
        self.root = Path(root or configured_root or _DEFAULT_ROOT)
        if ttl_seconds is None:
            ttl_seconds = settings.source_snapshot_ttl_seconds
        self.ttl_seconds = max(int(ttl_seconds), 1)
        self._context_cache: OrderedDict[tuple[str, str], _RedactedSource] = OrderedDict()
        self._context_cache_bytes = 0
        self._context_cache_lock = Lock()
        self._context_cache_generation = 0
        self._context_pending: dict[tuple[str, str, str], Future[tuple[str, ...]]] = {}
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            self.root.chmod(0o700)
        except OSError:
            pass
        self.cleanup_expired()

    @staticmethod
    def _safe_snapshot_id(snapshot_id: str) -> bool:
        return bool(_SNAPSHOT_ID_RE.fullmatch(snapshot_id))

    def _path_for(self, snapshot_id: str) -> Path | None:
        if not self._safe_snapshot_id(snapshot_id):
            return None
        return self.root / f"{snapshot_id}.json"

    def _load_payload(self, snapshot_id: str) -> dict[str, Any] | None:
        path = self._path_for(snapshot_id)
        if path is None or path.is_symlink():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def _expired(metadata: Any) -> bool:
        if not isinstance(metadata, dict):
            return True
        try:
            return int(metadata.get("expires_at", 0)) < int(time.time())
        except (TypeError, ValueError):
            return True

    def _discard_context_cache(self, snapshot_id: str) -> None:
        with self._context_cache_lock:
            self._context_cache_generation += 1
            for key in list(self._context_cache):
                if key[0] == snapshot_id:
                    self._context_cache_bytes -= self._context_cache.pop(key).size_bytes

    def _redacted_source_lines(
        self, snapshot_id: str, relative_path: str, raw_content: str,
        files: dict[str, str] | None = None,
    ) -> tuple[str, ...]:
        """Cache redacted lines by content digest, including cross-worker changes."""
        # A credential can be declared in another file. Hash the full scope so
        # changes there invalidate a previously safe-looking literal preview.
        scope = files if files is not None else {relative_path: raw_content}
        scope_hash = hashlib.sha256()
        for path, content in sorted(scope.items()):
            if isinstance(content, str):
                encoded = content.encode("utf-8")
                scope_hash.update(path.encode("utf-8") + b"\0")
                scope_hash.update(str(len(encoded)).encode("ascii") + b"\0" + encoded)
        digest = scope_hash.hexdigest()
        key = (snapshot_id, relative_path)
        pending_key = (*key, digest)
        with self._context_cache_lock:
            cached = self._context_cache.get(key)
            if cached is not None:
                if cached.content_sha256 == digest:
                    self._context_cache.move_to_end(key)
                    return cached.lines
                self._context_cache_bytes -= self._context_cache.pop(key).size_bytes

            pending = self._context_pending.get(pending_key)
            leader = pending is None
            if pending is None:
                pending = Future()
                self._context_pending[pending_key] = pending
            generation = self._context_cache_generation
            # Reuse another file's matcher only for the exact same snapshot
            # bytes. It expires/evicts with the existing bounded preview cache.
            literal_redactions = next((
                entry.literal_redactions
                for (cached_snapshot, _), entry in self._context_cache.items()
                if cached_snapshot == snapshot_id and entry.content_sha256 == digest
            ), None)

        if not leader:
            return pending.result()
        try:
            # Recognize and mask only on cache misses; repeated windows share
            # the same bounded redacted-line cache and concurrent work.
            if literal_redactions is None:
                literal_redactions = credential_redactions(
                    content for content in scope.values() if isinstance(content, str)
                )
            raw_content = mask_literals(raw_content, literal_redactions)
            lines = tuple(redact_text(raw_content).splitlines()) or ("",)
            size = sys.getsizeof(lines) + sum(sys.getsizeof(line) for line in lines)
            # Charge shared matchers per entry conservatively, including both
            # compiled storage and the retained pattern string.
            size += sys.getsizeof(literal_redactions) + sys.getsizeof(literal_redactions.pattern)
            if literal_redactions.pattern is not None:
                size += sys.getsizeof(literal_redactions.pattern.pattern)
        except BaseException as error:
            with self._context_cache_lock:
                self._context_pending.pop(pending_key, None)
            pending.set_exception(error)
            raise
        with self._context_cache_lock:
            if (
                generation == self._context_cache_generation
                and size <= _CONTEXT_CACHE_MAX_BYTES
            ):
                replaced = self._context_cache.pop(key, None)
                if replaced is not None:
                    self._context_cache_bytes -= replaced.size_bytes
                while self._context_cache and (
                    self._context_cache_bytes + size > _CONTEXT_CACHE_MAX_BYTES
                    or len(self._context_cache) >= _CONTEXT_CACHE_MAX_ENTRIES
                ):
                    _, evicted = self._context_cache.popitem(last=False)
                    self._context_cache_bytes -= evicted.size_bytes
                self._context_cache[key] = _RedactedSource(digest, lines, size, literal_redactions)
                self._context_cache_bytes += size
            self._context_pending.pop(pending_key, None)
        pending.set_result(lines)
        return lines

    def save(self, files: dict[str, str], *, snapshot_id: str | None = None,
             source_hash: str | None = None, ttl_seconds: int | None = None,
             owner_id: str | None = None) -> dict[str, Any]:
        """Persist a snapshot and return metadata for the stored contents.

        ``source_hash`` is retained for callers from the previous API, but it
        is intentionally ignored. The scanner's content-tree hash can describe
        a bounded scan and is not the hash of this stored snapshot.
        """
        snapshot_id = snapshot_id or f"snapshot-{uuid.uuid4().hex}"
        if not self._safe_snapshot_id(snapshot_id):
            raise ValueError("invalid snapshot id")
        snapshot_content = json.dumps(
            files, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        digest = hashlib.sha256(snapshot_content).hexdigest()
        now = int(time.time())
        metadata = {"snapshot_id": snapshot_id, "sha256": digest, "created_at": now,
                    "expires_at": now + max(ttl_seconds if ttl_seconds is not None else self.ttl_seconds, 1)}
        if owner_id:
            metadata["owner_id"] = str(owner_id)
        payload = {"metadata": metadata, "files": files}
        target = self.root / f"{snapshot_id}.json"
        fd, temp_name = tempfile.mkstemp(prefix=f".{snapshot_id}.", suffix=".tmp", dir=self.root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
            os.replace(temp_name, target)
            self._discard_context_cache(snapshot_id)
            try:
                target.chmod(0o600)
            except OSError:
                pass
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
        self.cleanup_expired()
        return metadata

    def load_for_diff(self, snapshot_id: str) -> dict[str, str]:
        payload = self._load_payload(snapshot_id)
        if payload is None:
            return {}
        metadata = payload.get("metadata", {})
        if self._expired(metadata):
            self.delete(snapshot_id)
            return {}
        files = payload.get("files", {})
        return files if isinstance(files, dict) else {}

    def load_context(
        self,
        snapshot_id: str,
        relative_path: str,
        *,
        line: int | None = None,
        max_lines: int = 40,
        max_bytes: int = 8192,
        expected_owner_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Return only a redacted, bounded context around one source line."""
        payload = self._load_payload(snapshot_id)
        if payload is None:
            return None
        metadata = payload.get("metadata", {})
        if self._expired(metadata):
            self.delete(snapshot_id)
            return None
        actual_owner = str(metadata.get("owner_id") or "")
        if actual_owner and expected_owner_id and actual_owner != str(expected_owner_id):
            return None

        normalized = normalize_file_path(relative_path)
        if normalized is None:
            return None
        files = payload.get("files", {})
        raw_content = files.get(normalized) if isinstance(files, dict) else None
        if not isinstance(raw_content, str):
            return None

        source_lines = self._redacted_source_lines(snapshot_id, normalized, raw_content, files)
        requested_line = max(1, int(line or 1))
        if requested_line > len(source_lines):
            return None
        target_line = requested_line
        bounded_lines = max(1, min(int(max_lines), 200))
        start = max(0, target_line - 1 - bounded_lines // 2)
        end = min(len(source_lines), start + bounded_lines)
        redacted = "\n".join(source_lines[start:end])
        encoded = redacted.encode("utf-8")
        byte_limited = len(encoded) > max(1, int(max_bytes))
        partial_line = False
        if byte_limited:
            delivered: list[str] = []
            size = 0
            for source_line in source_lines[start:end]:
                line_size = len(source_line.encode("utf-8")) + int(bool(delivered))
                if size + line_size > max(1, int(max_bytes)):
                    break
                delivered.append(source_line)
                size += line_size
            if not delivered:
                # Human previews may show a marked prefix of a very long line.
                # LLM evidence delivery has its own complete-line budget.
                redacted = source_lines[start].encode("utf-8")[
                    :max(1, int(max_bytes))
                ].decode("utf-8", errors="ignore")
                end = start + 1
                partial_line = True
            else:
                redacted = "\n".join(delivered)
                end = start + len(delivered)

        return {
            "file": normalized,
            "start_line": start + 1,
            "end_line": end,
            "total_lines": len(source_lines),
            "content": redacted,
            "truncated": byte_limited or end < len(source_lines),
            "partial_line": partial_line,
            "redacted": True,
            "expires_at": metadata.get("expires_at"),
        }

    def cleanup_expired(self, *, now: int | None = None) -> int:
        """Delete expired snapshots and return the number of removed files."""
        current = int(time.time() if now is None else now)
        removed = 0
        try:
            candidates = list(self.root.glob("*.json"))
        except OSError:
            return 0
        for path in candidates:
            if path.is_symlink():
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                expires_at = int((payload.get("metadata") or {}).get("expires_at", 0))
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                continue
            if expires_at and expires_at < current:
                try:
                    path.unlink()
                    self._discard_context_cache(path.stem)
                    removed += 1
                except FileNotFoundError:
                    pass
        return removed

    def delete(self, snapshot_id: str) -> None:
        path = self._path_for(snapshot_id)
        if path is None or path.is_symlink():
            return
        self._discard_context_cache(snapshot_id)
        try:
            path.unlink()
        except FileNotFoundError:
            pass
