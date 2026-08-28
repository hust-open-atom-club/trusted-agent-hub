"""Independent, expiring source storage used only for version diffs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
import uuid
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from scanners.risk_scanner.redaction import redact_text
from src.settings import get_settings


_SNAPSHOT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_DEFAULT_TTL_SECONDS = 7 * 24 * 3600
_DEFAULT_ROOT = Path(__file__).resolve().parents[2] / "data" / "source-snapshots"


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

        normalized = str(relative_path).replace("\\", "/")
        path = PurePosixPath(normalized)
        if (
            not normalized
            or normalized.startswith("/")
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            return None
        files = payload.get("files", {})
        raw_content = files.get(normalized) if isinstance(files, dict) else None
        if not isinstance(raw_content, str):
            return None

        source_lines = raw_content.splitlines() or [""]
        requested_line = max(1, int(line or 1))
        target_line = min(requested_line, len(source_lines))
        bounded_lines = max(1, min(int(max_lines), 200))
        start = max(0, target_line - 1 - bounded_lines // 2)
        end = min(len(source_lines), start + bounded_lines)
        redacted = redact_text("\n".join(source_lines[start:end]))
        encoded = redacted.encode("utf-8")
        byte_limited = len(encoded) > max(1, int(max_bytes))
        if byte_limited:
            redacted = encoded[:max(1, int(max_bytes))].decode("utf-8", errors="ignore")

        return {
            "file": normalized,
            "start_line": start + 1,
            "end_line": end,
            "total_lines": len(source_lines),
            "content": redacted,
            "truncated": byte_limited or end < len(source_lines),
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
                    removed += 1
                except FileNotFoundError:
                    pass
        return removed

    def delete(self, snapshot_id: str) -> None:
        path = self._path_for(snapshot_id)
        if path is None or path.is_symlink():
            return
        try:
            path.unlink()
        except FileNotFoundError:
            pass
