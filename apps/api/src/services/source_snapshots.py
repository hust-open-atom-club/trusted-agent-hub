"""Independent, expiring source storage used only for version diffs."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any


class SourceSnapshotStore:
    def __init__(self, root: str | Path | None = None, ttl_seconds: int = 7 * 24 * 3600) -> None:
        self.root = Path(root or os.environ.get("SOURCE_SNAPSHOT_DIR", Path(tempfile.gettempdir()) / "trusted-agent-hub-snapshots"))
        self.ttl_seconds = ttl_seconds
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, files: dict[str, str], *, snapshot_id: str | None = None,
             source_hash: str | None = None, ttl_seconds: int | None = None) -> dict[str, Any]:
        snapshot_id = snapshot_id or f"snapshot-{uuid.uuid4().hex}"
        canonical = "".join(f"{path}\0{files[path]}\0" for path in sorted(files))
        digest = source_hash or hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        now = int(time.time())
        metadata = {"snapshot_id": snapshot_id, "sha256": digest, "created_at": now,
                    "expires_at": now + (ttl_seconds if ttl_seconds is not None else self.ttl_seconds)}
        payload = {"metadata": metadata, "files": files}
        target = self.root / f"{snapshot_id}.json"
        fd, temp_name = tempfile.mkstemp(prefix=f".{snapshot_id}.", suffix=".tmp", dir=self.root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False)
            os.replace(temp_name, target)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
        return metadata

    def load_for_diff(self, snapshot_id: str) -> dict[str, str]:
        path = self.root / f"{snapshot_id}.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        metadata = payload.get("metadata", {})
        if int(metadata.get("expires_at", 0)) < int(time.time()):
            self.delete(snapshot_id)
            return {}
        files = payload.get("files", {})
        return files if isinstance(files, dict) else {}

    def delete(self, snapshot_id: str) -> None:
        try:
            (self.root / f"{snapshot_id}.json").unlink()
        except FileNotFoundError:
            pass
