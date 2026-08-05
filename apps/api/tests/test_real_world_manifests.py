"""Validate examples/real-world manifests against the agent-package schema."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import jsonschema
import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = PROJECT_ROOT / "packages" / "schema" / "agent-package.schema.json"
REAL_WORLD_DIR = PROJECT_ROOT / "examples" / "real-world"


def _manifests() -> list[Path]:
    return sorted(REAL_WORLD_DIR.rglob("manifest.json"))


def _tree_hash(package_dir: Path) -> str:
    digest = hashlib.sha256()
    entries: list[tuple[str, Path]] = []
    for base, dirs, files in os.walk(package_dir):
        dirs.sort()
        for name in sorted(files):
            path = Path(base) / name
            rel = path.relative_to(package_dir).as_posix()
            if rel == "manifest.json":
                continue
            entries.append((rel, path))
    for rel, path in sorted(entries):
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


@pytest.mark.parametrize(
    "manifest_path",
    _manifests(),
    ids=lambda p: p.relative_to(REAL_WORLD_DIR).as_posix(),
)
def test_real_world_manifest_schema(manifest_path: Path) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    jsonschema.validate(data, schema)


@pytest.mark.parametrize(
    "manifest_path",
    _manifests(),
    ids=lambda p: p.relative_to(REAL_WORLD_DIR).as_posix(),
)
def test_real_world_manifest_integrity(manifest_path: Path) -> None:
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = data["integrity"]["sha256"]
    assert _tree_hash(manifest_path.parent) == expected
