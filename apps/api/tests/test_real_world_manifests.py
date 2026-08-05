"""Validate examples/real-world manifests against the agent-package schema."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = PROJECT_ROOT / "packages" / "schema" / "agent-package.schema.json"
REAL_WORLD_DIR = PROJECT_ROOT / "examples" / "real-world"

sys.path.insert(0, str(PROJECT_ROOT))
from scripts.compute_package_hash import tree_hash


def _manifests() -> list[Path]:
    return sorted(REAL_WORLD_DIR.rglob("manifest.json"))


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
    assert tree_hash(manifest_path.parent) == expected
