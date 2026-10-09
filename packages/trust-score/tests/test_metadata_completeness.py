"""
Metadata-completeness dimension tests (issue #48).

The dimension must:
  - detect every required descriptive field (name, version, type,
    description, author, license, source) defined once in
    packages/schema/constants.py and kept in sync with
    agent-package.schema.json;
  - score and report from that same list;
  - treat keywords as optional metadata that is reported but never penalized;
  - give empty metadata the intended floor score.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

# Ensure the trust-score package root is importable so that
# relative imports in src/*.py resolve correctly.
_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from src.engine import rate as _engine_rate
from packages.schema.constants import (
    AGENT_PACKAGE_OPTIONAL_METADATA_FIELDS,
    AGENT_PACKAGE_REQUIRED_FIELDS,
    AGENT_PACKAGE_REQUIRED_METADATA_FIELDS,
)

_REPO_ROOT = _PKG_ROOT.parent.parent


def _dim(package_metadata: dict[str, Any]) -> dict[str, Any]:
    """Return the metadata_completeness dimension for the given metadata."""
    return _engine_rate(package_metadata=package_metadata)["dimensions"][
        "metadata_completeness"
    ]


def _complete_metadata(**overrides: Any) -> dict[str, Any]:
    """Package metadata with every required descriptive field present."""
    pkg: dict[str, Any] = {
        "name": "complete-pkg",
        "version": "1.0.0",
        "type": "skill",
        "description": "A complete package with every required metadata field",
        "author": {"name": "Tester"},
        "license": "MIT",
        "source": {
            "type": "github",
            "repository_url": "https://github.com/tester/complete-pkg",
            "ref": "v1.0.0",
            "commit_hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
        },
    }
    pkg.update(overrides)
    return pkg


def test_required_field_lists_match_agent_package_schema() -> None:
    """The scoring field list must stay in sync with agent-package.schema.json."""
    schema_path = _REPO_ROOT / "packages" / "schema" / "agent-package.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    required = set(schema["required"])

    assert required == set(AGENT_PACKAGE_REQUIRED_FIELDS)

    # Descriptive metadata is a subset of the schema's required fields; the
    # remainder are structural sections covered by dedicated dimensions.
    structural = required - set(AGENT_PACKAGE_REQUIRED_METADATA_FIELDS)
    assert structural == {"integrity", "compatibility", "permissions", "installation"}

    # keywords is optional metadata: reported, never required.
    assert "keywords" not in required
    assert set(AGENT_PACKAGE_OPTIONAL_METADATA_FIELDS) == {"keywords"}


def test_empty_metadata_reports_every_required_field_and_floor_score() -> None:
    """Empty metadata → all 7 required fields missing → floor score 30."""
    dim = _dim({})
    assert dim["score"] == 30
    assert dim["details"]["missing_required_fields"] == list(
        AGENT_PACKAGE_REQUIRED_METADATA_FIELDS
    )
    assert dim["details"]["has_description"] is False
    assert dim["details"]["has_license"] is False
    assert dim["details"]["has_keywords"] is False


def test_present_but_empty_values_count_as_missing() -> None:
    """Keys present with falsy values (empty str/dict) still count as missing."""
    pkg: dict[str, Any] = {
        field: "" for field in AGENT_PACKAGE_REQUIRED_METADATA_FIELDS
    }
    pkg["author"] = {}
    pkg["source"] = {}
    dim = _dim(pkg)
    assert set(dim["details"]["missing_required_fields"]) == set(
        AGENT_PACKAGE_REQUIRED_METADATA_FIELDS
    )
    assert dim["score"] == 30


def test_partial_metadata_detects_only_the_missing_fields() -> None:
    """Two missing fields → listed, and score is 100 - 2 * 20 = 60."""
    pkg = _complete_metadata()
    del pkg["license"]
    del pkg["source"]
    dim = _dim(pkg)
    assert dim["details"]["missing_required_fields"] == ["license", "source"]
    assert dim["score"] == 60


def test_complete_metadata_scores_full() -> None:
    """All required fields present → no missing fields → score 100."""
    dim = _dim(_complete_metadata())
    assert dim["details"]["missing_required_fields"] == []
    assert dim["score"] == 100
    assert dim["details"]["has_description"] is True
    assert dim["details"]["has_license"] is True


def test_keywords_are_optional_and_never_deducted() -> None:
    """keywords is explicitly optional: reported via has_keywords, no penalty."""
    without_keywords = _dim(_complete_metadata())
    assert without_keywords["details"]["has_keywords"] is False
    assert "keywords" not in without_keywords["details"]["missing_required_fields"]
    assert without_keywords["score"] == 100

    with_keywords = _dim(_complete_metadata(keywords=["demo"]))
    assert with_keywords["details"]["has_keywords"] is True
    assert with_keywords["score"] == 100


def test_missing_field_penalty_ladder_and_floor() -> None:
    """Each missing required field deducts 20 points, floored at 30."""
    fields = list(AGENT_PACKAGE_REQUIRED_METADATA_FIELDS)
    for removed, expected in ((0, 100), (1, 80), (2, 60), (3, 40), (4, 30), (7, 30)):
        pkg = _complete_metadata()
        for field in fields[:removed]:
            del pkg[field]
        assert _dim(pkg)["score"] == expected
