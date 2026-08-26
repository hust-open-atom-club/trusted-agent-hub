"""Tests for the automatic trust-score model identity."""

from __future__ import annotations

import re
import sys
from pathlib import Path

_PKG_ROOT = Path(__file__).resolve().parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

from src.model_identity import (
    _compute_model_fingerprint,
    _normalized_source,
    _SOURCE_ROOT,
    get_model_fingerprint,
    get_model_version,
)


def test_model_fingerprint_is_a_stable_sha256_identifier() -> None:
    fingerprint = get_model_fingerprint()

    assert re.fullmatch(r"[0-9a-f]{64}", fingerprint)
    assert get_model_fingerprint() == fingerprint
    assert get_model_version() == f"auto-{fingerprint[:12]}"


def test_source_and_configuration_changes_change_the_identity() -> None:
    base = _compute_model_fingerprint(_SOURCE_ROOT, {"weight": 1})
    changed_config = _compute_model_fingerprint(
        _SOURCE_ROOT,
        {"weight": 2},
    )

    assert _normalized_source(b"score = 1\r\n") == b"score = 1\n"
    assert _normalized_source(b"score = 1\r") == b"score = 1\n"
    assert base != changed_config
