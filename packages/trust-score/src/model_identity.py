"""Deterministic identity for the trust-score model.

The score model is made up of the Python implementation in this directory
plus a small set of shared scoring constants.  Keeping the identity next to
the model makes a score-model change observable without relying on a human to
remember to edit a version string.

Scanner implementation identity is intentionally separate: scanner changes
produce a new scan report and are represented by the scan report's own
``scanner_version``.
"""

from __future__ import annotations

import json
from functools import lru_cache
from hashlib import sha256
from pathlib import Path
from typing import Any

from packages.schema.constants import (
    FINDING_CATEGORY_POLICY,
    GRADE_TO_RECOMMENDATION,
    GRADE_TO_RISK_LEVEL,
    HASH_SCOPE_SCANNED_SOURCE,
)
from scanners.risk_scanner.weights import LEVEL_TO_GRADE, SEVERITY_POINTS


_MODEL_NAMESPACE = "trusted-agent-hub:trust-score-model:fingerprint:v1"
_SOURCE_ROOT = Path(__file__).resolve().parent

# These are the external values that affect the score or its trust-level
# projection.  The trust-score source tree is hashed separately below.
_CONFIG_VALUES: dict[str, Any] = {
    "finding_category_policy": FINDING_CATEGORY_POLICY,
    "grade_to_recommendation": GRADE_TO_RECOMMENDATION,
    "grade_to_risk_level": GRADE_TO_RISK_LEVEL,
    "hash_scope_scanned_source": HASH_SCOPE_SCANNED_SOURCE,
    "level_to_grade": LEVEL_TO_GRADE,
    "severity_points": SEVERITY_POINTS,
}


def _canonicalize(value: Any) -> Any:
    """Convert supported configuration values into JSON-stable values."""
    if isinstance(value, dict):
        return {
            str(key): _canonicalize(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    if isinstance(value, (set, frozenset)):
        normalized = [_canonicalize(item) for item in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(
                item,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise TypeError(
        f"Unsupported trust-score model configuration value: {type(value)!r}"
    )


def _normalized_source(source: bytes) -> bytes:
    """Make source hashing independent of the checkout's line endings."""
    return source.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _compute_model_fingerprint(
    source_root: Path,
    config_values: dict[str, Any],
) -> str:
    """Compute the model fingerprint from source files and config values."""
    digest = sha256()
    digest.update(_MODEL_NAMESPACE.encode("utf-8"))
    digest.update(b"\0")

    for path in sorted(source_root.rglob("*.py")):
        relative_path = path.relative_to(source_root).as_posix()
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(_normalized_source(path.read_bytes()))
        digest.update(b"\0")

    serialized_config = json.dumps(
        _canonicalize(config_values),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest.update(b"config\0")
    digest.update(serialized_config)
    return digest.hexdigest()


@lru_cache(maxsize=1)
def get_model_fingerprint() -> str:
    """Return the current deterministic trust-score model fingerprint."""
    return _compute_model_fingerprint(_SOURCE_ROOT, _CONFIG_VALUES)


def model_version_for_fingerprint(fingerprint: str) -> str:
    """Return a readable compatibility identifier derived from a fingerprint."""
    return f"auto-{fingerprint[:12]}"


def get_model_version() -> str:
    """Return the compatibility identifier for the current model."""
    return model_version_for_fingerprint(get_model_fingerprint())
