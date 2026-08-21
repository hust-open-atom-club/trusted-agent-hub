"""Parse structured manifests before rules inspect their fields."""

from __future__ import annotations

import json
from typing import Any

try:
    import tomllib  # type: ignore[import-not-found]
except ImportError:  # Python < 3.11: use tomli when an application provides it.
    try:
        import tomli as tomllib  # type: ignore[import-not-found,no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

from .models import StructuredDocument


_FORMATS = {
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
}


def parse_structured_document(path: str, content: str) -> StructuredDocument:
    suffix = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
    format_name = _FORMATS.get(suffix)
    if not format_name:
        return StructuredDocument(path, "unknown", "none", None)
    try:
        if format_name == "json":
            return StructuredDocument(path, format_name, "json", json.loads(content))
        if format_name == "toml":
            if tomllib is None:
                return StructuredDocument(path, format_name, "unavailable", None, "toml parser unavailable")
            return StructuredDocument(path, format_name, "tomllib", tomllib.loads(content))
        try:
            import yaml  # type: ignore[import-not-found]
        except ImportError:
            return StructuredDocument(path, format_name, "unavailable", None, "yaml parser unavailable")
        return StructuredDocument(path, format_name, "pyyaml", yaml.safe_load(content))
    except (ValueError, TypeError) as exc:
        return StructuredDocument(path, format_name, format_name, None, f"invalid {format_name}")


def analyze_structured_documents(contents: dict[str, str], files: list[str]) -> list[StructuredDocument]:
    documents: list[StructuredDocument] = []
    for path in sorted(files):
        suffix = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
        if suffix not in _FORMATS:
            continue
        document = parse_structured_document(path, contents.get(path, ""))
        documents.append(document)
    return documents


def get_field(data: Any, path: str, default: Any = None) -> Any:
    """Read a dotted manifest field without regex matching its serialization."""
    current = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current
