"""Shared, safe parser for Markdown YAML frontmatter.

The extractor, scanner, and API fallback path must interpret the same
frontmatter.  In particular, YAML block scalars such as ``description: |``
are valid and must not be treated as the literal value ``|``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class FrontmatterResult:
    """Result of parsing one Markdown document's frontmatter."""

    data: dict[str, Any]
    present: bool
    error: str | None = None


def _closing_index(lines: list[str]) -> int | None:
    """Return the line index of the unindented YAML closing marker."""

    for index, line in enumerate(lines[1:], start=1):
        if not line.startswith((" ", "\t")) and line.strip() in {"---", "..."}:
            return index
    return None


def parse_frontmatter(content: str) -> FrontmatterResult:
    """Parse a Markdown document's YAML frontmatter safely.

    Only an unindented ``---``/``...`` line closes the frontmatter block.
    This avoids treating an indented ``---`` inside a YAML block scalar as a
    delimiter.  ``yaml.safe_load`` is deliberately used so tags cannot create
    arbitrary Python objects.
    """

    normalized = content.lstrip("\ufeff")
    lines = normalized.splitlines()
    if not lines or lines[0].strip() != "---":
        return FrontmatterResult({}, False)

    closing_index = _closing_index(lines)

    if closing_index is None:
        return FrontmatterResult(
            {}, True, "frontmatter 开始标记后缺少结束标记 --- 或 ..."
        )

    yaml_text = "\n".join(lines[1:closing_index])
    try:
        loaded = yaml.safe_load(yaml_text) or {}
    except yaml.YAMLError as exc:
        return FrontmatterResult({}, True, f"YAML 解析失败: {exc}")

    if not isinstance(loaded, dict):
        return FrontmatterResult({}, True, "frontmatter 顶层必须是 YAML 对象")

    return FrontmatterResult(dict(loaded), True)


def split_frontmatter(content: str) -> tuple[FrontmatterResult, str]:
    """Parse frontmatter and return the body using the same delimiter rules."""

    normalized = content.lstrip("\ufeff")
    result = parse_frontmatter(normalized)
    if not result.present or result.error:
        return result, content
    lines = normalized.splitlines(keepends=True)
    closing_index = _closing_index(lines)
    if closing_index is None:
        return result, content
    return result, "".join(lines[closing_index + 1:])


def parse_frontmatter_file(filepath: Path) -> FrontmatterResult:
    """Read and parse a Markdown file, preserving an actionable error."""

    try:
        content = filepath.read_text(encoding="utf-8")
    except OSError as exc:
        return FrontmatterResult({}, False, f"无法读取文件: {exc}")
    except UnicodeDecodeError as exc:
        return FrontmatterResult({}, False, f"文件不是有效 UTF-8: {exc}")
    return parse_frontmatter(content)
