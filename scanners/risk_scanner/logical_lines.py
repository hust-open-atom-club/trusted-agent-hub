"""Fold backslash continuations while retaining physical source positions."""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Iterator
from dataclasses import dataclass


@dataclass(frozen=True)
class LogicalLine:
    text: str
    start_line: int
    # Offset in text at which each physical line begins, including empty lines.
    line_offsets: tuple[int, ...]

    def source_line(self, offset: int) -> int:
        return self.start_line + bisect_right(self.line_offsets, offset) - 1


def iter_logical_lines(
    content: str, *, requirement_comments: bool = False
) -> Iterator[LogicalLine]:
    """Remove continued newlines without inserting spaces into split tokens.

    Requirements comments are removed after joining, preserving URL fragments.
    A comment-only line ends a logical requirement even if it ends in ``\\``.
    Code uses LF line numbers to match scanner locations; requirements retain
    pip's splitlines behavior for other line separators.
    """
    parts: list[str] = []
    offsets: list[int] = []
    length = 0
    start_line = 1
    physical_lines = content.splitlines() if requirement_comments else content.split("\n")
    for line_no, raw_line in enumerate(physical_lines, 1):
        raw_line = raw_line.removesuffix("\r")
        if not parts:
            start_line = line_no
        offsets.append(length)
        comment = requirement_comments and raw_line.lstrip().startswith("#")
        continued = raw_line.endswith("\\") and not comment
        part = "" if comment else raw_line[:-1] if continued else raw_line
        parts.append(part)
        length += len(part)
        if continued:
            continue
        text = "".join(parts)
        if requirement_comments:
            text = re.split(r"(?:^|\s+)#", text, maxsplit=1)[0]
        yield LogicalLine(text, start_line, tuple(offsets))
        parts = []
        offsets = []
        length = 0

    if parts:
        text = "".join(parts)
        if requirement_comments:
            text = re.split(r"(?:^|\s+)#", text, maxsplit=1)[0]
        yield LogicalLine(text, start_line, tuple(offsets))
