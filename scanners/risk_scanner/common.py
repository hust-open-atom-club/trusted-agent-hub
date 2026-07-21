"""
Common utilities for risk scanner rules.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

DANGEROUS_EXTENSIONS = frozenset({".exe", ".dll", ".so", ".dylib", ".bin", ".sh", ".bat", ".ps1"})

REQUIRED_FILES_BY_TYPE: dict[str, list[str]] = {
    "skill": ["SKILL.md"],
    "mcp_server": ["manifest.json"],
    "plugin": ["plugin.json"],
    "command": ["SKILL.md"],
    "prompt": ["SKILL.md"],
}

CODE_EXAMPLE_INDICATORS: list[str] = [
    '```',
    'example',
    'sample',
    'tutorial',
    'demonstration',
]


def is_code_example(text: str) -> bool:
    lower = text.lower()
    for indicator in CODE_EXAMPLE_INDICATORS:
        if indicator in lower:
            return True
    return False


def infer_file_type(path: str) -> str:
    idx = path.rfind(".")
    suffix = path[idx:].lower() if idx >= 0 else ""
    file_types = {
        ".md": "markdown", ".markdown": "markdown",
        ".py": "python",
        ".sh": "shell", ".bash": "shell", ".zsh": "shell",
        ".json": "json", ".yaml": "yaml", ".yml": "yaml",
        ".toml": "toml", ".txt": "text",
        ".js": "javascript", ".ts": "typescript",
        ".rb": "ruby", ".go": "go", ".rs": "rust",
    }
    return file_types.get(suffix, "other")
