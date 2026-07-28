"""
Common utilities for risk scanner rules.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

SKIP_READ_EXTENSIONS = frozenset({
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".avif",
    ".ttf", ".otf", ".woff", ".woff2",
    ".mp4", ".mov", ".webm", ".mp3", ".wav", ".ogg",
    ".docx", ".xlsx", ".pptx", ".pdf", ".ico", ".zip", ".tar", ".gz", ".bz2",
})

SUSPICIOUS_EXTENSIONS = frozenset({".sh", ".bat", ".ps1"})

DANGEROUS_EXTENSIONS = frozenset({
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".sh", ".bat", ".ps1",
})

CODE_FILE_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".sh", ".bash", ".zsh", ".ps1", ".bat",
    ".rb", ".php", ".go", ".rs", ".java", ".kt", ".swift",
    ".c", ".cpp", ".h", ".hpp",
})

KNOWN_SAFE_FILES = frozenset({
    ".gitignore", ".gitattributes", ".dockerignore",
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "Pipfile.lock", "Gemfile.lock",
})

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


RULE_FILE_FILTERS: dict[str, dict] = {
    "SR-001": {
        "exclude_extensions": [".css", ".html", ".htm", ".svg"],
        "exclude_dirs": [],
        "note": "Prompt injection — exclude non-instruction files (CSS/HTML/SVG are styling/markup, not AI instructions)",
    },
    "SR-002": {
        "exclude_extensions": [".html", ".css", ".svg", ".md", ".markdown", ".txt", ".rst", ".json", ".yaml", ".yml", ".toml"],
        "exclude_dirs": [],
        "note": "Dangerous shell — only code files; PATH pattern case-sensitive + code only",
    },
    "SR-003": {
        "exclude_extensions": [],
        "exclude_dirs": [],
        "note": "Credential access — filesystem-enum patterns code-only; env pattern global",
    },
    "SR-008": {
        "exclude_extensions": [".html", ".css", ".svg", ".md", ".markdown", ".txt", ".rst"],
        "exclude_dirs": [],
        "note": "Supply chain — URL patterns code-file only; deprecation/shell patterns global",
    },
    "SR-012": {
        "exclude_extensions": [".html", ".css", ".svg"],
        "exclude_dirs": [],
        "note": "System prompt leakage — code and .md files only",
    },
    "SR-013": {
        "exclude_extensions": [".html", ".css", ".svg"],
        "exclude_dirs": [],
        "note": "Memory poisoning — code and .md files only",
    },
    "SR-014": {
        "exclude_extensions": [".html", ".css", ".svg", ".md", ".markdown", ".txt", ".rst"],
        "exclude_dirs": [],
        "note": "SSRF — code files only; URLs in docs are normal links",
    },
    "SR-015": {
        "exclude_extensions": [".html", ".css", ".svg"],
        "exclude_dirs": [],
        "note": "Agent snooping — code and .md files only",
    },
    "SR-016": {
        "exclude_extensions": [".html", ".css", ".svg"],
        "exclude_dirs": [],
        "note": "Tool misuse — code and .md files only",
    },
}


def should_skip_file_for_rule(rule_id: str, rel_path: str) -> bool:
    """Check if a file should be skipped for a given rule based on config."""
    cfg = RULE_FILE_FILTERS.get(rule_id)
    if cfg is None:
        return False
    ext = Path(rel_path).suffix.lower()
    if ext in cfg.get("exclude_extensions", []):
        return True
    for pattern in cfg.get("exclude_files", []):
        if Path(rel_path).name == pattern:
            return True
    for pattern in cfg.get("exclude_dirs", []):
        if pattern in str(Path(rel_path).parent):
            return True
    return False
