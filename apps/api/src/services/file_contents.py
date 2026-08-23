"""Safety filters for file content snapshots exposed by public APIs."""

from __future__ import annotations

from pathlib import PurePosixPath
import re


PUBLIC_FILE_MAX_BYTES = 64 * 1024
PUBLIC_FILE_TOTAL_MAX_BYTES = 512 * 1024
PUBLIC_FILE_MAX_COUNT = 80

_SAFE_SUFFIXES = {
    ".css",
    ".html",
    ".js",
    ".json",
    ".jsx",
    ".md",
    ".mjs",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}

_SAFE_FILENAMES = {
    ".gitattributes",
    ".gitignore",
    "dockerfile",
    "license",
    "makefile",
    "manifest.json",
    "package.json",
    "plugin.json",
    "pyproject.toml",
    "readme",
    "readme.md",
    "requirements.txt",
    "skill.md",
}

_SENSITIVE_FILENAMES = {
    ".env",
    ".env.local",
    ".npmrc",
    ".pypirc",
    "credentials",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "secret.json",
    "secrets.json",
}

_SENSITIVE_SUFFIXES = {
    ".env",
    ".key",
    ".p12",
    ".pem",
    ".pfx",
}

_SENSITIVE_PARTS = {
    ".aws",
    ".azure",
    ".config",
    ".gcp",
    ".gnupg",
    ".ssh",
    "credential",
    "credentials",
    "private",
    "secret",
    "secrets",
}

_SENSITIVE_SUBSTRINGS = (
    "api_key",
    "apikey",
    "auth_token",
    "authorization",
    "client_secret",
    "private_key",
)

_SECRET_VALUE_RE = re.compile(
    r"(?im)^\s*(?:[A-Z0-9_]*"
    r"(?:API[_-]?KEY|AUTH[_-]?TOKEN|CLIENT[_-]?SECRET|PASSWORD|PRIVATE[_-]?KEY|SECRET)"
    r"[A-Z0-9_]*)\s*[:=]\s*['\"]?[^'\"\s]{8,}"
)
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def normalize_public_file_path(path: object) -> str | None:
    """Return a stable relative POSIX path or None for unsafe path shapes."""
    if not isinstance(path, str):
        return None

    value = path.replace("\\", "/").strip()
    while value.startswith("./"):
        value = value[2:]
    if not value or value.startswith("/") or value.startswith("~"):
        return None

    parsed = PurePosixPath(value)
    if any(part in {"", ".", ".."} for part in parsed.parts):
        return None
    return parsed.as_posix()


def is_public_file_content_path(path: object) -> bool:
    """Allow only non-sensitive source/document files for public preview."""
    normalized = normalize_public_file_path(path)
    if normalized is None:
        return False

    parsed = PurePosixPath(normalized)
    parts = tuple(part.lower() for part in parsed.parts)
    name = parts[-1]

    if name.startswith(".env"):
        return False
    if name in _SENSITIVE_FILENAMES:
        return False
    if parsed.suffix.lower() in _SENSITIVE_SUFFIXES:
        return False
    if any(part in _SENSITIVE_PARTS for part in parts):
        return False
    joined = "/".join(parts)
    if any(token in joined for token in _SENSITIVE_SUBSTRINGS):
        return False

    return name in _SAFE_FILENAMES or parsed.suffix.lower() in _SAFE_SUFFIXES


def is_safe_public_file_content(path: object, content: object) -> bool:
    if not isinstance(content, str):
        return False
    if not is_public_file_content_path(path):
        return False
    if len(content.encode("utf-8")) > PUBLIC_FILE_MAX_BYTES:
        return False
    if _PRIVATE_KEY_RE.search(content):
        return False
    if _SECRET_VALUE_RE.search(content):
        return False
    return True


def sanitize_public_file_contents(
    file_contents: object,
    *,
    max_files: int = PUBLIC_FILE_MAX_COUNT,
    max_total_bytes: int = PUBLIC_FILE_TOTAL_MAX_BYTES,
) -> dict[str, str]:
    """Filter raw scan snapshots before exposing them through public APIs."""
    if not isinstance(file_contents, dict):
        return {}

    sanitized: dict[str, str] = {}
    total_bytes = 0
    for raw_path, raw_content in sorted(file_contents.items(), key=lambda item: str(item[0])):
        path = normalize_public_file_path(raw_path)
        if path is None or not is_safe_public_file_content(path, raw_content):
            continue

        content = raw_content
        size = len(content.encode("utf-8"))
        if total_bytes + size > max_total_bytes:
            continue

        sanitized[path] = content
        total_bytes += size
        if len(sanitized) >= max_files:
            break

    return sanitized
