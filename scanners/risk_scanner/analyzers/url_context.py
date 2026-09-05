"""Small, deterministic URL-use classifier shared by URL-related rules.

The scanner must not treat every URL-shaped string as a network action.  This
module deliberately answers the narrower question "how is this value used?"
without relying on package names or path allowlists.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


URL_USAGE_COMPARISON = "comparison"
URL_USAGE_DEPENDENCY = "dependency"
URL_USAGE_DOWNLOAD_EXECUTE = "download_execute"
URL_USAGE_LOCAL_REFERENCE = "local_reference"
URL_USAGE_NETWORK_REQUEST = "network_request"
URL_USAGE_STATIC_ASSET = "static_asset"
URL_USAGE_UNKNOWN = "unknown"

_NETWORK_CALL = re.compile(
    r"\b(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?|"
    r"requests?\.(?:get|post|put|delete|patch|request)|httpx\.|"
    r"urllib(?:\.request)?\.(?:urlopen|Request)|socket\.create_connection|"
    r"curl|wget)\b",
    re.IGNORECASE,
)
_DEPENDENCY_USE = re.compile(
    r"\b(?:pip|npm|pnpm|yarn|cargo|install|registry|dependency|dependencies|"
    r"resolved|download|curl|wget)\b",
    re.IGNORECASE,
)
_STATIC_ASSET = re.compile(
    r"(?:<img\b|\bsrc\s*=|background-image|\.png\b|\.jpe?g\b|\.gif\b|"
    r"\.svg\b|\.webp\b|\.ico\b|font-face)",
    re.IGNORECASE,
)
_COMPARISON = re.compile(r"(?:===|!==|==|!=|\.startsWith\s*\(|\.endsWith\s*\()")


def extract_hostname(value: str) -> str:
    """Return a normalized hostname from a URL-containing value."""
    match = re.search(r"https?://[^\s\"'<>`)]+", value, re.IGNORECASE)
    candidate = (match.group(0) if match else value).rstrip(".,;:!?")
    try:
        return (urlsplit(candidate).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def is_loopback_url(value: str) -> bool:
    """Return whether *value* points to localhost or a loopback IP."""
    hostname = extract_hostname(value)
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def surrounding_lines(content: str, line_no: int, radius: int = 2) -> str:
    lines = content.splitlines()
    start = max(0, line_no - 1 - radius)
    end = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end])


def classify_url_usage(content: str, line_no: int, matched_value: str) -> str:
    """Classify the observable use of a URL match near *line_no*.

    Classification is based on syntax around the match and the value's host.
    It intentionally does not infer trust from a repository, filename, or
    package identity.
    """
    context = surrounding_lines(content, line_no)
    current_line = (content.splitlines() or [""])[max(0, line_no - 1)]

    if re.search(r"(?:curl|wget).{0,240}(?:\||;|&&)\s*(?:ba)?sh\b", context, re.I | re.S):
        return URL_USAGE_DOWNLOAD_EXECUTE
    if _COMPARISON.search(current_line) and not _NETWORK_CALL.search(current_line):
        return URL_USAGE_COMPARISON
    if _STATIC_ASSET.search(context) and not re.search(
        r"(?:eval|exec|spawn|import\s*\(|subprocess)", context, re.I
    ):
        return URL_USAGE_STATIC_ASSET
    if _DEPENDENCY_USE.search(context):
        return URL_USAGE_DEPENDENCY
    if _NETWORK_CALL.search(context):
        return URL_USAGE_NETWORK_REQUEST
    if is_loopback_url(matched_value):
        return URL_USAGE_LOCAL_REFERENCE
    return URL_USAGE_UNKNOWN


def request_controlled_aliases(content: str) -> set[str]:
    """Find simple variables assigned from HTTP request fields.

    This is deliberately a one-hop, auditable baseline.  It covers common
    request query/header aliases while leaving complex flow to later analyzers.
    """
    aliases: set[str] = set()
    assignment = re.compile(
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)",
        re.IGNORECASE,
    )
    request_source = re.compile(
        r"\b(?:request|req)\s*\.\s*(?:headers?|query|body|params?|url)\b",
        re.IGNORECASE,
    )
    for match in assignment.finditer(content):
        if request_source.search(match.group(2)):
            aliases.add(match.group(1))
    return aliases
