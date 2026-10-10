"""Content-based credential recognizers shared by SR-004 and redaction.

Matches are private scanner inputs, never report payloads. A format match is
evidence of credential material, not a claim that a credential is live.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import math
import re
from collections import Counter
from collections.abc import Iterable, Iterator
from bisect import bisect_left, bisect_right


@dataclass(frozen=True)
class CredentialMatch:
    start: int
    end: int
    value: str = field(repr=False)
    type: str
    rule: str
    field: str = ""


# Explicit formats take precedence over placeholder/fixture classification.
FORMAT_RULES = (
    ("github_token", "github-token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    ("api_key", "openai-key", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"),
    ("cloud_credential", "aws-access-key", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    ("cloud_credential", "google-api-key", r"\bAIza[A-Za-z0-9_-]{35}\b"),
    ("cloud_credential", "digitalocean-token", r"\bdo[por]_v1_[a-f0-9]{64}\b"),
    ("token", "slack-token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ("token", "jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{8,}\b"),
)
_FORMATS = [(kind, rule, re.compile(pattern)) for kind, rule, pattern in FORMAT_RULES]
_PRIVATE_BOUNDARY = re.compile(r"-----(BEGIN|END) [A-Z ]*PRIVATE KEY-----")
_CONNECTION = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s/@:]+:(?P<value>[^\s/@]+)@", re.I)
_BEARER = re.compile(r"\bBearer\s+(?P<value>[A-Za-z0-9._~+/=-]+)", re.I)
_ASSIGNMENT = re.compile(
    r'''(?<![\w$])(?P<field>[A-Za-z_$][\w$.-]{0,127})["']?'''
    r'''(?:\s*:\s*(?:str|string)\s*)?\s*[:=](?!=)\s*'''
    r'''(?:(?P<quote>["'`])(?P<quoted>(?:\\[^\r\n]|(?!(?P=quote))[^\\\r\n])*?)(?P=quote)'''
    r'''|(?P<bare>[^\s,;}`"']+))'''
)


def field_type(name: str) -> str | None:
    name = re.sub(r"[^a-z0-9]", "", name.lower())
    if name.endswith(("privatekey",)):
        return "private_key"
    if name.endswith(("secretaccesskey", "accesskeyid", "accountkey")):
        return "cloud_credential"
    if name.endswith(("password", "passwd")):
        return "password"
    if name.endswith(("apikey", "accesskey")):
        return "api_key"
    if name.endswith(("token", "authorization")):
        return "token"
    if name.endswith("secret"):
        return "secret"
    return None


def find_credentials(content: str) -> list[CredentialMatch]:
    matches: list[CredentialMatch] = []
    # Linear delimiter walk also handles truncated PEM blocks conservatively.
    start: int | None = None
    for boundary in _PRIVATE_BOUNDARY.finditer(content):
        if boundary[1] == "BEGIN" and start is None:
            start = boundary.start()
        elif boundary[1] == "END" and start is not None:
            matches.append(CredentialMatch(start, boundary.end(), content[start:boundary.end()], "private_key", "private-key"))
            start = None
    if start is not None:
        matches.append(CredentialMatch(start, len(content), content[start:], "private_key", "private-key"))
    for kind, rule, pattern in _FORMATS:
        matches.extend(CredentialMatch(m.start(), m.end(), m[0], kind, rule) for m in pattern.finditer(content))
    for kind, rule, pattern in (
        ("connection_string", "connection-password", _CONNECTION),
        ("token", "bearer-token", _BEARER),
    ):
        matches.extend(CredentialMatch(m.start("value"), m.end("value"), m["value"], kind, rule) for m in pattern.finditer(content))
    matches.sort(key=lambda item: (item.start, item.end))
    format_starts = [item.start for item in matches]
    format_ends: list[int] = []
    for item in matches:
        format_ends.append(max(item.end, format_ends[-1] if format_ends else 0))
    for match in _ASSIGNMENT.finditer(content):
        kind = field_type(match["field"])
        if not kind:
            continue
        group = "quoted" if match["quote"] else "bare"
        value = match[group]
        if not value or value.startswith(("[REDACTED", "${", "{{", "process.env.", "os.environ", "getenv(")):
            continue
        if group == "bare":
            # Only dotenv/YAML scalar literals, not unquoted code expressions.
            prefix = content[content.rfind("\n", 0, match.start()) + 1:match.start()].strip()
            if prefix not in {"", "export"} or any(c in value for c in "()[]"):
                continue
            line_end = content.find("\n", match.end())
            tail = content[match.end():line_end if line_end >= 0 else len(content)].strip()
            if tail and not tail.startswith(("#", "//", "`")):
                continue
            if value in {"str", "string", "int", "bool", "boolean", "None", "null", "undefined", "True", "False", "true", "false", "Any"}:
                continue
        first, last = match.span(group)
        overlaps = [i for i in range(bisect_right(format_ends, first), bisect_left(format_starts, last)) if matches[i].end > first]
        if overlaps:
            for i in overlaps:
                matches[i] = replace(matches[i], field=match["field"])
        else:
            matches.append(CredentialMatch(first, last, value, kind, "literal-sensitive-field", match["field"]))
    # Overlapping bearer/provider hits describe the same material once.
    unique: dict[tuple[int, int], CredentialMatch] = {}
    for item in matches:
        unique.setdefault((item.start, item.end), item)
    return sorted(unique.values(), key=lambda m: (m.start, m.end, m.rule))


MAX_LITERAL_VALUES = 512
MAX_LITERAL_CHARS = 64 * 1024


class CredentialLimitExceeded(ValueError):
    """Cross-file credential analysis cannot complete within its fixed budget."""


@dataclass(frozen=True)
class LiteralRedactions:
    # Owned by a scan/snapshot, never a process-wide cache of credential values.
    pattern: re.Pattern[str] | None = field(default=None, repr=False)
    limited: bool = False

    def finditer(self, content: str) -> Iterator[re.Match[str]]:
        if self.limited:
            raise CredentialLimitExceeded("credential_literal_limit_exceeded")
        return self.pattern.finditer(content) if self.pattern is not None else iter(())


def literal_pattern(values: Iterable[str]) -> LiteralRedactions:
    """Bound input before sorting, escaping or compiling the alternation.

    Overflow deliberately retains no partial matcher: values omitted from a
    truncated allowlist would leak through cross-file references.
    """
    unique: set[str] = set()
    chars = 0
    for value in values:
        if not value or value in unique:
            continue
        if len(unique) >= MAX_LITERAL_VALUES or chars + len(value) > MAX_LITERAL_CHARS:
            return LiteralRedactions(limited=True)
        unique.add(value)
        chars += len(value)
    if not unique:
        return LiteralRedactions()
    ordered = sorted(unique, key=lambda value: (-len(value), value))
    return LiteralRedactions(re.compile("|".join(
        (r"(?<!\w)" if value[0].isalnum() or value[0] == "_" else "")
        + re.escape(value)
        + (r"(?!\w)" if value[-1].isalnum() or value[-1] == "_" else "")
        for value in ordered
    )))


def mask_literals(content: str, pattern: LiteralRedactions | None) -> str:
    """Preserve line numbers, including the final line of multiline values."""
    def mask(value: str) -> str:
        newlines = value.count("\n")
        return "[REDACTED]" + "\n" * newlines + ("[REDACTED]" if newlines and not value.endswith("\n") else "")
    if pattern is None or not content:
        return content
    if pattern.limited:
        return mask(content)
    return pattern.pattern.sub(lambda match: mask(match[0]), content) if pattern.pattern is not None else content


def entropy(value: str) -> float:
    counts = Counter(value)
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values()) if value else 0.0


# Exact content allow rules. No filename rules and no fuzzy "contains test" rule.
PLACEHOLDERS = frozenset({
    "YOUR_API_KEY", "YOUR_API_KEY_HERE", "YOUR_TOKEN", "YOUR_TOKEN_HERE",
    "YOUR_PASSWORD", "YOUR_PASSWORD_HERE", "REPLACE_ME", "CHANGEME",
    "<API_KEY>", "<TOKEN>", "<PASSWORD>",
})
FIXTURES = frozenset({"test-token", "test-password", "fake-token", "fake-password", "dummy-token", "dummy-password"})
EXAMPLES = frozenset({"example-token", "example-password", "sk-your-key-here", "ghp_example_token"})


def classify(value: str, rules: set[str], contexts: set[str], cross_file: bool) -> tuple[str, str, float, list[str]]:
    reasons = []
    formats = rules - {"literal-sensitive-field", "bearer-token"}
    if formats:
        reasons.append("credential_format")
    if len(value) >= 20 and entropy(value) >= 3.5:
        reasons.append("high_entropy")
    if cross_file:
        reasons.append("cross_file_reuse")
    reasons.extend(sorted(contexts & {"network_use", "config_write"}))
    if reasons:
        return ("credential_format" if formats else "suspected", "high", 0.99 if formats else 0.85, reasons)
    if value.upper() in PLACEHOLDERS:
        return "placeholder", "info", 1.0, ["exact_placeholder"]
    if value in FIXTURES and "test_assertion" in contexts:
        return "test_fixture", "info", 0.95, ["exact_fixture_with_assertion"]
    if value in EXAMPLES:
        return "example", "info", 0.95, ["exact_example"]
    return "unknown", "medium", 0.4, ["insufficient_evidence"]
