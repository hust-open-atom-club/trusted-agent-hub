"""Auditable dependency-registry classification and matching policy.

Registry identity is deliberately separate from package safety.  Entries in
this module only decide whether an observed dependency source is approved for
the way it is being used; vulnerability, integrity, and source-code checks run
independently.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from enum import StrEnum
import ipaddress
import json
import re
from typing import Iterable
from urllib.parse import SplitResult, unquote, urlsplit

from scanners.risk_scanner.dependency_parsers.models import (
    DependencySourceUsage,
)


REGISTRY_POLICY_VERSION = "2026-09-22"


class RegistryClassification(StrEnum):
    OFFICIAL = "official"
    AUTHORITATIVE_MIRROR = "authoritative_mirror"
    APPROVED_PRIVATE = "approved_private"
    UNKNOWN = "unknown"


# Keep the historical public name while using the dependency model as the
# single source of truth for the two supported source-usage values.
RegistryUsage = DependencySourceUsage


_ECOSYSTEM_ALIASES = {
    "cargo": "cargo",
    "crates.io": "cargo",
    "rust": "cargo",
    "npm": "npm",
    "nuget": "nuget",
    "pypi": "pypi",
    "python": "pypi",
}
_SUPPORTED_ECOSYSTEMS = frozenset({"cargo", "npm", "nuget", "pypi"})
_UNKNOWN_ECOSYSTEM_FALLBACK_CLASSIFICATIONS = frozenset({
    RegistryClassification.OFFICIAL,
    RegistryClassification.APPROVED_PRIVATE,
})
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_REGISTRY_SCHEME_PREFIXES = (
    "registry+",
    "sparse+",
    "git+",
    "hg+",
    "svn+",
    "bzr+",
)
_ENCODED_PATH_SEPARATOR = re.compile(r"%(?:2f|5c)", re.IGNORECASE)


def normalize_ecosystem(value: str) -> str:
    normalized = str(value or "").strip().casefold()
    return _ECOSYSTEM_ALIASES.get(normalized, normalized)


def _normalize_hostname(value: str) -> str:
    raw = str(value or "").strip().rstrip(".")
    if not raw or any(char in raw for char in ("*", "/", "@", "?", "#")):
        raise ValueError("registry host must be an exact hostname")
    try:
        return ipaddress.ip_address(raw).compressed.casefold()
    except ValueError:
        pass
    try:
        normalized = raw.encode("idna").decode("ascii").casefold()
    except UnicodeError as exc:
        raise ValueError("registry host is not a valid IDNA hostname") from exc
    if len(normalized) > 253 or any(
        not _HOST_LABEL.fullmatch(label) for label in normalized.split(".")
    ):
        raise ValueError("registry host must be an exact hostname")
    return normalized


def _validated_https_url(
    value: str,
    *,
    field_name: str,
    allow_query_fragment: bool = False,
) -> str:
    raw = str(value or "").strip()
    try:
        parsed = urlsplit(raw)
        hostname = _normalize_hostname(parsed.hostname or "")
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a valid HTTPS URL") from exc
    if (
        parsed.scheme.casefold() != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or (not allow_query_fragment and (parsed.query or parsed.fragment))
    ):
        raise ValueError(f"{field_name} must be a credential-free HTTPS URL")
    if port is not None and not (1 <= port <= 65535):
        raise ValueError(f"{field_name} contains an invalid port")
    return raw


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    ecosystem: str
    classification: RegistryClassification
    evidence_url: str
    allow_as_resolved_download: bool
    note: str
    reviewed_at: date
    exact_host: str | None = None
    canonical_url: str | None = None

    def __post_init__(self) -> None:
        classification = RegistryClassification(self.classification)
        if classification is RegistryClassification.UNKNOWN:
            raise ValueError("unknown is a decision fallback, not a registry entry")
        object.__setattr__(self, "classification", classification)
        object.__setattr__(self, "ecosystem", normalize_ecosystem(self.ecosystem))
        if self.ecosystem not in _SUPPORTED_ECOSYSTEMS:
            raise ValueError(
                "registry entry ecosystem must be npm, pypi, cargo, or nuget"
            )
        if bool(self.exact_host) == bool(self.canonical_url):
            raise ValueError("registry entry must define exactly one match target")
        if not isinstance(self.allow_as_resolved_download, bool):
            raise ValueError("allow_as_resolved_download must be a boolean")
        if self.exact_host:
            object.__setattr__(self, "exact_host", _normalize_hostname(self.exact_host))
        if self.canonical_url:
            object.__setattr__(
                self,
                "canonical_url",
                _validated_https_url(self.canonical_url, field_name="canonical_url"),
            )
        object.__setattr__(
            self,
            "evidence_url",
            _validated_https_url(
                self.evidence_url,
                field_name="evidence_url",
                allow_query_fragment=True,
            ),
        )
        if not str(self.note or "").strip():
            raise ValueError("registry entry note must not be blank")
        if not isinstance(self.reviewed_at, date):
            raise ValueError("registry entry reviewed_at must be a date")


@dataclass(frozen=True, slots=True)
class RegistryDecision:
    classification: RegistryClassification
    allowed: bool
    reason: str
    normalized_host: str | None
    usage: RegistryUsage


@dataclass(frozen=True, slots=True)
class _ParsedSource:
    scheme: str
    hostname: str
    port: int | None
    path: str
    username_present: bool


def _parse_source_url(value: str) -> tuple[_ParsedSource | None, str]:
    candidate = str(value or "").strip()
    if not candidate or any(char.isspace() for char in candidate):
        return None, "invalid_url"
    lowered = candidate.casefold()
    for prefix in _REGISTRY_SCHEME_PREFIXES:
        if lowered.startswith(prefix):
            candidate = candidate[len(prefix):]
            break
    try:
        parsed = urlsplit(candidate)
        hostname = _normalize_hostname(parsed.hostname or "")
        port = parsed.port
    except (TypeError, ValueError):
        return None, "invalid_url"
    scheme = parsed.scheme.casefold()
    if not scheme or not hostname:
        return None, "non_registry_source"
    if _has_ambiguous_path(parsed.path):
        return None, "invalid_url"
    return (
        _ParsedSource(
            scheme=scheme,
            hostname=hostname,
            port=port,
            path=parsed.path or "/",
            username_present=(parsed.username is not None or parsed.password is not None),
        ),
        "matched",
    )


def _has_ambiguous_path(path: str) -> bool:
    """Reject paths whose interpretation can change after URL decoding."""
    current = path
    for _ in range(10):
        if "\\" in current or _ENCODED_PATH_SEPARATOR.search(current):
            return True
        if any(segment in {".", ".."} for segment in current.split("/")):
            return True
        decoded = unquote(current)
        if decoded == current:
            return False
        current = decoded
    # Deeply nested escaping is ambiguous across proxies that decode more
    # than once, so fail closed when it does not stabilize within the limit.
    return True


def _canonical_parts(entry: RegistryEntry) -> SplitResult | None:
    return urlsplit(entry.canonical_url) if entry.canonical_url else None


def _entry_hostname(entry: RegistryEntry) -> str:
    if entry.exact_host:
        return entry.exact_host
    parsed = _canonical_parts(entry)
    return _normalize_hostname(parsed.hostname or "") if parsed else ""


def _path_matches(entry: RegistryEntry, candidate_path: str) -> bool:
    parsed = _canonical_parts(entry)
    if parsed is None:
        return True
    expected = parsed.path or "/"
    if _has_ambiguous_path(expected) or _has_ambiguous_path(candidate_path):
        return False
    if expected.endswith("/"):
        return (
            candidate_path == expected.rstrip("/")
            or candidate_path.startswith(expected)
        )
    return candidate_path == expected


def _port_matches(entry: RegistryEntry, parsed: _ParsedSource) -> bool:
    if entry.exact_host:
        return parsed.port in (None, 443)
    canonical = _canonical_parts(entry)
    if canonical is None:
        return False
    expected_port = canonical.port or 443
    actual_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return actual_port == expected_port


@dataclass(frozen=True, slots=True, init=False)
class RegistryPolicy:
    entries: tuple[RegistryEntry, ...]
    version: str

    def __init__(
        self,
        entries: Iterable[RegistryEntry],
        *,
        version: str = REGISTRY_POLICY_VERSION,
    ) -> None:
        object.__setattr__(self, "entries", tuple(entries))
        object.__setattr__(self, "version", str(version))

    def evaluate(
        self,
        ecosystem: str,
        raw_url: str,
        usage: RegistryUsage | str,
    ) -> RegistryDecision:
        normalized_ecosystem = normalize_ecosystem(ecosystem)
        normalized_usage = RegistryUsage(usage)
        parsed, parse_reason = _parse_source_url(raw_url)
        if parsed is None:
            return RegistryDecision(
                RegistryClassification.UNKNOWN,
                False,
                parse_reason,
                None,
                normalized_usage,
            )

        ecosystem_is_known = normalized_ecosystem in _SUPPORTED_ECOSYSTEMS
        candidate_entries = tuple(
            entry
            for entry in self.entries
            if _entry_hostname(entry) == parsed.hostname
            and (
                entry.ecosystem == normalized_ecosystem
                if ecosystem_is_known
                else entry.classification
                in _UNKNOWN_ECOSYSTEM_FALLBACK_CLASSIFICATIONS
            )
        )
        path_matches = tuple(
            entry for entry in candidate_entries if _path_matches(entry, parsed.path)
        )

        transport_entry = (
            path_matches[0]
            if path_matches
            else candidate_entries[0]
            if candidate_entries
            else None
        )
        if parsed.username_present or parsed.scheme != "https":
            reason = (
                "non_registry_source"
                if parsed.scheme not in {"http", "https"}
                else "insecure_scheme"
                if parsed.scheme != "https"
                else "credentials_in_url"
            )
            return RegistryDecision(
                (
                    transport_entry.classification
                    if transport_entry
                    else RegistryClassification.UNKNOWN
                ),
                False,
                reason,
                parsed.hostname,
                normalized_usage,
            )

        if not path_matches:
            if ecosystem_is_known:
                cross_ecosystem_match = any(
                    entry.ecosystem != normalized_ecosystem
                    and _entry_hostname(entry) == parsed.hostname
                    and _path_matches(entry, parsed.path)
                    for entry in self.entries
                )
                reason = (
                    "canonical_url_mismatch"
                    if candidate_entries
                    else "wrong_ecosystem"
                    if cross_ecosystem_match
                    else "unknown_host"
                )
                matched = candidate_entries[0] if candidate_entries else None
            else:
                # Unknown observations may use an audited official/private
                # endpoint, but a host/path miss must remain fail-closed.
                reason = "unknown_host"
                matched = None
            return RegistryDecision(
                matched.classification if matched else RegistryClassification.UNKNOWN,
                False,
                reason,
                parsed.hostname,
                normalized_usage,
            )

        entry = path_matches[0]
        if not _port_matches(entry, parsed):
            reason = "unapproved_port"
        elif (
            normalized_usage is RegistryUsage.RESOLVED_DOWNLOAD
            and not entry.allow_as_resolved_download
        ):
            reason = "usage_not_allowed"
        else:
            return RegistryDecision(
                entry.classification,
                True,
                "matched",
                parsed.hostname,
                normalized_usage,
            )

        return RegistryDecision(
            entry.classification,
            False,
            reason,
            parsed.hostname,
            normalized_usage,
        )


_REVIEWED_AT = date(2026, 9, 22)

BUILTIN_REGISTRY_ENTRIES: tuple[RegistryEntry, ...] = (
    RegistryEntry(
        ecosystem="npm",
        exact_host="registry.npmjs.org",
        classification=RegistryClassification.OFFICIAL,
        evidence_url="https://docs.npmjs.com/cli/v11/using-npm/registry/",
        allow_as_resolved_download=True,
        note="npm CLI default public registry and package download host.",
        reviewed_at=_REVIEWED_AT,
    ),
    RegistryEntry(
        ecosystem="npm",
        exact_host="registry.yarnpkg.com",
        classification=RegistryClassification.AUTHORITATIVE_MIRROR,
        evidence_url="https://classic.yarnpkg.com/lang/en/docs/cli/config/",
        allow_as_resolved_download=True,
        note="Yarn Classic default registry proxy for npm packages.",
        reviewed_at=_REVIEWED_AT,
    ),
    RegistryEntry(
        ecosystem="pypi",
        canonical_url="https://pypi.org/simple/",
        classification=RegistryClassification.OFFICIAL,
        evidence_url="https://packaging.python.org/en/latest/specifications/simple-repository-api/",
        allow_as_resolved_download=False,
        note="Canonical PyPI Simple API base URL.",
        reviewed_at=_REVIEWED_AT,
    ),
    RegistryEntry(
        ecosystem="pypi",
        exact_host="files.pythonhosted.org",
        classification=RegistryClassification.OFFICIAL,
        evidence_url="https://docs.pypi.org/api/",
        allow_as_resolved_download=True,
        note="PyPI-hosted distribution file endpoint documented by PyPI.",
        reviewed_at=_REVIEWED_AT,
    ),
    RegistryEntry(
        ecosystem="cargo",
        canonical_url="https://github.com/rust-lang/crates.io-index",
        classification=RegistryClassification.OFFICIAL,
        evidence_url="https://doc.rust-lang.org/cargo/reference/registry-index.html",
        allow_as_resolved_download=False,
        note="Canonical crates.io git registry index.",
        reviewed_at=_REVIEWED_AT,
    ),
    RegistryEntry(
        ecosystem="cargo",
        canonical_url="https://index.crates.io/",
        classification=RegistryClassification.OFFICIAL,
        evidence_url="https://doc.rust-lang.org/cargo/reference/registry-index.html",
        allow_as_resolved_download=False,
        note="Canonical crates.io sparse registry index.",
        reviewed_at=_REVIEWED_AT,
    ),
    RegistryEntry(
        ecosystem="cargo",
        canonical_url="https://crates.io/",
        classification=RegistryClassification.OFFICIAL,
        evidence_url="https://doc.rust-lang.org/cargo/reference/registries.html",
        allow_as_resolved_download=False,
        note="Official crates.io registry service.",
        reviewed_at=_REVIEWED_AT,
    ),
    RegistryEntry(
        ecosystem="nuget",
        canonical_url="https://api.nuget.org/v3/index.json",
        classification=RegistryClassification.OFFICIAL,
        evidence_url="https://learn.microsoft.com/en-us/nuget/api/overview",
        allow_as_resolved_download=False,
        note="Official NuGet v3 service index; dependency parsing is not yet supported.",
        reviewed_at=_REVIEWED_AT,
    ),
)


def parse_approved_private_registries(raw_json: str | None) -> tuple[RegistryEntry, ...]:
    """Parse trusted server-side private-registry approvals from JSON."""
    if raw_json is None or not raw_json.strip():
        return ()
    try:
        value = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "TAH_APPROVED_PRIVATE_REGISTRIES_JSON must be valid JSON"
        ) from exc
    if not isinstance(value, list):
        raise ValueError("TAH_APPROVED_PRIVATE_REGISTRIES_JSON must be a JSON array")

    entries: list[RegistryEntry] = []
    allowed_keys = {
        "ecosystem",
        "exact_host",
        "canonical_url",
        "evidence_url",
        "allow_as_resolved_download",
        "note",
        "reviewed_at",
    }
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(
                f"TAH_APPROVED_PRIVATE_REGISTRIES_JSON[{index}] must be an object"
            )
        unknown_keys = set(item) - allowed_keys
        if unknown_keys:
            raise ValueError(
                "TAH_APPROVED_PRIVATE_REGISTRIES_JSON contains unsupported fields: "
                + ", ".join(sorted(unknown_keys))
            )
        required = {"ecosystem", "evidence_url", "note", "reviewed_at"}
        missing = sorted(key for key in required if not item.get(key))
        if missing:
            raise ValueError(
                f"TAH_APPROVED_PRIVATE_REGISTRIES_JSON[{index}] is missing: "
                + ", ".join(missing)
            )
        allow_download = item.get("allow_as_resolved_download", False)
        if not isinstance(allow_download, bool):
            raise ValueError("allow_as_resolved_download must be a boolean")
        try:
            reviewed_at = date.fromisoformat(str(item["reviewed_at"]))
        except ValueError as exc:
            raise ValueError("reviewed_at must use YYYY-MM-DD") from exc
        if reviewed_at > date.today():
            raise ValueError("reviewed_at must not be in the future")
        entries.append(
            RegistryEntry(
                ecosystem=str(item["ecosystem"]),
                exact_host=(str(item["exact_host"]) if item.get("exact_host") else None),
                canonical_url=(
                    str(item["canonical_url"]) if item.get("canonical_url") else None
                ),
                classification=RegistryClassification.APPROVED_PRIVATE,
                evidence_url=str(item["evidence_url"]),
                allow_as_resolved_download=allow_download,
                note=str(item["note"]),
                reviewed_at=reviewed_at,
            )
        )
    return tuple(entries)


def build_registry_policy(
    approved_private: Iterable[RegistryEntry] = (),
) -> RegistryPolicy:
    private_entries = tuple(approved_private)
    if any(
        entry.classification is not RegistryClassification.APPROVED_PRIVATE
        for entry in private_entries
    ):
        raise ValueError("runtime registry approvals must be approved_private entries")
    return RegistryPolicy((*BUILTIN_REGISTRY_ENTRIES, *private_entries))


DEFAULT_REGISTRY_POLICY = build_registry_policy()


__all__ = [
    "BUILTIN_REGISTRY_ENTRIES",
    "DEFAULT_REGISTRY_POLICY",
    "REGISTRY_POLICY_VERSION",
    "RegistryClassification",
    "RegistryDecision",
    "RegistryEntry",
    "RegistryPolicy",
    "RegistryUsage",
    "build_registry_policy",
    "normalize_ecosystem",
    "parse_approved_private_registries",
]
