"""Server-side provenance verification helpers.

The package manifest is an evidence source, not an authority.  This module
only derives facts from the acquisition request/result and accepts the
optional verification flags supplied by a separately trusted verifier.  In
particular, a manifest's ``verified_owner`` or integrity URLs are never
promoted here.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


_COMMIT_RE = re.compile(r"^[a-f0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _normalise_github_url(value: str) -> tuple[str, str] | None:
    """Return a canonical ``(owner, repo)`` pair for a GitHub URL."""
    if not isinstance(value, str):
        return None
    parsed = urlparse(value.strip().rstrip("/"))
    try:
        port = parsed.port
    except ValueError:
        return None
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2:
        return None
    owner, repo = parts
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo:
        return None
    return owner.casefold(), repo.casefold()


def verify_acquired_repository(
    parsed: dict[str, Any] | None,
    repository_url: str,
    acquisition_method: str,
    commit_hash: str,
) -> bool:
    """Verify that the acquired source identity is internally consistent.

    A successful git/zip acquisition plus a valid commit proves that the
    bytes came from the canonical GitHub repository requested by the server.
    It does *not* trust a package-authored owner claim.  The stricter
    repository-owner/API check used by the default-branch flow can be passed
    in as ``parsed['repository_verified']`` and is also accepted here.
    """
    if not isinstance(parsed, dict):
        return False
    if acquisition_method not in {"git", "zip"}:
        return False
    if not _COMMIT_RE.fullmatch(str(commit_hash)):
        return False

    expected = _normalise_github_url(repository_url)
    if expected is None:
        return False
    owner = str(parsed.get("owner", "")).casefold()
    repo = str(parsed.get("repo", "")).casefold()
    if not owner or not repo or (owner, repo) != expected:
        return False

    # Repository identity is not the same as repository ownership.  Only an
    # explicit server-side verification result may promote this flag; missing
    # or malformed values remain unverified.
    return parsed.get("repository_verified") is True


def build_verification_facts(
    *,
    parsed: dict[str, Any] | None,
    repository_url: str,
    acquisition_method: str,
    commit_hash: str,
    content_sha256: str,
    content_hash_complete: bool = False,
    server_verification: dict[str, Any] | None = None,
) -> dict[str, bool]:
    """Build the four persisted verification flags.

    ``server_verification`` is intentionally an input from a verifier owned by
    the server (for example a signature/attestation worker), never from
    package metadata.  Artifact flags are accepted only when that verifier
    binds them to the exact content hash being scored.  The owner flag is
    always derived from the acquired repository identity rather than copied
    from an input flag.  Unknown or malformed values remain false.
    """
    supplied = server_verification if isinstance(server_verification, dict) else {}
    owner_verified = verify_acquired_repository(
        parsed,
        repository_url,
        acquisition_method,
        commit_hash,
    )
    supplied_content_sha256 = supplied.get("content_sha256")
    content_bound = (
        content_hash_complete
        and _is_sha256(content_sha256)
        and _is_sha256(supplied_content_sha256)
        and supplied_content_sha256 == content_sha256
    )
    return {
        "owner": owner_verified,
        "signature": supplied.get("signature") is True and content_bound,
        "attestation": supplied.get("attestation") is True and content_bound,
        "sbom": supplied.get("sbom") is True and content_bound,
    }
