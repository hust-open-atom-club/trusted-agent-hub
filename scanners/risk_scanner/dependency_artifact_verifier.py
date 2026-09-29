"""Bounded, SSRF-resistant acquisition of dependency artifact digests.

Lockfiles are untrusted input.  This module deliberately sits in front of the
scanner and turns approved dependency download URLs into small digest records;
artifact bodies are streamed and never retained.  Every redirect is evaluated
against the registry policy and resolved to public addresses before a pinned
TLS connection is opened.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import base64
import binascii
import hashlib
import hmac
import http.client
import ipaddress
import os
from pathlib import Path
import socket
import ssl
import threading
import time
from typing import Literal, Protocol
from urllib.parse import urljoin, urlsplit, urlunsplit

from scanners.risk_scanner.dependency_parsers import parse_dependencies
from scanners.risk_scanner.dependency_parsers.models import (
    DependencyRecord,
    DependencySourceUsage,
)
from scanners.risk_scanner.registry_policy import RegistryPolicy


_DIGEST_PRIORITIES = {"sha512": 4, "sha384": 3, "sha256": 2, "sha1": 1}
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_ARTIFACT_MANIFEST_NAMES = frozenset({
    "cargo.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pipfile.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "yarn.lock",
})


@dataclass(frozen=True, slots=True)
class ArtifactFetchConfig:
    """Operator-owned resource limits for dependency artifact acquisition."""

    max_artifacts: int = 100
    max_concurrency: int = 4
    max_artifact_bytes: int = 20 * 1024 * 1024
    max_total_bytes: int = 100 * 1024 * 1024
    timeout_seconds: float = 10.0
    max_redirects: int = 3
    chunk_size: int = 64 * 1024
    # Defaults mirror ScanPolicy so standalone callers do not acquire from a
    # lockfile that the default scanner would refuse to parse.
    max_manifest_file_bytes: int = 2 * 1024 * 1024
    max_manifest_total_bytes: int = 64 * 1024 * 1024
    max_manifest_files: int = 5000
    max_examined_files: int = 5000
    max_depth: int = 32
    user_agent: str = "TrustedAgentHub-Dependency-Integrity/1"

    def __post_init__(self) -> None:
        positive_integers = (
            self.max_artifacts,
            self.max_concurrency,
            self.max_artifact_bytes,
            self.max_total_bytes,
            self.chunk_size,
            self.max_manifest_file_bytes,
            self.max_manifest_total_bytes,
            self.max_manifest_files,
            self.max_examined_files,
        )
        if any(value < 1 for value in positive_integers):
            raise ValueError("artifact fetch limits must be positive")
        if self.timeout_seconds <= 0:
            raise ValueError("artifact fetch timeout must be positive")
        if self.max_redirects < 0 or self.max_depth < 0:
            raise ValueError("redirect and depth limits must not be negative")
        if not self.user_agent.strip():
            raise ValueError("artifact fetch user agent must not be blank")


@dataclass(frozen=True, slots=True)
class DependencyArtifactVerification:
    """Digest-only result for one resolved dependency URL."""

    status: Literal["fetched", "unavailable"]
    digests: Mapping[str, str] = field(default_factory=dict)
    size_bytes: int | None = None
    reason: str | None = None
    redirect_count: int = 0

    def __post_init__(self) -> None:
        if self.status == "fetched":
            if self.reason is not None or self.size_bytes is None:
                raise ValueError("fetched verification requires size and no reason")
            if set(self.digests) != set(_DIGEST_PRIORITIES):
                raise ValueError("fetched verification requires all supported digests")
        elif self.reason is None or self.digests or self.size_bytes is not None:
            raise ValueError("unavailable verification requires only a reason")
        if self.redirect_count < 0:
            raise ValueError("redirect_count must not be negative")


@dataclass(frozen=True, slots=True)
class DependencyArtifactAcquisition:
    """Batch result suitable for passing to ``RiskScanner``."""

    status: Literal["not_applicable", "complete", "partial"]
    verifications: Mapping[str, DependencyArtifactVerification]
    requested_count: int
    fetched_count: int
    unavailable_count: int
    bytes_downloaded: int
    unavailable_reasons: Mapping[str, int]
    collection_errors: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        """Return a URL-free operational summary safe for persistence."""
        return {
            "status": self.status,
            "requested_count": self.requested_count,
            "fetched_count": self.fetched_count,
            "unavailable_count": self.unavailable_count,
            "bytes_downloaded": self.bytes_downloaded,
            "unavailable_reasons": dict(self.unavailable_reasons),
            "collection_errors": list(self.collection_errors),
        }


class ArtifactHTTPResponse(Protocol):
    status: int

    def get_header(self, name: str) -> str | None: ...

    def read(self, size: int) -> bytes: ...

    def set_timeout(self, seconds: float) -> None: ...

    def close(self) -> None: ...


class ArtifactTransport(Protocol):
    def open(
        self,
        *,
        url: str,
        connect_ip: str,
        timeout_seconds: float,
        user_agent: str,
    ) -> ArtifactHTTPResponse: ...


Resolver = Callable[[str, int], Sequence[str]]


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TLS connection whose TCP peer is the address already policy-checked."""

    def __init__(
        self,
        host: str,
        port: int,
        connect_ip: str,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._connect_ip = connect_ip

    def connect(self) -> None:
        self.sock = socket.create_connection(
            (self._connect_ip, self.port),
            self.timeout,
            self.source_address,
        )
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class _StdlibHTTPResponse:
    def __init__(
        self,
        response: http.client.HTTPResponse,
        connection: _PinnedHTTPSConnection,
    ) -> None:
        self.status = response.status
        self._response = response
        self._connection = connection

    def get_header(self, name: str) -> str | None:
        return self._response.getheader(name)

    def read(self, size: int) -> bytes:
        return self._response.read(size)

    def set_timeout(self, seconds: float) -> None:
        if self._connection.sock is not None:
            self._connection.sock.settimeout(seconds)

    def close(self) -> None:
        try:
            self._response.close()
        finally:
            self._connection.close()


class StdlibArtifactTransport:
    """Direct HTTPS transport with no proxy or ambient credential support."""

    def __init__(self, *, context: ssl.SSLContext | None = None) -> None:
        self._context = context or ssl.create_default_context()

    def open(
        self,
        *,
        url: str,
        connect_ip: str,
        timeout_seconds: float,
        user_agent: str,
    ) -> ArtifactHTTPResponse:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        port = parsed.port or 443
        connection = _PinnedHTTPSConnection(
            host,
            port,
            connect_ip,
            timeout=timeout_seconds,
            context=self._context,
        )
        target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        try:
            connection.request(
                "GET",
                target,
                headers={
                    "Accept": "application/octet-stream",
                    "Connection": "close",
                    "User-Agent": user_agent,
                },
            )
            return _StdlibHTTPResponse(connection.getresponse(), connection)
        except Exception:
            connection.close()
            raise


@dataclass(frozen=True, slots=True)
class _ArtifactRequest:
    url: str
    ecosystems: tuple[str, ...]


class _SharedByteBudget:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0
        self._reserved = 0
        self._condition = threading.Condition()

    def reserve(self, amount: int, deadline: float) -> int:
        """Reserve bytes without making concurrent scheduling affect results."""
        with self._condition:
            while self.limit - self.used - self._reserved <= 0 and self._reserved:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return 0
                self._condition.wait(remaining)
            granted = min(amount, self.limit - self.used - self._reserved)
            self._reserved += granted
            return granted

    def settle(self, reserved: int, consumed: int) -> None:
        if reserved < 0 or consumed < 0 or consumed > reserved:
            raise ValueError("invalid byte-budget settlement")
        with self._condition:
            self._reserved -= reserved
            self.used += consumed
            self._condition.notify_all()


def _manifest_name(name: str) -> bool:
    lowered = name.casefold()
    return lowered in _ARTIFACT_MANIFEST_NAMES or (
        lowered.startswith("requirements") and lowered.endswith(".txt")
    )


def is_dependency_manifest_path(path: str) -> bool:
    """Return whether a POSIX-style snapshot path is dependency metadata."""
    if not isinstance(path, str) or not path or "\x00" in path:
        return False
    normalized = path.replace("\\", "/")
    return _manifest_name(normalized.rsplit("/", 1)[-1])


def _load_dependency_files(
    root: Path,
    config: ArtifactFetchConfig,
) -> tuple[dict[str, str], tuple[str, ...]]:
    files: dict[str, str] = {}
    errors: set[str] = set()
    examined = 0
    total_bytes = 0
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            entries = os.scandir(directory)
        except OSError:
            errors.add("directory_unreadable")
            continue
        with entries:
            for entry in entries:
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if entry.name != ".git" and depth < config.max_depth:
                            stack.append((Path(entry.path), depth + 1))
                        elif depth >= config.max_depth:
                            errors.add("manifest_depth_limit")
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    examined += 1
                    if examined > config.max_examined_files:
                        errors.add("examined_file_limit")
                        stack.clear()
                        break
                    if not _manifest_name(entry.name):
                        continue
                    if len(files) >= config.max_manifest_files:
                        errors.add("manifest_file_limit")
                        continue
                    stat = entry.stat(follow_symlinks=False)
                    if stat.st_size > config.max_manifest_file_bytes:
                        errors.add("manifest_file_size_limit")
                        continue
                    if total_bytes + stat.st_size > config.max_manifest_total_bytes:
                        errors.add("manifest_total_size_limit")
                        continue
                    path = Path(entry.path)
                    try:
                        resolved = path.resolve(strict=True)
                        if resolved != root and root not in resolved.parents:
                            errors.add("manifest_path_escape")
                            continue
                        # Bound the actual read as well as the preceding stat;
                        # a concurrently replaced/growing file must not turn
                        # the manifest pre-scan into an unbounded allocation.
                        with path.open("rb") as stream:
                            raw = stream.read(config.max_manifest_file_bytes + 1)
                        if len(raw) > config.max_manifest_file_bytes:
                            errors.add("manifest_file_size_limit")
                            continue
                        if len(raw) != stat.st_size:
                            errors.add("manifest_changed_during_read")
                            continue
                        content = raw.decode("utf-8-sig")
                    except (OSError, UnicodeError):
                        errors.add("manifest_unreadable")
                        continue
                    relative = resolved.relative_to(root).as_posix()
                    files[relative] = content
                    total_bytes += len(raw)
                except OSError:
                    errors.add("manifest_unreadable")
    return files, tuple(sorted(errors))


def _artifact_requests(
    files: Mapping[str, str],
) -> tuple[list[_ArtifactRequest], tuple[str, ...]]:
    records: list[DependencyRecord] = []
    errors: set[str] = set()
    for path, content in sorted(files.items()):
        try:
            records.extend(parse_dependencies({path: content}))
        except (RecursionError, TypeError, ValueError):
            errors.add("dependency_parse_error")
    grouped: dict[str, set[str]] = {}
    for record in records:
        if (
            record.registry
            and record.integrity
            and integrity_claim_supported(record.integrity)
            and record.registry_usage == DependencySourceUsage.RESOLVED_DOWNLOAD
        ):
            grouped.setdefault(record.registry, set()).add(record.ecosystem)
    return (
        [
            _ArtifactRequest(url, tuple(sorted(ecosystems)))
            for url, ecosystems in sorted(grouped.items())
        ],
        tuple(sorted(errors)),
    )


def _default_resolver(host: str, port: int) -> Sequence[str]:
    answers = socket.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP,
    )
    return tuple(dict.fromkeys(answer[4][0] for answer in answers))


def _public_addresses(
    host: str,
    port: int,
    resolver: Resolver,
) -> tuple[tuple[str, ...] | None, str | None]:
    try:
        raw_addresses = resolver(host, port)
        addresses = tuple(dict.fromkeys(str(item) for item in raw_addresses))
    except (OSError, ValueError):
        return None, "dns_failed"
    if not addresses:
        return None, "dns_failed"
    parsed: list[str] = []
    for value in addresses:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return None, "dns_failed"
        # ``is_global`` also excludes unspecified, multicast, reserved and the
        # shared address space in addition to loopback/private/link-local.
        if not address.is_global:
            return None, "unsafe_address"
        parsed.append(address.compressed)
    return tuple(parsed), None


def _public_addresses_before_deadline(
    host: str,
    port: int,
    resolver: Resolver,
    deadline_monotonic: float,
) -> tuple[tuple[str, ...] | None, str | None]:
    """Bound even the platform resolver, whose API has no timeout argument.

    A timed-out lookup is left only in a daemon thread. Because queued fetches
    observe the shared deadline before resolving, at most ``max_concurrency``
    such lookups can remain after a batch is terminalized.
    """

    remaining = deadline_monotonic - time.monotonic()
    if remaining <= 0:
        return None, "timeout"
    completed = threading.Event()
    outcome: list[tuple[tuple[str, ...] | None, str | None]] = []

    def resolve() -> None:
        try:
            outcome.append(_public_addresses(host, port, resolver))
        except Exception:
            outcome.append((None, "dns_failed"))
        finally:
            completed.set()

    threading.Thread(
        target=resolve,
        name="dependency-artifact-dns",
        daemon=True,
    ).start()
    if not completed.wait(remaining):
        return None, "timeout"
    return outcome[0] if outcome else (None, "dns_failed")


def _allowed_url(
    raw_url: str,
    ecosystems: Iterable[str],
    registry_policy: RegistryPolicy,
) -> tuple[str | None, tuple[str, ...], str | None]:
    if not isinstance(raw_url, str) or not raw_url or any(
        character.isspace() or ord(character) < 32 for character in raw_url
    ):
        return None, (), "invalid_url"
    try:
        parsed = urlsplit(raw_url)
        host = (parsed.hostname or "").encode("idna").decode("ascii").casefold()
        port = parsed.port
    except (UnicodeError, ValueError):
        return None, (), "invalid_url"
    if parsed.scheme.casefold() != "https":
        return None, (), "insecure_scheme"
    if parsed.username is not None or parsed.password is not None:
        return None, (), "credentials_in_url"
    if not host or "\\" in parsed.netloc:
        return None, (), "invalid_url"
    normalized = urlunsplit(("https", parsed.netloc, parsed.path or "/", parsed.query, ""))
    allowed_ecosystems = tuple(
        ecosystem
        for ecosystem in ecosystems
        if registry_policy.evaluate(
            ecosystem,
            normalized,
            DependencySourceUsage.RESOLVED_DOWNLOAD,
        ).allowed
    )
    if not allowed_ecosystems:
        return None, (), "registry_not_allowed"
    if port is not None and not (1 <= port <= 65535):
        return None, (), "invalid_url"
    return normalized, allowed_ecosystems, None


def _unavailable(reason: str, redirects: int = 0) -> DependencyArtifactVerification:
    return DependencyArtifactVerification(
        status="unavailable",
        reason=reason,
        redirect_count=redirects,
    )


def _fetch_one(
    request: _ArtifactRequest,
    *,
    registry_policy: RegistryPolicy,
    config: ArtifactFetchConfig,
    transport: ArtifactTransport,
    resolver: Resolver,
    byte_budget: _SharedByteBudget,
    deadline_monotonic: float,
) -> DependencyArtifactVerification:
    current_url = request.url
    ecosystems = request.ecosystems
    redirects = 0
    visited: set[str] = set()
    while True:
        if time.monotonic() >= deadline_monotonic:
            return _unavailable("timeout", redirects)
        normalized, ecosystems, rejection = _allowed_url(
            current_url,
            ecosystems,
            registry_policy,
        )
        if rejection or normalized is None:
            return _unavailable(rejection or "invalid_url", redirects)
        if normalized in visited:
            return _unavailable("redirect_loop", redirects)
        visited.add(normalized)
        parsed = urlsplit(normalized)
        addresses, resolution_error = _public_addresses_before_deadline(
            parsed.hostname or "",
            parsed.port or 443,
            resolver,
            deadline_monotonic,
        )
        if resolution_error or not addresses:
            return _unavailable(resolution_error or "dns_failed", redirects)
        remaining = deadline_monotonic - time.monotonic()
        if remaining <= 0:
            return _unavailable("timeout", redirects)
        response: ArtifactHTTPResponse | None = None
        try:
            last_open_reason = "transport_error"
            for connect_ip in addresses:
                remaining = deadline_monotonic - time.monotonic()
                if remaining <= 0:
                    return _unavailable("timeout", redirects)
                try:
                    response = transport.open(
                        url=normalized,
                        connect_ip=connect_ip,
                        timeout_seconds=remaining,
                        user_agent=config.user_agent,
                    )
                    break
                except (TimeoutError, socket.timeout):
                    last_open_reason = "timeout"
                except ssl.SSLError:
                    last_open_reason = "tls_error"
                except (http.client.HTTPException, OSError, ValueError):
                    last_open_reason = "transport_error"
            if response is None:
                return _unavailable(last_open_reason, redirects)
            if response.status in _REDIRECT_STATUSES:
                location = response.get_header("Location")
                if not location:
                    return _unavailable("redirect_missing_location", redirects)
                if redirects >= config.max_redirects:
                    return _unavailable("redirect_limit", redirects)
                current_url = urljoin(normalized, location)
                redirects += 1
                continue
            if response.status != 200:
                return _unavailable("http_status", redirects)
            content_length = response.get_header("Content-Length")
            transfer_encoding = response.get_header("Transfer-Encoding")
            if transfer_encoding is not None:
                transfer_tokens = [
                    token.strip().casefold()
                    for token in transfer_encoding.split(",")
                    if token.strip()
                ]
                if content_length is not None:
                    return _unavailable("ambiguous_response_framing", redirects)
                if transfer_tokens != ["chunked"]:
                    return _unavailable("unsupported_transfer_encoding", redirects)
            declared_size: int | None = None
            if content_length is not None:
                try:
                    declared_size = int(content_length)
                except ValueError:
                    return _unavailable("invalid_content_length", redirects)
                if declared_size < 0:
                    return _unavailable("invalid_content_length", redirects)
                if declared_size > config.max_artifact_bytes:
                    return _unavailable("artifact_too_large", redirects)

            digests = {
                algorithm: hashlib.new(algorithm)
                for algorithm in _DIGEST_PRIORITIES
            }
            size = 0
            while True:
                remaining = deadline_monotonic - time.monotonic()
                if remaining <= 0:
                    return _unavailable("timeout", redirects)
                response.set_timeout(max(remaining, 0.001))
                if declared_size is not None and size == declared_size:
                    break
                read_limit = min(
                    config.chunk_size,
                    config.max_artifact_bytes - size + 1,
                )
                allowance = byte_budget.reserve(
                    read_limit,
                    deadline_monotonic,
                )
                if allowance <= 0:
                    if time.monotonic() >= deadline_monotonic:
                        return _unavailable("timeout", redirects)
                    # An EOF probe is necessary for an unknown-length stream
                    # whose body exactly fills the shared budget. At most one
                    # sentinel byte is read and it is never hashed as evidence.
                    extra = response.read(1)
                    if extra:
                        return _unavailable("total_size_limit", redirects)
                    break
                try:
                    chunk = response.read(allowance)
                except Exception:
                    byte_budget.settle(allowance, 0)
                    raise
                byte_budget.settle(allowance, len(chunk))
                if not chunk:
                    if declared_size is not None and size != declared_size:
                        return _unavailable("truncated_response", redirects)
                    break
                size += len(chunk)
                if size > config.max_artifact_bytes:
                    return _unavailable("artifact_too_large", redirects)
                for digest in digests.values():
                    digest.update(chunk)
            return DependencyArtifactVerification(
                status="fetched",
                digests={name: digest.hexdigest() for name, digest in digests.items()},
                size_bytes=size,
                redirect_count=redirects,
            )
        except (TimeoutError, socket.timeout):
            return _unavailable("timeout", redirects)
        except ssl.SSLError:
            return _unavailable("tls_error", redirects)
        except (http.client.HTTPException, OSError, ValueError):
            return _unavailable("transport_error", redirects)
        finally:
            if response is not None:
                response.close()


def acquire_dependency_verifications(
    scan_dir: str | Path,
    registry_policy: RegistryPolicy,
    *,
    config: ArtifactFetchConfig | None = None,
    transport: ArtifactTransport | None = None,
    resolver: Resolver | None = None,
    manifest_files: Mapping[str, str] | None = None,
    manifest_collection_errors: Iterable[str] = (),
) -> DependencyArtifactAcquisition:
    """Acquire bounded digest evidence for lockfile dependency artifacts.

    The function is synchronous because the production scan pipeline runs in a
    worker thread.  Downloads within the call use a bounded thread pool.
    ``transport`` and ``resolver`` are injectable so tests never need network
    access and production DNS decisions remain explicit.
    """

    effective_config = config or ArtifactFetchConfig()
    effective_transport = transport or StdlibArtifactTransport()
    effective_resolver = resolver or _default_resolver
    deadline_monotonic = time.monotonic() + effective_config.timeout_seconds
    root = Path(scan_dir).resolve()
    if not root.is_dir():
        return DependencyArtifactAcquisition(
            status="partial",
            verifications={},
            requested_count=0,
            fetched_count=0,
            unavailable_count=0,
            bytes_downloaded=0,
            unavailable_reasons={},
            collection_errors=("invalid_scan_directory",),
        )

    supplied_errors = {
        str(error) for error in manifest_collection_errors if str(error)
    }
    if manifest_files is None:
        files, load_errors = _load_dependency_files(root, effective_config)
    else:
        files = {
            str(path): content
            for path, content in manifest_files.items()
            if isinstance(path, str)
            and isinstance(content, str)
            and is_dependency_manifest_path(path)
        }
        load_errors = ()
        if len(files) != len(manifest_files):
            supplied_errors.add("invalid_manifest_snapshot")
    requests, parse_errors = _artifact_requests(files)
    collection_errors = tuple(
        sorted(supplied_errors | set(load_errors) | set(parse_errors))
    )
    # Reject policy-ineligible URLs before applying the artifact budget. An
    # untrusted lockfile must not starve approved artifacts by flooding the
    # lexicographically earlier portion of the request set with blocked hosts.
    eligible_requests: list[_ArtifactRequest] = []
    verifications: dict[str, DependencyArtifactVerification] = {}
    for request in requests:
        _normalized, _ecosystems, rejection = _allowed_url(
            request.url,
            request.ecosystems,
            registry_policy,
        )
        if rejection:
            verifications[request.url] = _unavailable(rejection)
        else:
            eligible_requests.append(request)
    selected = eligible_requests[: effective_config.max_artifacts]
    omitted = eligible_requests[effective_config.max_artifacts :]
    verifications.update({
        request.url: _unavailable("artifact_limit") for request in omitted
    })
    budget = _SharedByteBudget(effective_config.max_total_bytes)
    if selected:
        with ThreadPoolExecutor(
            max_workers=min(effective_config.max_concurrency, len(selected)),
            thread_name_prefix="dependency-integrity",
        ) as executor:
            futures = {
                executor.submit(
                    _fetch_one,
                    request,
                    registry_policy=registry_policy,
                    config=effective_config,
                    transport=effective_transport,
                    resolver=effective_resolver,
                    byte_budget=budget,
                    deadline_monotonic=deadline_monotonic,
                ): request.url
                for request in selected
            }
            for future in as_completed(futures):
                url = futures[future]
                try:
                    verifications[url] = future.result()
                except Exception:  # pragma: no cover - final fail-closed guard
                    verifications[url] = _unavailable("internal_error")

    reasons = Counter(
        result.reason
        for result in verifications.values()
        if result.status == "unavailable" and result.reason is not None
    )
    fetched = sum(result.status == "fetched" for result in verifications.values())
    unavailable = len(verifications) - fetched
    if not requests and not collection_errors:
        status: Literal["not_applicable", "complete", "partial"] = "not_applicable"
    elif unavailable or collection_errors:
        status = "partial"
    else:
        status = "complete"
    return DependencyArtifactAcquisition(
        status=status,
        verifications=verifications,
        requested_count=len(requests),
        fetched_count=fetched,
        unavailable_count=unavailable,
        bytes_downloaded=budget.used,
        unavailable_reasons=dict(sorted(reasons.items())),
        collection_errors=collection_errors,
    )


def _integrity_candidates(claim: object) -> list[tuple[int, str, bytes]]:
    if not isinstance(claim, str):
        return []
    candidates: list[tuple[int, str, bytes]] = []
    for token in claim.split():
        if ":" in token and "-" not in token:
            algorithm, encoded = token.split(":", 1)
            try:
                expected = bytes.fromhex(encoded)
            except ValueError:
                continue
        elif "-" in token:
            algorithm, encoded = token.split("-", 1)
            try:
                expected = base64.b64decode(encoded.split("?", 1)[0], validate=True)
            except (ValueError, binascii.Error):
                continue
        else:
            continue
        algorithm = algorithm.casefold()
        if (
            algorithm in _DIGEST_PRIORITIES
            and len(expected) == hashlib.new(algorithm).digest_size
        ):
            candidates.append((_DIGEST_PRIORITIES[algorithm], algorithm, expected))
    return candidates


def match_integrity_bytes(content: bytes, claim: object) -> bool | None:
    """Check the strongest supported digest in a claim against artifact bytes."""
    candidates = _integrity_candidates(claim)
    if not candidates:
        return None
    strongest = max(candidate[0] for candidate in candidates)
    return any(
        hmac.compare_digest(hashlib.new(algorithm, content).digest(), expected)
        for priority, algorithm, expected in candidates
        if priority == strongest
    )


def match_integrity_verification(
    verification: DependencyArtifactVerification | Mapping[str, object],
    claim: object,
) -> bool | None:
    """Check a claim using a precomputed digest-only verification result."""
    candidates = _integrity_candidates(claim)
    if not candidates:
        return None
    if isinstance(verification, DependencyArtifactVerification):
        if verification.status != "fetched":
            return None
        digests = verification.digests
    else:
        if verification.get("status") != "fetched":
            return None
        value = verification.get("digests")
        digests = value if isinstance(value, Mapping) else {}
    strongest = max(candidate[0] for candidate in candidates)
    compared = False
    for priority, algorithm, expected in candidates:
        if priority != strongest:
            continue
        actual = digests.get(algorithm)
        if not isinstance(actual, str):
            continue
        try:
            actual_bytes = bytes.fromhex(actual)
        except ValueError:
            continue
        compared = True
        if hmac.compare_digest(actual_bytes, expected):
            return True
    return False if compared else None


def integrity_claim_supported(claim: object) -> bool:
    return bool(_integrity_candidates(claim))


__all__ = [
    "ArtifactFetchConfig",
    "ArtifactHTTPResponse",
    "ArtifactTransport",
    "DependencyArtifactAcquisition",
    "DependencyArtifactVerification",
    "Resolver",
    "StdlibArtifactTransport",
    "acquire_dependency_verifications",
    "integrity_claim_supported",
    "is_dependency_manifest_path",
    "match_integrity_bytes",
    "match_integrity_verification",
]
