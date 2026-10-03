from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import KW_ONLY, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from .models import DependencyRecord


logger = logging.getLogger(__name__)

OSVQueryStatus = Literal[
    "succeeded",
    "failed",
    "rate_limited",
    "unsupported",
    "not_queried",
]
OSVCoordinate = tuple[str, str, str]

DEFAULT_OSV_BASE_URL = "https://api.osv.dev"
_LOCAL_HTTP_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_SUPPORTED_ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "python": "PyPI",
    "crates.io": "crates.io",
    "cargo": "crates.io",
    "rust": "crates.io",
}
_RETRYABLE_HTTP_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_MAX_VULNERABILITIES_PER_COORDINATE = 1_000
_PERSISTENT_CACHE_MAX_ROWS = 200_000
# Three bind parameters are used per coordinate, plus one provider parameter.
# Keep each cache lookup below SQLite's commonly configured 999-parameter limit.
_PERSISTENT_CACHE_READ_BATCH_SIZE = 300
_PERSISTENT_CACHE_WRITE_LOCK = threading.Lock()


def _validated_base_url(value: object) -> str:
    raw = str(value or "").strip().rstrip("/")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("base_url must be an absolute HTTP(S) URL") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "base_url must be a credential-free HTTP(S) origin without a path"
        )
    if parsed.scheme == "http" and parsed.hostname not in _LOCAL_HTTP_HOSTS:
        raise ValueError("base_url must use HTTPS unless it is a loopback origin")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("base_url contains an invalid port")
    return raw


@dataclass(frozen=True)
class OSVQueryResult:
    """Auditable result for one normalized dependency coordinate."""

    vulnerability_ids: list[str]
    _: KW_ONLY
    status: OSVQueryStatus = "succeeded"
    queried_at: str | None = None
    response_status: int | None = None
    failure_reason: str | None = None
    from_cache: bool = False
    cache_source: str | None = None
    cache_age_seconds: int | None = None
    attempts: int = 0


@dataclass(frozen=True)
class OSVHTTPResponse:
    status_code: int
    body: bytes
    headers: Mapping[str, str]


OSVRequester = Callable[[bytes, float], OSVHTTPResponse]


def normalize_osv_ecosystem(value: object) -> str | None:
    return _SUPPORTED_ECOSYSTEMS.get(str(value or "").strip().casefold())


def _exact_version(value: object) -> str | None:
    version = str(value or "").strip()
    if not version or len(version) > 256:
        return None
    lowered = version.casefold()
    if (
        lowered in {"latest", "stable", "next", "*"}
        or "://" in lowered
        or lowered.startswith(
            ("git+", "git:", "github:", "file:", "link:", "workspace:", "npm:")
        )
        or version.startswith(("^", "~", ">", "<", "=", "!"))
        or any(token in version for token in ("||", "&&", ",", "*"))
        or lowered == "x"
        or lowered.startswith(("x.", "v*"))
        or lowered.endswith((".x", ".*"))
        or any(character.isspace() for character in version)
    ):
        return None
    return version


def _normalized_package_name(value: object, ecosystem: str) -> str:
    name = str(value or "").strip().casefold()
    if ecosystem == "PyPI":
        # PEP 503 names are case-insensitive and collapse runs of [-_.].
        pieces: list[str] = []
        separator_pending = False
        for character in name:
            if character in "-_.":
                separator_pending = bool(pieces)
                continue
            if separator_pending:
                pieces.append("-")
                separator_pending = False
            pieces.append(character)
        return "".join(pieces).rstrip("-")
    return name


def dependency_coordinate(dependency: DependencyRecord) -> OSVCoordinate:
    ecosystem = normalize_osv_ecosystem(dependency.ecosystem)
    normalized_ecosystem = ecosystem or str(
        dependency.ecosystem or "unknown"
    ).strip().casefold()
    return (
        normalized_ecosystem,
        _normalized_package_name(dependency.name, normalized_ecosystem),
        str(dependency.version or "").strip(),
    )


def dependency_queryability(dependency: DependencyRecord) -> tuple[bool, str | None]:
    ecosystem = normalize_osv_ecosystem(dependency.ecosystem)
    if ecosystem is None:
        return False, "unsupported_ecosystem"
    name = str(dependency.name or "").strip()
    if (
        not name
        or not _normalized_package_name(name, ecosystem)
        or len(name) > 256
        or any(ord(character) < 32 for character in name)
    ):
        return False, "invalid_package_name"
    raw_version = str(dependency.version or "").strip()
    if not raw_version:
        return False, "missing_version"
    if _exact_version(raw_version) is None:
        return False, "non_exact_version"
    return True, None


def _utc_iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def _header_value(headers: Mapping[str, str] | object, name: str) -> str | None:
    getter = getattr(headers, "get", None)
    if callable(getter):
        value = getter(name)
        if value is not None:
            return str(value)
    if isinstance(headers, Mapping):
        for key, value in headers.items():
            if str(key).casefold() == name.casefold():
                return str(value)
    return None


class OSVClient:
    """Bounded, batched OSV client with optional durable success caching."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        base_url: str = DEFAULT_OSV_BASE_URL,
        allow_private_coordinates: bool = False,
        timeout: float = 15.0,
        max_queries: int = 5_000,
        cache_ttl: int = 3_600,
        batch_size: int = 100,
        max_concurrency: int = 4,
        max_retries: int = 2,
        retry_backoff_seconds: float = 0.25,
        max_retry_delay_seconds: float = 5.0,
        cache_path: str | Path | None = None,
        requester: OSVRequester | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(enabled, bool):
            raise ValueError("enabled must be a boolean")
        if not isinstance(allow_private_coordinates, bool):
            raise ValueError("allow_private_coordinates must be a boolean")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if max_queries < 1:
            raise ValueError("max_queries must be at least 1")
        if cache_ttl < 0:
            raise ValueError("cache_ttl must be non-negative")
        if batch_size < 1 or batch_size > 1_000:
            raise ValueError("batch_size must be between 1 and 1000")
        if max_concurrency < 1 or max_concurrency > 32:
            raise ValueError("max_concurrency must be between 1 and 32")
        if max_retries < 0 or max_retries > 8:
            raise ValueError("max_retries must be between 0 and 8")
        if retry_backoff_seconds < 0 or max_retry_delay_seconds < 0:
            raise ValueError("retry delays must be non-negative")

        self.enabled = enabled
        self.base_url = _validated_base_url(base_url)
        self.query_url = f"{self.base_url}/v1/querybatch"
        self.allow_private_coordinates = allow_private_coordinates
        self.timeout = float(timeout)
        self.max_queries = int(max_queries)
        self.cache_ttl = int(cache_ttl)
        self.batch_size = int(batch_size)
        self.max_concurrency = int(max_concurrency)
        self.max_retries = int(max_retries)
        self.retry_backoff_seconds = float(retry_backoff_seconds)
        self.max_retry_delay_seconds = float(max_retry_delay_seconds)
        self.cache_path = Path(cache_path).resolve() if cache_path else None
        self._requester = requester or self._default_requester
        self._sleeper = sleeper
        self._clock = clock
        self._cache: dict[OSVCoordinate, tuple[float, OSVQueryResult]] = {}
        self._cache_lock = threading.Lock()
        self._cache_setup_lock = threading.Lock()
        self._counter_lock = threading.Lock()
        self._cache_ready = False
        self._cache_checked = False

        # ``queried`` counts coordinates sent to OSV; ``request_count`` counts
        # HTTP attempts (including retries).
        self.queried = 0
        self.failures = 0
        self.rate_limited = 0
        self.skipped = 0
        self.cache_hits = 0
        self.request_count = 0
        self.limit_reached = False

    def _default_requester(self, payload: bytes, timeout: float) -> OSVHTTPResponse:
        request = urllib.request.Request(
            self.query_url,
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(body) > _MAX_RESPONSE_BYTES:
                raise ValueError("response_too_large")
            status_code = getattr(response, "status", None)
            if status_code is None:
                getcode = getattr(response, "getcode", None)
                status_code = getcode() if callable(getcode) else 200
            headers = getattr(response, "headers", {})
            return OSVHTTPResponse(int(status_code or 200), body, headers)

    def _ensure_cache(self) -> None:
        if self.cache_path is None or self._cache_checked:
            return
        with self._cache_setup_lock:
            if self._cache_checked:
                return
            try:
                self.cache_path.parent.mkdir(parents=True, exist_ok=True)
                with _PERSISTENT_CACHE_WRITE_LOCK:
                    with sqlite3.connect(self.cache_path, timeout=5) as connection:
                        connection.execute("PRAGMA journal_mode=WAL")
                        connection.execute(
                            """
                            CREATE TABLE IF NOT EXISTS osv_query_cache_v2 (
                                provider TEXT NOT NULL,
                                ecosystem TEXT NOT NULL,
                                package_name TEXT NOT NULL,
                                version TEXT NOT NULL,
                                queried_at REAL NOT NULL,
                                response_status INTEGER,
                                vulnerability_ids TEXT NOT NULL,
                                PRIMARY KEY (provider, ecosystem, package_name, version)
                            )
                            """
                        )
                        connection.execute(
                            """
                            CREATE INDEX IF NOT EXISTS
                                osv_query_cache_v2_queried_at_idx
                            ON osv_query_cache_v2 (queried_at DESC)
                            """
                        )
                        connection.execute(
                            "DELETE FROM osv_query_cache_v2 WHERE queried_at < ?",
                            (self._clock() - self.cache_ttl,),
                        )
                        connection.execute(
                            """
                            DELETE FROM osv_query_cache_v2
                            WHERE rowid IN (
                                SELECT rowid
                                FROM osv_query_cache_v2
                                ORDER BY queried_at DESC
                                LIMIT -1 OFFSET ?
                            )
                            """,
                            (_PERSISTENT_CACHE_MAX_ROWS,),
                        )
                        connection.execute("DROP TABLE IF EXISTS osv_query_cache")
                self._cache_ready = True
            except (OSError, sqlite3.Error) as exc:
                self._cache_ready = False
                logger.warning("OSV persistent cache is unavailable: %s", exc)
            finally:
                self._cache_checked = True

    def _cached(self, key: OSVCoordinate) -> OSVQueryResult | None:
        """Return a valid in-memory result without performing persistent I/O."""
        if self.cache_ttl == 0:
            return None
        now = self._clock()
        with self._cache_lock:
            memory = self._cache.get(key)
            if memory is not None and now - memory[0] > self.cache_ttl:
                self._cache.pop(key, None)
                memory = None
        if memory is None:
            return None
        cached_at, result = memory
        age = max(0, int(now - cached_at))
        self.cache_hits += 1
        return replace(
            result,
            from_cache=True,
            cache_source="memory",
            cache_age_seconds=age,
            attempts=0,
        )

    def _preload_persistent_cache(
        self,
        keys: Sequence[OSVCoordinate],
    ) -> dict[OSVCoordinate, OSVQueryResult]:
        """Load many persistent entries with one connection and bounded SQL."""
        if not keys or self.cache_ttl == 0 or self.cache_path is None:
            return {}
        self._ensure_cache()
        if not self._cache_ready:
            return {}

        unique_keys = list(dict.fromkeys(keys))
        rows: list[tuple[object, ...]] = []
        try:
            with sqlite3.connect(self.cache_path, timeout=5) as connection:
                for index in range(
                    0,
                    len(unique_keys),
                    _PERSISTENT_CACHE_READ_BATCH_SIZE,
                ):
                    batch = unique_keys[
                        index : index + _PERSISTENT_CACHE_READ_BATCH_SIZE
                    ]
                    placeholders = ",".join("(?, ?, ?)" for _key in batch)
                    parameters = tuple(value for key in batch for value in key)
                    rows.extend(
                        connection.execute(
                            f"""
                            SELECT ecosystem, package_name, version,
                                   queried_at, response_status,
                                   vulnerability_ids
                            FROM osv_query_cache_v2
                            WHERE provider = ?
                              AND (ecosystem, package_name, version)
                                  IN ({placeholders})
                            """,
                            (self.base_url, *parameters),
                        ).fetchall()
                    )
        except sqlite3.Error as exc:
            self._cache_ready = False
            logger.warning("OSV persistent cache batch read failed: %s", exc)
            return {}

        now = self._clock()
        loaded: dict[OSVCoordinate, OSVQueryResult] = {}
        memory_entries: dict[
            OSVCoordinate, tuple[float, OSVQueryResult]
        ] = {}
        for row in rows:
            ecosystem, package_name, version = (str(value) for value in row[:3])
            key = (ecosystem, package_name, version)
            try:
                queried_at = float(row[3])
                vulnerability_ids = json.loads(str(row[5]))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            age = max(0, int(now - queried_at))
            if age > self.cache_ttl:
                continue
            if not isinstance(vulnerability_ids, list) or not all(
                isinstance(value, str) for value in vulnerability_ids
            ):
                continue
            try:
                response_status = int(row[4]) if row[4] is not None else None
            except (TypeError, ValueError):
                response_status = None
            result = OSVQueryResult(
                vulnerability_ids,
                status="succeeded",
                queried_at=_utc_iso(queried_at),
                response_status=response_status,
                attempts=0,
            )
            memory_entries[key] = (queried_at, result)
            loaded[key] = replace(
                result,
                from_cache=True,
                cache_source="persistent",
                cache_age_seconds=age,
            )
        with self._cache_lock:
            self._cache.update(memory_entries)
        self.cache_hits += len(loaded)
        return loaded

    def _store_successes(
        self, results: Mapping[OSVCoordinate, OSVQueryResult]
    ) -> None:
        if not results or self.cache_ttl == 0:
            return
        cached_at = self._clock()
        memory_entries = {
            key: (
                cached_at,
                replace(
                    result,
                    from_cache=False,
                    cache_source=None,
                    cache_age_seconds=None,
                ),
            )
            for key, result in results.items()
        }
        with self._cache_lock:
            self._cache.update(memory_entries)
        if self.cache_path is None:
            return
        self._ensure_cache()
        if not self._cache_ready:
            return
        try:
            with _PERSISTENT_CACHE_WRITE_LOCK:
                if not self._cache_ready:
                    return
                with sqlite3.connect(self.cache_path, timeout=5) as connection:
                    connection.executemany(
                        """
                        INSERT INTO osv_query_cache_v2 (
                            provider, ecosystem, package_name, version, queried_at,
                            response_status, vulnerability_ids
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(provider, ecosystem, package_name, version) DO UPDATE SET
                            queried_at = excluded.queried_at,
                            response_status = excluded.response_status,
                            vulnerability_ids = excluded.vulnerability_ids
                        """,
                        [
                            (
                                self.base_url,
                                *key,
                                cached_at,
                                result.response_status,
                                json.dumps(
                                    result.vulnerability_ids,
                                    separators=(",", ":"),
                                ),
                            )
                            for key, result in results.items()
                        ],
                    )
        except sqlite3.Error as exc:
            self._cache_ready = False
            logger.warning("OSV persistent cache write failed: %s", exc)

    @staticmethod
    def _payload(
        records: Sequence[tuple[OSVCoordinate, DependencyRecord]],
    ) -> bytes:
        queries = []
        for key, dependency in records:
            ecosystem, _normalized_name, version = key
            queries.append(
                {
                    "package": {
                        "name": str(dependency.name).strip(),
                        "ecosystem": ecosystem,
                    },
                    "version": version,
                }
            )
        return json.dumps({"queries": queries}, separators=(",", ":")).encode(
            "utf-8"
        )

    def _retry_delay(
        self, attempt: int, headers: Mapping[str, str] | object
    ) -> float:
        retry_after = _header_value(headers, "Retry-After")
        if retry_after is not None:
            try:
                return min(
                    max(0.0, float(retry_after)),
                    self.max_retry_delay_seconds,
                )
            except ValueError:
                pass
        exponential = self.retry_backoff_seconds * (2 ** max(attempt - 1, 0))
        return min(exponential, self.max_retry_delay_seconds)

    def _failed_batch(
        self,
        records: Sequence[tuple[OSVCoordinate, DependencyRecord]],
        *,
        status: OSVQueryStatus,
        reason: str,
        response_status: int | None,
        attempts: int,
    ) -> dict[OSVCoordinate, OSVQueryResult]:
        queried_at = _utc_iso(self._clock())
        return {
            key: OSVQueryResult(
                [],
                status=status,
                queried_at=queried_at,
                response_status=response_status,
                failure_reason=reason,
                attempts=attempts,
            )
            for key, _dependency in records
        }

    def _query_batch(
        self,
        records: Sequence[tuple[OSVCoordinate, DependencyRecord]],
    ) -> dict[OSVCoordinate, OSVQueryResult]:
        payload = self._payload(records)
        attempts = 0
        while attempts <= self.max_retries:
            attempts += 1
            with self._counter_lock:
                self.request_count += 1
            response_status: int | None = None
            headers: Mapping[str, str] | object = {}
            try:
                response = self._requester(payload, self.timeout)
                response_status = int(response.status_code)
                headers = response.headers
                if response_status == 429:
                    reason = "rate_limited"
                    status: OSVQueryStatus = "rate_limited"
                elif response_status in _RETRYABLE_HTTP_STATUSES:
                    reason = "provider_server_error"
                    status = "failed"
                elif not 200 <= response_status < 300:
                    return self._failed_batch(
                        records,
                        status="failed",
                        reason="provider_client_error",
                        response_status=response_status,
                        attempts=attempts,
                    )
                else:
                    try:
                        payload_data = json.loads(response.body.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                        return self._failed_batch(
                            records,
                            status="failed",
                            reason="response_parse_error",
                            response_status=response_status,
                            attempts=attempts,
                        )
                    result_rows = (
                        payload_data.get("results")
                        if isinstance(payload_data, dict)
                        else None
                    )
                    if not isinstance(result_rows, list) or len(result_rows) != len(
                        records
                    ):
                        return self._failed_batch(
                            records,
                            status="failed",
                            reason="partial_response",
                            response_status=response_status,
                            attempts=attempts,
                        )
                    queried_at = _utc_iso(self._clock())
                    results: dict[OSVCoordinate, OSVQueryResult] = {}
                    for (key, _dependency), row in zip(records, result_rows):
                        vulnerabilities = (
                            row.get("vulns", []) if isinstance(row, dict) else []
                        )
                        if not isinstance(vulnerabilities, list):
                            return self._failed_batch(
                                records,
                                status="failed",
                                reason="response_parse_error",
                                response_status=response_status,
                                attempts=attempts,
                            )
                        vulnerability_ids: list[str] = []
                        for vulnerability in vulnerabilities:
                            identifier = (
                                vulnerability.get("id")
                                if isinstance(vulnerability, dict)
                                else None
                            )
                            if isinstance(identifier, str) and identifier.strip():
                                vulnerability_ids.append(identifier.strip()[:128])
                        result = OSVQueryResult(
                            sorted(set(vulnerability_ids))[
                                :_MAX_VULNERABILITIES_PER_COORDINATE
                            ],
                            status="succeeded",
                            queried_at=queried_at,
                            response_status=response_status,
                            attempts=attempts,
                        )
                        results[key] = result
                    self._store_successes(results)
                    return results
            except urllib.error.HTTPError as exc:
                response_status = int(exc.code)
                headers = exc.headers or {}
                if response_status == 429:
                    reason = "rate_limited"
                    status = "rate_limited"
                elif response_status in _RETRYABLE_HTTP_STATUSES:
                    reason = "provider_server_error"
                    status = "failed"
                else:
                    return self._failed_batch(
                        records,
                        status="failed",
                        reason="provider_client_error",
                        response_status=response_status,
                        attempts=attempts,
                    )
            except TimeoutError:
                reason = "timeout"
                status = "failed"
            except (urllib.error.URLError, OSError):
                reason = "network_error"
                status = "failed"
            except ValueError as exc:
                reason = (
                    "response_too_large"
                    if str(exc) == "response_too_large"
                    else "response_parse_error"
                )
                return self._failed_batch(
                    records,
                    status="failed",
                    reason=reason,
                    response_status=response_status,
                    attempts=attempts,
                )

            if attempts > self.max_retries:
                return self._failed_batch(
                    records,
                    status=status,
                    reason=reason,
                    response_status=response_status,
                    attempts=attempts,
                )
            delay = self._retry_delay(attempts, headers)
            if delay:
                self._sleeper(delay)

        return self._failed_batch(
            records,
            status="failed",
            reason="internal_error",
            response_status=None,
            attempts=attempts,
        )

    def query_many(
        self,
        dependencies: Sequence[DependencyRecord],
    ) -> dict[OSVCoordinate, OSVQueryResult]:
        unique: dict[OSVCoordinate, DependencyRecord] = {}
        for dependency in dependencies:
            unique.setdefault(dependency_coordinate(dependency), dependency)

        results: dict[OSVCoordinate, OSVQueryResult] = {}
        memory_misses: list[tuple[OSVCoordinate, DependencyRecord]] = []
        for key in sorted(unique):
            dependency = unique[key]
            queryable, reason = dependency_queryability(dependency)
            if not queryable:
                results[key] = OSVQueryResult(
                    [],
                    status="unsupported",
                    failure_reason=reason,
                )
                continue
            if not self.enabled:
                results[key] = OSVQueryResult(
                    [],
                    status="not_queried",
                    failure_reason="provider_disabled",
                )
                self.skipped += 1
                continue
            cached = self._cached(key)
            if cached is not None:
                results[key] = cached
            else:
                memory_misses.append((key, dependency))

        persistent_hits = self._preload_persistent_cache(
            [key for key, _dependency in memory_misses]
        )
        misses: list[tuple[OSVCoordinate, DependencyRecord]] = []
        for key, dependency in memory_misses:
            cached = persistent_hits.get(key)
            if cached is not None:
                results[key] = cached
            else:
                misses.append((key, dependency))

        available = max(self.max_queries - self.queried, 0)
        selected = misses[:available]
        omitted = misses[available:]
        if omitted:
            self.limit_reached = True
            self.skipped += len(omitted)
            for key, _dependency in omitted:
                results[key] = OSVQueryResult(
                    [],
                    status="not_queried",
                    failure_reason="query_limit_exceeded",
                )

        if not selected:
            return results

        self.queried += len(selected)
        batches = [
            selected[index : index + self.batch_size]
            for index in range(0, len(selected), self.batch_size)
        ]
        workers = min(self.max_concurrency, len(batches))
        with ThreadPoolExecutor(
            max_workers=max(workers, 1),
            thread_name_prefix="osv-query",
        ) as executor:
            batch_iterator = iter(batches)
            pending: dict[
                Future[dict[OSVCoordinate, OSVQueryResult]],
                list[tuple[OSVCoordinate, DependencyRecord]],
            ] = {}

            def submit_next() -> bool:
                try:
                    batch = next(batch_iterator)
                except StopIteration:
                    return False
                pending[executor.submit(self._query_batch, batch)] = batch
                return True

            for _ in range(workers):
                submit_next()
            while pending:
                completed, _still_pending = wait(
                    pending,
                    return_when=FIRST_COMPLETED,
                )
                for future in completed:
                    batch = pending.pop(future)
                    try:
                        batch_results = future.result()
                    except Exception:  # pragma: no cover - fail-closed safety net
                        logger.exception("Unexpected OSV batch failure")
                        batch_results = self._failed_batch(
                            batch,
                            status="failed",
                            reason="internal_error",
                            response_status=None,
                            attempts=0,
                        )
                    results.update(batch_results)
                    submit_next()

        failed = sum(result.status == "failed" for result in results.values())
        rate_limited = sum(
            result.status == "rate_limited" for result in results.values()
        )
        self.failures += failed
        self.rate_limited += rate_limited
        return results

    def query(self, dependency: DependencyRecord) -> OSVQueryResult:
        key = dependency_coordinate(dependency)
        return self.query_many([dependency])[key]


__all__ = [
    "OSVClient",
    "OSVCoordinate",
    "OSVHTTPResponse",
    "OSVQueryResult",
    "OSVQueryStatus",
    "DEFAULT_OSV_BASE_URL",
    "dependency_coordinate",
    "dependency_queryability",
    "normalize_osv_ecosystem",
]
