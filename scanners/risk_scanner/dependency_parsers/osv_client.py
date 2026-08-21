from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from .models import DependencyRecord


@dataclass(frozen=True)
class OSVQueryResult:
    vulnerability_ids: list[str]
    error: str | None = None


class OSVClient:
    def __init__(self, *, timeout: float = 5.0, max_queries: int = 100, cache_ttl: int = 3600) -> None:
        self.timeout = timeout
        self.max_queries = max_queries
        self.cache_ttl = cache_ttl
        self._cache: dict[tuple[str, str, str | None], tuple[float, OSVQueryResult]] = {}
        self.queried = 0
        self.failures = 0
        self.limit_reached = False

    def query(self, dependency: DependencyRecord) -> OSVQueryResult:
        key = (dependency.ecosystem, dependency.name, dependency.version)
        cached = self._cache.get(key)
        if cached and time.time() - cached[0] < self.cache_ttl:
            return cached[1]
        if self.queried >= self.max_queries:
            self.limit_reached = True
            return OSVQueryResult([], "query_limit_exceeded")
        self.queried += 1
        payload = {"package": {"name": dependency.name, "ecosystem": dependency.ecosystem}}
        if dependency.version:
            payload["version"] = dependency.version
        try:
            request = urllib.request.Request(
                "https://api.osv.dev/v1/query", data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
            result = OSVQueryResult([v.get("id", "OSV-UNKNOWN") for v in data.get("vulns", [])])
        except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
            self.failures += 1
            result = OSVQueryResult([], type(exc).__name__)
        self._cache[key] = (time.time(), result)
        return result
