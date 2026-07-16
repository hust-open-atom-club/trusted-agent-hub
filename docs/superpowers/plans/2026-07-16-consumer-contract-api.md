# Consumer Contract API Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build one strict, published-only Consumer v0.1 read API with a schema-compliant install manifest, repository abstraction, deterministic OpenAPI snapshot, and boundary-focused tests.

**Architecture:** FastAPI routers translate HTTP requests, focused services enforce public visibility and query semantics, and a `PackageRepository` protocol isolates the current JSON mock store from future PostgreSQL work. Pydantic/FastAPI are the runtime contract source; an export script commits a deterministic Consumer-only OpenAPI snapshot.

**Tech Stack:** Python 3.11+, FastAPI 0.115+, Pydantic 2, pytest, FastAPI TestClient, standard-library JSON/path/typing utilities.

---

## File map

### Create

- `apps/api/src/errors.py` — typed Consumer exceptions and JSON error handlers.
- `apps/api/src/dependencies.py` — cached production mock repository dependency.
- `apps/api/src/models/__init__.py` — public model exports.
- `apps/api/src/models/common.py` — enums, owner, generic pagination, and health/error models.
- `apps/api/src/models/packages.py` — package/version/source/permission/trust record and response models.
- `apps/api/src/models/install.py` — Install Manifest v1.0 models.
- `apps/api/src/models/legacy.py` — temporary response aliases required only until the old router is removed.
- `apps/api/src/repositories/__init__.py` — repository exports.
- `apps/api/src/repositories/base.py` — repository protocol and repository-data exception.
- `apps/api/src/repositories/mock.py` — strict JSON-backed repository.
- `apps/api/src/services/__init__.py` — service exports.
- `apps/api/src/services/packages.py` — filtering, sorting, pagination, visibility, detail, trust, and stats behavior.
- `apps/api/src/services/install.py` — manifest eligibility and construction.
- `apps/api/src/routers/packages.py` — package and version endpoints.
- `apps/api/src/routers/install.py` — install-manifest endpoint.
- `apps/api/src/routers/trust_scores.py` — canonical trust-score endpoint.
- `apps/api/src/routers/stats.py` — package-statistics endpoint.
- `apps/api/src/scripts/__init__.py` — script package marker.
- `apps/api/src/scripts/export_openapi.py` — deterministic Consumer OpenAPI exporter.
- `apps/api/tests/conftest.py` — isolated application/repository fixtures.
- `apps/api/tests/test_errors.py` — error-envelope tests.
- `apps/api/tests/test_repository.py` — strict repository tests.
- `apps/api/tests/test_packages_contract.py` — list/detail/version behavior tests.
- `apps/api/tests/test_install_contract.py` — install manifest tests.
- `apps/api/tests/test_trust_stats_contract.py` — trust and stats tests.
- `apps/api/tests/test_openapi_contract.py` — route/schema snapshot tests.
- `packages/schema/openapi/consumer-v0.1.json` — generated contract snapshot.

### Modify

- `apps/api/src/main.py` — wire canonical routers, dependencies, handlers, and health route.
- `packages/schema/mock/packages.json` — make latest-version relationships explicit and consistent.
- `packages/schema/mock/versions/code-review-skill-1.0.0.json` — add a valid install source, hash, steps, and client target.
- `packages/schema/mock/versions/risky-executor-0.1.0.json` — retain rejected visibility test data while normalizing record fields.
- `packages/schema/mock/README.md` — document canonical routes and explicit-version rule.
- `apps/api/pyproject.toml` — add strict pytest warning configuration.

### Remove after migration

- `apps/api/src/data.py`
- `apps/api/src/consumer_router.py`
- `apps/api/src/models/legacy.py`
- `apps/api/tests/test_consumer.py`

---

### Task 1: Establish the error contract and test application fixture

**Files:**
- Create: `apps/api/src/errors.py`
- Create: `apps/api/tests/conftest.py`
- Create: `apps/api/tests/test_errors.py`
- Modify: `apps/api/src/main.py`

- [ ] **Step 1: Write the failing error-envelope tests**

Create `apps/api/tests/test_errors.py`:

```python
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.errors import ConsumerAPIError, install_error_handlers


def test_consumer_error_uses_canonical_envelope() -> None:
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/boom")
    def boom() -> None:
        raise ConsumerAPIError(
            status_code=404,
            code="package_not_found",
            message="Package 'missing' was not found.",
        )

    response = TestClient(app).get("/boom")
    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "code": "package_not_found",
            "message": "Package 'missing' was not found.",
            "details": {},
        }
    }
```

- [ ] **Step 2: Run the test and confirm the module is missing**

Run: `python -m pytest tests/test_errors.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'src.errors'`.

- [ ] **Step 3: Implement the canonical error type and handler**

Create `apps/api/src/errors.py`:

```python
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


class ConsumerAPIError(Exception):
    def __init__(
        self,
        *,
        status_code: int,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details or {}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ConsumerAPIError)
    async def handle_consumer_error(
        request: Request, exc: ConsumerAPIError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "details": exc.details,
                }
            },
        )
```

Add `install_error_handlers(app)` immediately after constructing the FastAPI application in `apps/api/src/main.py`. Do not change router behavior yet.

- [ ] **Step 4: Run the focused and existing suites**

Run: `python -m pytest tests/test_errors.py tests/test_consumer.py -q`

Expected: the new test passes and all 18 existing Consumer tests still pass.

- [ ] **Step 5: Commit the error foundation**

```bash
git add apps/api/src/errors.py apps/api/src/main.py apps/api/tests/test_errors.py
git commit -m "feat(api): add canonical consumer error envelope"
```

---

### Task 2: Define canonical package, version, and pagination models

**Files:**
- Create: `apps/api/src/models/__init__.py`
- Create: `apps/api/src/models/common.py`
- Create: `apps/api/src/models/packages.py`
- Create: `apps/api/src/models/legacy.py`
- Remove: `apps/api/src/models.py`
- Test: `apps/api/tests/test_packages_contract.py`

- [ ] **Step 1: Write failing model-contract tests**

Create the initial `apps/api/tests/test_packages_contract.py`:

```python
from src.models.common import PackageListQuery, SortField, SortOrder
from src.models.packages import PackagePage


def test_package_query_defaults_are_public_and_canonical() -> None:
    query = PackageListQuery()
    assert query.status == "published"
    assert query.sort_by is SortField.TRUST_SCORE
    assert query.order is SortOrder.DESC
    assert query.page == 1
    assert query.page_size == 20


def test_empty_page_has_zero_total_pages() -> None:
    page = PackagePage(items=[], total=0, page=1, page_size=20, total_pages=0)
    assert page.model_dump()["total_pages"] == 0
```

- [ ] **Step 2: Run the tests and confirm the models package is missing**

Run: `python -m pytest tests/test_packages_contract.py -q`

Expected: FAIL during collection because `src.models.common` is not a package.

- [ ] **Step 3: Implement common query and pagination models**

Create `apps/api/src/models/common.py` with these exact public types:

```python
from enum import StrEnum
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field


class PackageType(StrEnum):
    SKILL = "skill"
    MCP_SERVER = "mcp_server"
    PLUGIN = "plugin"
    SUBAGENT = "subagent"
    COMMAND = "command"
    PROMPT = "prompt"


class SortField(StrEnum):
    TRUST_SCORE = "trust_score"
    UPDATED_AT = "updated_at"
    INSTALL_COUNT = "install_count"
    AVG_RATING = "avg_rating"
    NAME = "name"


class SortOrder(StrEnum):
    ASC = "asc"
    DESC = "desc"


class PackageListQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    q: str | None = None
    type: PackageType | None = None
    client: str | None = None
    category: str | None = None
    status: Literal["published"] = "published"
    sort_by: SortField = SortField.TRUST_SCORE
    order: SortOrder = SortOrder.DESC
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)


class Owner(BaseModel):
    id: str
    username: str
    display_name: str
    role: str


T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int
    total_pages: int


class HealthResponse(BaseModel):
    service: str
    version: str
    status: Literal["ok"] = "ok"


class ErrorBody(BaseModel):
    code: str
    message: str
    details: dict[str, object] = Field(default_factory=dict)


class ErrorEnvelope(BaseModel):
    error: ErrorBody
```

- [ ] **Step 4: Implement package and version models**

Create `apps/api/src/models/packages.py` by moving the reusable nested source, integrity, permission, dependency, installation, scan, and trust models from the old `src/models.py`, then define these canonical outer models:

```python
from pydantic import BaseModel, Field

from .common import Owner, PackageType, Page


class PackageSummary(BaseModel):
    id: str
    name: str
    description: str
    type: PackageType
    license: str | None = None
    keywords: list[str] = Field(default_factory=list)
    category: str | None = None
    homepage: str | None = None
    icon_url: str | None = None
    owner: Owner | None = None
    latest_version: str
    status: str
    trust_score: float | None = None
    risk_level: str | None = None
    install_count: int = 0
    avg_rating: float | None = None
    created_at: str | None = None
    updated_at: str | None = None


class VersionSummary(BaseModel):
    id: str
    version: str
    status: str
    submitted_at: str | None = None
    created_at: str | None = None
    trust_score: float | None = None


class VersionDetail(BaseModel):
    id: str
    package_id: str
    version: str
    status: str
    author: Author | None = None
    source: Source | None = None
    integrity: Integrity | None = None
    compatibility: list[str] = Field(default_factory=list)
    permissions: Permissions | None = None
    installation: Installation | None = None
    type_config: dict[str, object] | None = None
    dependencies: Dependencies | None = None
    entry_points: EntryPoints | None = None
    submitted_at: str | None = None
    published_at: str | None = None
    created_at: str | None = None
    trust_score: TrustScore | None = None
    scan_report: ScanReport | None = None


class PackageDetail(PackageSummary):
    latest_version_detail: VersionSummary


class PackagePage(Page[PackageSummary]):
    pass


class PackageStats(BaseModel):
    package_name: str
    install_count: int
    avg_rating: float | None
    total_versions: int
    latest_version: str
    status: str
```

The nested classes copied from `src/models.py` must retain their existing fields and use `model_config = ConfigDict(extra="allow")` only where mock version documents contain extension fields. Add `download_url: str | None` to `Source`, `download_size_bytes: int | None` to `Integrity`, and structured `steps`/`target_client` fields to `Installation` so Task 6 can construct a strict manifest.

Because Python cannot safely evolve a `models.py` module and a `models/` package independently, copy the four old-router-only outer response types (`PackageDetail`, `InstallManifest`, `TrustScoreResponse`, `PaginatedResponse`) into `models/legacy.py`, remove `src/models.py` in the same change, and make `models/__init__.py` export the names expected by the current `consumer_router.py`:

```python
from .legacy import InstallManifest, PackageDetail, PaginatedResponse, TrustScoreResponse
from .packages import (
    PackageStats,
    PackageSummary,
    VersionDetail,
    VersionSummary,
)

__all__ = [
    "InstallManifest",
    "PackageDetail",
    "PackageStats",
    "PackageSummary",
    "PaginatedResponse",
    "TrustScoreResponse",
    "VersionDetail",
    "VersionSummary",
]
```

The new routers import canonical `PackageDetail` and `PackagePage` directly from `src.models.packages`, so the temporary legacy export cannot leak into the new contract.

- [ ] **Step 5: Run model tests**

Run: `python -m pytest tests/test_packages_contract.py tests/test_consumer.py -q`

Expected: the 2 new model tests and all 18 old-router regression tests pass after the module-to-package migration.

- [ ] **Step 6: Commit canonical models**

```bash
git add -A apps/api/src/models.py apps/api/src/models apps/api/tests/test_packages_contract.py
git commit -m "feat(api): define consumer contract models"
```

---

### Task 3: Add a strict repository protocol and JSON implementation

**Files:**
- Create: `apps/api/src/repositories/__init__.py`
- Create: `apps/api/src/repositories/base.py`
- Create: `apps/api/src/repositories/mock.py`
- Create: `apps/api/tests/test_repository.py`
- Modify: `packages/schema/mock/versions/*.json`

- [ ] **Step 1: Write repository tests that forbid synthetic versions**

Create `apps/api/tests/test_repository.py`:

```python
from pathlib import Path

import pytest

from src.repositories.base import RepositoryDataError
from src.repositories.mock import JsonPackageRepository


ROOT = Path(__file__).resolve().parents[3]
MOCK = ROOT / "packages" / "schema" / "mock"


def test_repository_loads_explicit_version() -> None:
    repo = JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")
    version = repo.get_version("code-review-skill", "1.0.0")
    assert version is not None
    assert version.id == "ver-001"


def test_repository_never_synthesizes_unknown_version() -> None:
    repo = JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")
    assert repo.get_version("code-review-skill", "9.9.9") is None


def test_invalid_latest_version_relationship_is_reported(tmp_path: Path) -> None:
    packages = tmp_path / "packages.json"
    versions = tmp_path / "versions"
    versions.mkdir()
    packages.write_text(
        '[{"id":"p1","name":"broken","description":"x",'
        '"type":"skill","latest_version":"1.0.0","status":"published"}]',
        encoding="utf-8",
    )
    with pytest.raises(RepositoryDataError, match="latest_version"):
        JsonPackageRepository(packages, versions)
```

- [ ] **Step 2: Run the repository tests and confirm failure**

Run: `python -m pytest tests/test_repository.py -q`

Expected: FAIL because `src.repositories` does not exist.

- [ ] **Step 3: Define repository contracts**

Create `apps/api/src/repositories/base.py`:

```python
from typing import Protocol, Sequence

from src.models.packages import PackageSummary, VersionDetail


class RepositoryDataError(RuntimeError):
    pass


class PackageRepository(Protocol):
    def list_packages(self) -> Sequence[PackageSummary]: ...
    def get_package(self, name: str) -> PackageSummary | None: ...
    def list_versions(self, name: str) -> Sequence[VersionDetail]: ...
    def get_version(self, name: str, version: str) -> VersionDetail | None: ...
    def get_version_by_id(self, version_id: str) -> VersionDetail | None: ...
```

- [ ] **Step 4: Implement strict JSON loading and indexing**

Create `apps/api/src/repositories/mock.py` with:

```python
import json
from pathlib import Path
from typing import Sequence

from pydantic import TypeAdapter, ValidationError

from src.models.packages import PackageSummary, VersionDetail
from .base import RepositoryDataError


class JsonPackageRepository:
    def __init__(self, packages_path: Path, versions_dir: Path) -> None:
        try:
            raw_packages = json.loads(packages_path.read_text(encoding="utf-8"))
            self._packages = TypeAdapter(list[PackageSummary]).validate_python(raw_packages)
            self._versions = [
                VersionDetail.model_validate(
                    json.loads(path.read_text(encoding="utf-8"))
                )
                for path in sorted(versions_dir.glob("*.json"))
            ]
        except (OSError, json.JSONDecodeError, ValidationError) as exc:
            raise RepositoryDataError(f"Invalid mock repository data: {exc}") from exc

        self._packages_by_name = {item.name: item for item in self._packages}
        self._versions_by_key: dict[tuple[str, str], VersionDetail] = {}
        self._versions_by_id = {item.id: item for item in self._versions}

        package_name_by_id = {item.id: item.name for item in self._packages}
        for version in self._versions:
            name = package_name_by_id.get(version.package_id)
            if name is None:
                raise RepositoryDataError(
                    f"Version {version.id} references unknown package {version.package_id}"
                )
            self._versions_by_key[(name, version.version)] = version

        for package in self._packages:
            if (package.name, package.latest_version) not in self._versions_by_key:
                raise RepositoryDataError(
                    f"Package {package.name} latest_version {package.latest_version} "
                    "has no explicit version record"
                )

    def list_packages(self) -> Sequence[PackageSummary]:
        return tuple(self._packages)

    def get_package(self, name: str) -> PackageSummary | None:
        return self._packages_by_name.get(name)

    def list_versions(self, name: str) -> Sequence[VersionDetail]:
        return tuple(v for (n, _), v in self._versions_by_key.items() if n == name)

    def get_version(self, name: str, version: str) -> VersionDetail | None:
        return self._versions_by_key.get((name, version))

    def get_version_by_id(self, version_id: str) -> VersionDetail | None:
        return self._versions_by_id.get(version_id)
```

- [ ] **Step 5: Add controlled repository-data error handling**

Append this failing case to `apps/api/tests/test_errors.py`:

```python
def test_repository_data_error_uses_controlled_500() -> None:
    app = FastAPI()
    install_error_handlers(app)

    @app.get("/broken-data")
    def broken_data() -> None:
        raise RepositoryDataError("latest_version relationship is invalid")

    response = TestClient(app, raise_server_exceptions=False).get("/broken-data")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "repository_data_invalid"
```

Update `install_error_handlers` after `RepositoryDataError` exists:

```python
@app.exception_handler(RepositoryDataError)
async def handle_repository_data_error(
    request: Request, exc: RepositoryDataError
) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "repository_data_invalid",
                "message": "The package repository contains invalid data.",
                "details": {"reason": str(exc)},
            }
        },
    )
```

Run: `python -m pytest tests/test_errors.py -q`

Expected: both error-envelope tests pass.

- [ ] **Step 6: Normalize explicit version fixtures**

Add one version JSON file for every package row that currently lacks one. Each file must include the package's exact `id`, `latest_version`, and `status`; use a unique `ver-00N` ID. Published rows receive `published_at`; pending/rejected rows retain their non-public status. Do not add install source/hash/steps except to `code-review-skill-1.0.0.json`, which Task 6 normalizes.

Use this minimal shape for non-installable records:

```json
{
  "id": "ver-002",
  "package_id": "pkg-002",
  "version": "2.1.0",
  "status": "published",
  "compatibility": ["claude-code"],
  "created_at": "2026-05-15T08:00:00Z",
  "published_at": "2026-06-15T08:00:00Z"
}
```

- [ ] **Step 7: Run repository tests**

Run: `python -m pytest tests/test_repository.py -q`

Expected: 3 tests pass and all mock packages have explicit versions.

- [ ] **Step 8: Commit repository isolation**

```bash
git add apps/api/src/errors.py apps/api/src/repositories apps/api/tests/test_errors.py apps/api/tests/test_repository.py packages/schema/mock/versions
git commit -m "feat(api): add strict mock package repository"
```

---

### Task 4: Implement published-only package query services

**Files:**
- Create: `apps/api/src/services/__init__.py`
- Create: `apps/api/src/services/packages.py`
- Modify: `apps/api/tests/test_packages_contract.py`

- [ ] **Step 1: Add failing service tests for visibility, sorting, and pagination**

Append tests using a small `FakeRepository` that implements `PackageRepository`:

```python
def test_list_excludes_non_public_packages(fake_repository) -> None:
    page = PackageService(fake_repository).list_packages(PackageListQuery())
    assert {item.status for item in page.items} == {"published"}


def test_null_trust_scores_are_last_in_both_orders(fake_repository) -> None:
    ascending = PackageService(fake_repository).list_packages(
        PackageListQuery(sort_by="trust_score", order="asc")
    )
    descending = PackageService(fake_repository).list_packages(
        PackageListQuery(sort_by="trust_score", order="desc")
    )
    assert ascending.items[-1].trust_score is None
    assert descending.items[-1].trust_score is None


def test_unknown_version_is_not_synthesized(fake_repository) -> None:
    with pytest.raises(ConsumerAPIError) as caught:
        PackageService(fake_repository).get_version("published-one", "9.9.9")
    assert caught.value.status_code == 404
    assert caught.value.code == "version_not_found"
```

- [ ] **Step 2: Run focused tests and confirm service import failure**

Run: `python -m pytest tests/test_packages_contract.py -q`

Expected: FAIL because `PackageService` does not exist.

- [ ] **Step 3: Implement strict filtering and null-last stable sorting**

Create `apps/api/src/services/packages.py`. The list method must use this sequence:

```python
class PackageService:
    def __init__(self, repository: PackageRepository) -> None:
        self.repository = repository

    def list_packages(self, query: PackageListQuery) -> PackagePage:
        items = [p for p in self.repository.list_packages() if p.status == "published"]

        if query.q:
            needle = query.q.casefold()
            items = [
                p for p in items
                if needle in p.name.casefold()
                or needle in p.description.casefold()
                or any(needle in keyword.casefold() for keyword in p.keywords)
            ]
        if query.type:
            items = [p for p in items if p.type == query.type]
        if query.category:
            items = [p for p in items if p.category == query.category]
        if query.client:
            items = [p for p in items if self._supports_client(p, query.client)]

        items = self._sort(items, query.sort_by, query.order)
        total = len(items)
        start = (query.page - 1) * query.page_size
        page_items = items[start : start + query.page_size]
        total_pages = math.ceil(total / query.page_size) if total else 0
        return PackagePage(
            items=page_items,
            total=total,
            page=query.page,
            page_size=query.page_size,
            total_pages=total_pages,
        )
```

Implement `_supports_client` and `_sort` exactly as follows so nulls stay last in both directions and equal primary values retain name ordering:

```python
def _supports_client(self, package: PackageSummary, client: str) -> bool:
    return any(
        version.status == "published" and client in version.compatibility
        for version in self.repository.list_versions(package.name)
    )


def _sort(
    self,
    items: list[PackageSummary],
    field: SortField,
    order: SortOrder,
) -> list[PackageSummary]:
    items = sorted(items, key=lambda item: item.name.casefold())

    def raw_value(item: PackageSummary):
        if field is SortField.NAME:
            return item.name.casefold()
        if field is SortField.UPDATED_AT:
            return (
                datetime.fromisoformat(item.updated_at.replace("Z", "+00:00"))
                if item.updated_at is not None
                else None
            )
        return getattr(item, field.value)

    present = [item for item in items if raw_value(item) is not None]
    missing = [item for item in items if raw_value(item) is None]
    present.sort(key=raw_value, reverse=order is SortOrder.DESC)
    return present + missing
```

- [ ] **Step 4: Implement strict detail/version/trust/stats methods**

Add methods with these failure mappings:

```python
def get_public_package(self, name: str) -> PackageSummary:
    package = self.repository.get_package(name)
    if package is None or package.status != "published":
        raise ConsumerAPIError(
            status_code=404,
            code="package_not_found",
            message=f"Package '{name}' was not found.",
        )
    return package


def get_public_version(self, name: str, version: str) -> VersionDetail:
    self.get_public_package(name)
    record = self.repository.get_version(name, version)
    if record is None or record.status != "published":
        raise ConsumerAPIError(
            status_code=404,
            code="version_not_found",
            message=f"Version '{name}@{version}' was not found.",
        )
    return record
```

Implement the remaining methods with these exact result mappings:

```python
def get_package_detail(self, name: str) -> PackageDetail:
    package = self.get_public_package(name)
    version = self.repository.get_version(name, package.latest_version)
    if version is None or version.status != "published":
        raise RepositoryDataError(
            f"Package {name} has invalid latest_version {package.latest_version}"
        )
    summary = VersionSummary(
        id=version.id,
        version=version.version,
        status=version.status,
        submitted_at=version.submitted_at,
        created_at=version.created_at,
        trust_score=version.trust_score.score if version.trust_score else None,
    )
    return PackageDetail(**package.model_dump(), latest_version_detail=summary)


def list_public_versions(self, name: str) -> list[VersionSummary]:
    self.get_public_package(name)
    return [
        VersionSummary(
            id=v.id,
            version=v.version,
            status=v.status,
            submitted_at=v.submitted_at,
            created_at=v.created_at,
            trust_score=v.trust_score.score if v.trust_score else None,
        )
        for v in self.repository.list_versions(name)
        if v.status == "published"
    ]


def get_public_version_by_id(self, version_id: str) -> VersionDetail:
    version = self.repository.get_version_by_id(version_id)
    if version is None or version.status != "published":
        raise ConsumerAPIError(
            status_code=404,
            code="version_not_found",
            message=f"Version '{version_id}' was not found.",
        )
    package = next(
        (p for p in self.repository.list_packages() if p.id == version.package_id),
        None,
    )
    if package is None or package.status != "published":
        raise ConsumerAPIError(
            status_code=404,
            code="version_not_found",
            message=f"Version '{version_id}' was not found.",
        )
    return version


def get_trust_score(self, version_id: str) -> TrustScore:
    version = self.get_public_version_by_id(version_id)
    if version.trust_score is None:
        raise ConsumerAPIError(
            status_code=404,
            code="trust_score_not_found",
            message=f"Trust score for version '{version_id}' was not found.",
        )
    return version.trust_score


def get_stats(self, name: str) -> PackageStats:
    package = self.get_public_package(name)
    versions = [
        v for v in self.repository.list_versions(name) if v.status == "published"
    ]
    return PackageStats(
        package_name=package.name,
        install_count=package.install_count,
        avg_rating=package.avg_rating,
        total_versions=len(versions),
        latest_version=package.latest_version,
        status=package.status,
    )
```

- [ ] **Step 5: Run service tests**

Run: `python -m pytest tests/test_packages_contract.py -q`

Expected: all model and service tests pass, including null-last ordering.

- [ ] **Step 6: Commit query services**

```bash
git add apps/api/src/services apps/api/tests/test_packages_contract.py
git commit -m "feat(api): enforce public package query semantics"
```

---

### Task 5: Expose canonical package and version routes

**Files:**
- Create: `apps/api/src/dependencies.py`
- Create: `apps/api/src/routers/packages.py`
- Create: `apps/api/tests/conftest.py`
- Modify: `apps/api/tests/test_packages_contract.py`
- Modify: `apps/api/src/main.py`

- [ ] **Step 1: Add failing HTTP contract tests**

Add tests using a `client` fixture:

```python
def test_list_uses_canonical_query_names(client) -> None:
    response = client.get(
        "/api/v0/packages",
        params={"sort_by": "name", "order": "asc", "page_size": 2},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["page_size"] == 2
    assert [item["name"] for item in body["items"]] == sorted(
        item["name"] for item in body["items"]
    )


def test_legacy_or_unknown_query_is_rejected(client) -> None:
    assert client.get("/api/v0/packages", params={"sort": "name"}).status_code == 422


def test_rejected_package_is_not_public(client) -> None:
    response = client.get("/api/v0/packages/risky-executor")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "package_not_found"


def test_unknown_version_returns_404(client) -> None:
    response = client.get(
        "/api/v0/packages/code-review-skill/versions/9.9.9"
    )
    assert response.status_code == 404
```

- [ ] **Step 2: Run HTTP tests and confirm canonical routes fail**

Run: `python -m pytest tests/test_packages_contract.py -q`

Expected: route tests fail because old parameter names and visibility behavior are still registered.

- [ ] **Step 3: Add repository dependency injection**

Create `apps/api/src/dependencies.py`:

```python
from functools import lru_cache
from pathlib import Path

from src.repositories.base import PackageRepository
from src.repositories.mock import JsonPackageRepository


ROOT = Path(__file__).resolve().parents[3]
MOCK = ROOT / "packages" / "schema" / "mock"


@lru_cache(maxsize=1)
def get_package_repository() -> PackageRepository:
    return JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")


RepositoryDependency = Annotated[
    PackageRepository, Depends(get_package_repository)
]
```

Use these fixtures in `apps/api/tests/conftest.py`:

```python
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.dependencies import get_package_repository
from src.main import create_app
from src.repositories.mock import JsonPackageRepository


ROOT = Path(__file__).resolve().parents[3]
MOCK = ROOT / "packages" / "schema" / "mock"


@pytest.fixture
def repository() -> JsonPackageRepository:
    return JsonPackageRepository(MOCK / "packages.json", MOCK / "versions")


@pytest.fixture
def client(repository: JsonPackageRepository) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_package_repository] = lambda: repository
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
```

- [ ] **Step 4: Implement the package router**

Create `apps/api/src/routers/packages.py` with:

```python
from typing import Annotated

from fastapi import APIRouter, Depends, Query

from src.dependencies import RepositoryDependency
from src.models.common import ErrorEnvelope, PackageListQuery
from src.models.packages import PackageDetail, PackagePage, VersionDetail, VersionSummary
from src.repositories.base import PackageRepository
from src.services.packages import PackageService


router = APIRouter(tags=["packages"])


@router.get("/packages", response_model=PackagePage)
def list_packages(
    query: Annotated[PackageListQuery, Query()],
    repository: RepositoryDependency,
) -> PackagePage:
    return PackageService(repository).list_packages(query)


@router.get(
    "/packages/{name}",
    response_model=PackageDetail,
    responses={404: {"model": ErrorEnvelope}},
)
def get_package(name: str, repository: RepositoryDependency) -> PackageDetail:
    return PackageService(repository).get_package_detail(name)


@router.get(
    "/packages/{name}/versions",
    response_model=list[VersionSummary],
    responses={404: {"model": ErrorEnvelope}},
)
def list_versions(name: str, repository: RepositoryDependency) -> list[VersionSummary]:
    return PackageService(repository).list_public_versions(name)


@router.get(
    "/packages/{name}/versions/{version}",
    response_model=VersionDetail,
    responses={404: {"model": ErrorEnvelope}},
)
def get_version(name: str, version: str, repository: RepositoryDependency) -> VersionDetail:
    return PackageService(repository).get_public_version(name, version)
```

- [ ] **Step 5: Introduce an application factory and replace the old router**

Refactor `apps/api/src/main.py` to expose `create_app() -> FastAPI`, install error handlers, include the existing scan router unchanged, include the new package router at `/api/v0`, and add:

```python
@app.get("/api/v0/health", response_model=HealthResponse, tags=["health"])
def health() -> HealthResponse:
    return HealthResponse(service="Trusted Agent Hub API", version="0.1.0")
```

Keep `app = create_app()` at module scope for Uvicorn.

- [ ] **Step 6: Run package HTTP tests**

Run: `python -m pytest tests/test_packages_contract.py -q`

Expected: all package list/detail/version HTTP tests pass; `sort=...` returns 422 and rejected packages return 404.

- [ ] **Step 7: Commit canonical package routes**

```bash
git add apps/api/src/dependencies.py apps/api/src/main.py apps/api/src/routers/packages.py apps/api/tests/conftest.py apps/api/tests/test_packages_contract.py
git commit -m "feat(api): expose canonical public package routes"
```

---

### Task 6: Build the strict Install Manifest v1.0 endpoint

**Files:**
- Create: `apps/api/src/models/install.py`
- Create: `apps/api/src/services/install.py`
- Create: `apps/api/src/routers/install.py`
- Create: `apps/api/tests/test_install_contract.py`
- Modify: `packages/schema/mock/versions/code-review-skill-1.0.0.json`
- Modify: `apps/api/src/main.py`

- [ ] **Step 1: Write failing manifest contract tests**

Create `apps/api/tests/test_install_contract.py`:

```python
def test_valid_manifest_contains_security_and_install_fields(client) -> None:
    response = client.get(
        "/api/v0/packages/code-review-skill/install-manifest",
        params={"client": "claude-code"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["manifest_version"] == "1.0"
    assert body["name"] == "code-review-skill"
    assert len(body["integrity"]["sha256"]) == 64
    assert body["installation"]["target_client"] == "claude-code"
    assert body["installation"]["steps"]
    assert isinstance(body["trust_score"], int)


def test_manifest_requires_client(client) -> None:
    response = client.get(
        "/api/v0/packages/code-review-skill/install-manifest"
    )
    assert response.status_code == 422


def test_rejected_package_has_no_manifest(client) -> None:
    response = client.get(
        "/api/v0/packages/risky-executor/install-manifest",
        params={"client": "claude-code"},
    )
    assert response.status_code == 404


def test_unsupported_client_returns_409(client) -> None:
    response = client.get(
        "/api/v0/packages/code-review-skill/install-manifest",
        params={"client": "unknown-client"},
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "install_manifest_unavailable"
```

- [ ] **Step 2: Run tests and confirm the endpoint is absent**

Run: `python -m pytest tests/test_install_contract.py -q`

Expected: success-case requests return 404 because the new route is not registered.

- [ ] **Step 3: Define strict manifest models**

Create `apps/api/src/models/install.py` with `Literal["1.0"]`, `HttpUrl` download/repository URLs, a lowercase-hex SHA256 field constrained by `pattern=r"^[a-f0-9]{64}$"`, supported method/action enums, non-empty `steps`, integer trust score 0-100, the existing permission/dependency models, and:

```python
class InstallManifest(BaseModel):
    manifest_version: Literal["1.0"] = "1.0"
    name: str
    version: str
    type: PackageType
    description: str
    source: ManifestSource
    integrity: ManifestIntegrity
    installation: ManifestInstallation
    permissions: Permissions
    risk_summary: RiskSummary
    trust_score: int = Field(ge=0, le=100)
    compatibility: list[str]
    dependencies: Dependencies
```

- [ ] **Step 4: Normalize the installable mock version**

Update `code-review-skill-1.0.0.json` with explicit values:

```json
"download_url": "https://github.com/alice-dev/code-review-skill/archive/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0.zip"
```

Keep the existing 64-character SHA256 and add `download_size_bytes`. Replace/extend installation data with `target_client: "claude-code"` and non-empty steps for download, verify, extract, and copy. Preserve existing targets temporarily only if scanner/legacy code still reads them.

- [ ] **Step 5: Implement eligibility collection and manifest construction**

Create `apps/api/src/services/install.py`. `get_manifest(name, version, client)` first calls `PackageService.get_public_package` and `get_public_version`, then collects exact invalid fields:

```python
missing: list[str] = []
if source is None or source.download_url is None:
    missing.append("source.download_url")
if integrity is None or not re.fullmatch(r"[a-f0-9]{64}", integrity.sha256):
    missing.append("integrity.sha256")
if client not in record.compatibility:
    missing.append("compatibility")
if installation is None or not installation.steps:
    missing.append("installation.steps")
elif installation.target_client != client:
    missing.append("installation.target_client")
elif installation.method not in {
    "copy_directory", "npm_install", "pip_install", "docker_run", "manual_steps"
}:
    missing.append("installation.method")
if record.permissions is None:
    missing.append("permissions")
if record.trust_score is None or record.trust_score.risk_summary is None:
    missing.append("trust_score")
elif record.trust_score.risk_summary.install_recommendation == "blocked":
    missing.append("risk_summary.install_recommendation")

if missing:
    raise ConsumerAPIError(
        status_code=409,
        code="install_manifest_unavailable",
        message=f"Package '{name}@{record.version}' is not safely installable.",
        details={"invalid_fields": missing},
    )
```

Construct `InstallManifest` only after this check. Convert the score to `round(record.trust_score.score)`, use the validated client-specific steps, and map absent dependencies to an empty `Dependencies()` model rather than omitting the required manifest object.

- [ ] **Step 6: Implement and register the route**

Create `apps/api/src/routers/install.py` using a semantic-version regex query and required `client` query. Declare `ErrorEnvelope` response models for 404 and 409 in the route decorator so these errors appear in OpenAPI. Register it in `create_app()` at `/api/v0`. Remove registration of the old `/packages/{name}/install` route by not including `consumer_router`.

- [ ] **Step 7: Run manifest tests**

Run: `python -m pytest tests/test_install_contract.py -q`

Expected: all success, 404, 409, and 422 cases pass.

- [ ] **Step 8: Commit install contract**

```bash
git add apps/api/src/models/install.py apps/api/src/services/install.py apps/api/src/routers/install.py apps/api/src/main.py apps/api/tests/test_install_contract.py packages/schema/mock/versions/code-review-skill-1.0.0.json
git commit -m "feat(api): add safe install manifest contract"
```

---

### Task 7: Add canonical trust-score and statistics endpoints

**Files:**
- Create: `apps/api/src/routers/trust_scores.py`
- Create: `apps/api/src/routers/stats.py`
- Create: `apps/api/tests/test_trust_stats_contract.py`
- Modify: `apps/api/src/main.py`

- [ ] **Step 1: Write failing trust and stats tests**

Create `apps/api/tests/test_trust_stats_contract.py`:

```python
def test_trust_score_uses_version_route(client) -> None:
    response = client.get("/api/v0/versions/ver-001/trust-score")
    assert response.status_code == 200
    assert response.json()["score"] == 92


def test_unknown_trust_score_returns_404(client) -> None:
    response = client.get("/api/v0/versions/not-real/trust-score")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "trust_score_not_found"


def test_legacy_trust_route_is_removed(client) -> None:
    assert client.get("/api/v0/trust-scores/ver-001").status_code == 404


def test_stats_count_explicit_published_versions(client) -> None:
    response = client.get("/api/v0/stats/packages/code-review-skill")
    assert response.status_code == 200
    assert response.json()["total_versions"] == 1
```

- [ ] **Step 2: Run tests and confirm route mismatch**

Run: `python -m pytest tests/test_trust_stats_contract.py -q`

Expected: canonical trust route fails because the old route is still active or no route is registered.

- [ ] **Step 3: Implement focused routers**

Both routers inject `PackageRepository`, instantiate `PackageService`, and return existing `TrustScore`/`PackageStats` models:

```python
@router.get("/versions/{version_id}/trust-score", response_model=TrustScore)
def get_trust_score(version_id: str, repository: RepositoryDependency) -> TrustScore:
    return PackageService(repository).get_trust_score(version_id)


@router.get("/stats/packages/{name}", response_model=PackageStats)
def get_package_stats(name: str, repository: RepositoryDependency) -> PackageStats:
    return PackageService(repository).get_stats(name)
```

Reuse the `RepositoryDependency` alias created in Task 5. Declare `ErrorEnvelope` as the 404 response model on both route decorators so not-found behavior is represented in OpenAPI.

- [ ] **Step 4: Register routers and run tests**

Run: `python -m pytest tests/test_trust_stats_contract.py -q`

Expected: all trust and stats tests pass; unknown scores no longer return synthetic zero objects.

- [ ] **Step 5: Commit trust and stats routes**

```bash
git add apps/api/src/dependencies.py apps/api/src/routers/trust_scores.py apps/api/src/routers/stats.py apps/api/src/main.py apps/api/tests/test_trust_stats_contract.py
git commit -m "feat(api): canonicalize trust and stats routes"
```

---

### Task 8: Export and lock the Consumer OpenAPI contract

**Files:**
- Create: `apps/api/src/scripts/__init__.py`
- Create: `apps/api/src/scripts/export_openapi.py`
- Create: `apps/api/tests/test_openapi_contract.py`
- Create: `packages/schema/openapi/consumer-v0.1.json`

- [ ] **Step 1: Write failing route and snapshot tests**

Create `apps/api/tests/test_openapi_contract.py`:

```python
import json
from pathlib import Path

from src.main import create_app
from src.scripts.export_openapi import build_consumer_openapi


EXPECTED_PATHS = {
    "/api/v0/health",
    "/api/v0/packages",
    "/api/v0/packages/{name}",
    "/api/v0/packages/{name}/versions",
    "/api/v0/packages/{name}/versions/{version}",
    "/api/v0/packages/{name}/install-manifest",
    "/api/v0/versions/{version_id}/trust-score",
    "/api/v0/stats/packages/{name}",
}


def test_consumer_openapi_has_only_canonical_paths() -> None:
    contract = build_consumer_openapi(create_app())
    assert set(contract["paths"]) == EXPECTED_PATHS
    assert "/api/v0/packages/{name}/install" not in contract["paths"]
    assert "/api/v0/trust-scores/{version_id}" not in contract["paths"]


def test_openapi_snapshot_is_current() -> None:
    root = Path(__file__).resolve().parents[3]
    snapshot = json.loads(
        (root / "packages/schema/openapi/consumer-v0.1.json").read_text("utf-8")
    )
    assert build_consumer_openapi(create_app()) == snapshot
```

- [ ] **Step 2: Run tests and confirm exporter is absent**

Run: `python -m pytest tests/test_openapi_contract.py -q`

Expected: FAIL because `src.scripts.export_openapi` does not exist.

- [ ] **Step 3: Implement deterministic path and schema extraction**

Create `apps/api/src/scripts/export_openapi.py` with:

```python
import json
from collections import deque
from pathlib import Path
from typing import Any

from fastapi import FastAPI


CONSUMER_PATHS = {
    "/api/v0/health",
    "/api/v0/packages",
    "/api/v0/packages/{name}",
    "/api/v0/packages/{name}/versions",
    "/api/v0/packages/{name}/versions/{version}",
    "/api/v0/packages/{name}/install-manifest",
    "/api/v0/versions/{version_id}/trust-score",
    "/api/v0/stats/packages/{name}",
}


def _schema_refs(value: Any) -> set[str]:
    refs: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref" and isinstance(child, str) and child.startswith("#/components/schemas/"):
                refs.add(child.rsplit("/", 1)[-1])
            else:
                refs.update(_schema_refs(child))
    elif isinstance(value, list):
        for child in value:
            refs.update(_schema_refs(child))
    return refs


def build_consumer_openapi(app: FastAPI) -> dict[str, Any]:
    source = app.openapi()
    paths = {path: source["paths"][path] for path in sorted(CONSUMER_PATHS)}
    all_schemas = source.get("components", {}).get("schemas", {})
    queue = deque(sorted(_schema_refs(paths)))
    selected: dict[str, Any] = {}
    while queue:
        name = queue.popleft()
        if name in selected:
            continue
        selected[name] = all_schemas[name]
        queue.extend(sorted(_schema_refs(all_schemas[name]) - selected.keys()))
    return {
        "openapi": source["openapi"],
        "info": source["info"],
        "paths": paths,
        "components": {"schemas": {name: selected[name] for name in sorted(selected)}},
    }


def write_snapshot(destination: Path) -> None:
    from src.main import create_app

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(build_consumer_openapi(create_app()), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[4]
    write_snapshot(root / "packages/schema/openapi/consumer-v0.1.json")
```

- [ ] **Step 4: Export the snapshot and run contract tests**

Run: `python -m src.scripts.export_openapi`

Run: `python -m pytest tests/test_openapi_contract.py -q`

Expected: 2 tests pass and the committed JSON contains exactly eight Consumer paths.

- [ ] **Step 5: Commit contract snapshot**

```bash
git add apps/api/src/scripts apps/api/tests/test_openapi_contract.py packages/schema/openapi/consumer-v0.1.json
git commit -m "docs(api): lock consumer OpenAPI contract"
```

---

### Task 9: Remove legacy mock routing and update repository documentation

**Files:**
- Remove: `apps/api/src/data.py`
- Remove: `apps/api/src/consumer_router.py`
- Remove: `apps/api/src/models/legacy.py`
- Remove: `apps/api/tests/test_consumer.py`
- Modify: `packages/schema/mock/README.md`
- Modify: `apps/api/pyproject.toml`

- [ ] **Step 1: Add regression assertions for removed legacy behavior**

Append to the contract tests:

```python
def test_removed_legacy_routes_return_404(client) -> None:
    assert client.get("/api/v0/packages/code-review-skill/install").status_code == 404
    assert client.get("/api/v0/trust-scores/ver-001").status_code == 404


def test_old_query_names_return_422(client) -> None:
    response = client.get("/api/v0/packages", params={"sort": "name", "limit": 2})
    assert response.status_code == 422
```

- [ ] **Step 2: Remove old modules and imports**

Delete the four legacy files listed above. Update `models/__init__.py` to export canonical models from `common.py`, `packages.py`, and `install.py`. Use `rg` to confirm there are no remaining imports of `src.data`, `src.consumer_router`, or `src.models.legacy`:

Run: `rg -n "consumer_router|from \.?src import data|models\.legacy" apps/api`

Expected: no legacy application import remains; imports from the new `src.models` package are allowed.

- [ ] **Step 3: Make Pydantic deprecations fail tests**

Add to `apps/api/pyproject.toml`:

```toml
[tool.pytest.ini_options]
filterwarnings = [
  "error::pydantic.warnings.PydanticDeprecatedSince20",
]
```

This turns any new `__fields__`-style usage into a test failure.

- [ ] **Step 4: Update mock-data documentation**

Replace references to the old paths and synthetic fallback with:

```markdown
## Consumer API contract

- Public package routes expose only explicit `published` package/version records.
- Every package row must have a matching explicit version JSON document.
- Install manifests are available at `/api/v0/packages/{name}/install-manifest?client=...`.
- The generated contract is `packages/schema/openapi/consumer-v0.1.json`.
- JSON files are development fixtures; persistence is implemented by a later repository backend.
```

- [ ] **Step 5: Run the entire API suite with warnings as errors**

Run: `python -m pytest -q`

Expected: all API tests pass with no Pydantic deprecation warning summary.

- [ ] **Step 6: Commit legacy removal**

```bash
git add -A apps/api packages/schema/mock/README.md
git commit -m "refactor(api): remove legacy consumer mock router"
```

---

### Task 10: Final contract verification and branch handoff

**Files:**
- Modify if required by verification: `packages/schema/openapi/consumer-v0.1.json`
- Modify if required by verification: tests directly identifying the mismatch

- [ ] **Step 1: Run focused contract tests**

Run:

```bash
cd apps/api
python -m pytest tests/test_packages_contract.py tests/test_install_contract.py tests/test_trust_stats_contract.py tests/test_openapi_contract.py -q
```

Expected: all contract tests pass.

- [ ] **Step 2: Run the full API suite**

Run: `python -m pytest -q`

Expected: exit code 0, no failures, and no Pydantic deprecation warnings.

- [ ] **Step 3: Exercise the critical public boundaries**

Run from `apps/api`:

```powershell
@'
from fastapi.testclient import TestClient
from src.main import create_app

c = TestClient(create_app(), raise_server_exceptions=False)
checks = {
    "published_list": c.get("/api/v0/packages").status_code,
    "null_sort": c.get("/api/v0/packages?sort_by=trust_score").status_code,
    "unknown_version": c.get("/api/v0/packages/code-review-skill/versions/9.9.9").status_code,
    "rejected_package": c.get("/api/v0/packages/risky-executor").status_code,
    "rejected_install": c.get("/api/v0/packages/risky-executor/install-manifest?client=claude-code").status_code,
    "valid_manifest": c.get("/api/v0/packages/code-review-skill/install-manifest?client=claude-code").status_code,
}
print(checks)
assert checks == {
    "published_list": 200,
    "null_sort": 200,
    "unknown_version": 404,
    "rejected_package": 404,
    "rejected_install": 404,
    "valid_manifest": 200,
}
'@ | python -
```

Expected: the printed mapping exactly matches the asserted values.

- [ ] **Step 4: Regenerate OpenAPI and verify no diff**

Run:

```bash
python -m src.scripts.export_openapi
git diff --exit-code -- packages/schema/openapi/consumer-v0.1.json
```

Expected: no diff.

- [ ] **Step 5: Verify repository scope and cleanliness**

Run:

```bash
git status --short
git diff main...HEAD --stat
```

Expected: no uncommitted implementation files. Diff contains only Consumer contract/API/test/mock/schema work plus the approved design and plan documents; no Web, CLI, scanner, trust-algorithm, database, or external-docs changes.

- [ ] **Step 6: Create the final verification commit only if verification changed files**

If Step 4 or a directly failing test required a correction, commit only those verified corrections:

```bash
git add apps/api packages/schema/openapi/consumer-v0.1.json packages/schema/mock docs/superpowers
git commit -m "test(api): verify consumer contract boundaries"
```

If verification produced no changes, do not create an empty commit.

---

## Completion checklist

- [ ] Eight canonical Consumer paths exist.
- [ ] Legacy install/trust paths are absent.
- [ ] Public routes expose only published records.
- [ ] Unknown package/version/score responses are 404.
- [ ] Null sort values never cause 500 and are always last.
- [ ] Unknown query parameters return 422.
- [ ] Install Manifest v1.0 is complete and client-specific.
- [ ] Rejected/blocked packages cannot obtain a manifest.
- [ ] Repository methods never synthesize records.
- [ ] Generated OpenAPI equals the committed snapshot.
- [ ] Full API suite passes without Pydantic deprecation warnings.
- [ ] No database, Web, CLI, scanner, or scoring-algorithm scope leaked into the branch.
