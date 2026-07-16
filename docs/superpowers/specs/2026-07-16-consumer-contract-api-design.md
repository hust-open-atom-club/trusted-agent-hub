# Consumer Contract API Design

## 1. Goal

The `consumer-contract-api` branch establishes one stable, public Consumer API contract for Web and CLI clients. It replaces the current mock-oriented route behavior with strict read semantics, a schema-compliant install manifest, explicit repository boundaries, and contract-focused tests.

This branch does not add a database, authentication, Web integration, CLI installation, or trust-algorithm changes. Its output is a reliable API surface that those later branches can depend on without changing paths or response shapes.

## 2. Success criteria

The branch is complete when all of the following are true:

1. FastAPI/Pydantic models are the runtime source of truth for Consumer v0.1.
2. The generated Consumer OpenAPI document is committed and checked by tests.
3. Public package endpoints expose only `published` packages and versions.
4. Unknown or non-public resources never receive synthetic success responses.
5. The package list supports the documented filters, ordering, and pagination without server errors.
6. Install manifests conform to the v1.0 install-manifest contract and are returned only when installation can be performed safely.
7. Consumer routes depend on a repository interface rather than module-level JSON dictionaries.
8. Existing Consumer tests are replaced or extended with contract and boundary tests.
9. Consumer API tests pass without Pydantic deprecation warnings.

## 3. Scope

### 3.1 Included

- Canonical public Consumer v0.1 routes.
- Canonical query parameters, response models, and error payloads.
- Published-only visibility rules.
- Correct filtering, sorting, pagination, and not-found behavior.
- Install Manifest v1.0 response model and validation.
- A read-only repository protocol and JSON-backed mock implementation.
- FastAPI dependency injection for repositories.
- Generated OpenAPI snapshot and export script.
- API unit, behavior, schema, and OpenAPI contract tests.
- Migration of Pydantic v1-style field introspection to Pydantic v2 APIs.

### 3.2 Excluded

- PostgreSQL, SQLAlchemy, Alembic, or other persistent storage.
- Registration, login, JWT, or RBAC.
- Installation-event writes, ratings, comments, and feedback writes.
- Trust scoring algorithm changes or scanner tuning.
- Web data fetching or UI changes.
- CLI downloading, installation, publishing, or npm packaging.
- Rebuilding example packages.
- Producer submission, review, publish, or yank endpoints.

These excluded areas will use separate branches after the read contract is stable.

## 4. Chosen approach

The implementation is contract-first at the API boundary and code-first at runtime:

- Pydantic request/response models and FastAPI route declarations define runtime behavior.
- FastAPI generates the OpenAPI document from those declarations.
- A deterministic export script writes the generated Consumer contract to the shared schema package.
- A contract test fails if runtime OpenAPI and the committed snapshot diverge.
- Route handlers obtain data through repository protocols, allowing the JSON mock repository to be replaced by PostgreSQL without changing route code.

An external hand-maintained OpenAPI file will not be a second source of truth. The separate documentation repository can import or copy the generated snapshot after this branch is merged.

## 5. Canonical public routes

All routes use the `/api/v0` prefix.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Service health and API version |
| GET | `/packages` | Search and browse public packages |
| GET | `/packages/{name}` | Read public package detail and latest-version summary |
| GET | `/packages/{name}/versions` | List public versions |
| GET | `/packages/{name}/versions/{version}` | Read one public version |
| GET | `/packages/{name}/install-manifest` | Obtain an installable manifest |
| GET | `/versions/{version_id}/trust-score` | Read the persisted/mock trust result for a public version |
| GET | `/stats/packages/{name}` | Read public package statistics |

The old `/packages/{name}/install` and `/trust-scores/{version_id}` routes are removed rather than maintained as aliases. No production Web or CLI client currently depends on them, so carrying aliases would preserve contract ambiguity.

## 6. Package list contract

### 6.1 Query parameters

| Parameter | Type | Default | Rules |
|---|---|---|---|
| `q` | string or null | null | Case-insensitive match against name, description, and keywords |
| `type` | package-type enum or null | null | One of the six shared package types |
| `client` | client enum/string or null | null | Version compatibility must explicitly contain the client |
| `category` | string or null | null | Exact category match |
| `status` | literal `published` | `published` | Public v0.1 accepts no other status |
| `sort_by` | enum | `trust_score` | `trust_score`, `updated_at`, `install_count`, `avg_rating`, or `name` |
| `order` | enum | `desc` | `asc` or `desc` |
| `page` | integer | 1 | Minimum 1 |
| `page_size` | integer | 20 | Minimum 1, maximum 100 |

Unknown query parameters return 422. The query model uses Pydantic `extra="forbid"` so legacy or misspelled parameters such as `sort` and `limit` cannot be silently ignored. Invalid values for declared enum/range parameters also return 422.

### 6.2 Visibility

The repository may contain non-public data, but public routes always apply `status == published`. The `status` parameter exists only to make that rule explicit in the contract. Requests with another status fail validation.

Client filtering is strict: packages without an explicit compatible version do not match. There is no optimistic fallback.

### 6.3 Sorting

- `name` sorts case-insensitively.
- Date values sort by parsed timestamp rather than raw presentation text.
- Numeric values sort numerically.
- Null values always appear last for both ascending and descending order.
- Sorting is stable, with normalized package name as a deterministic tie-breaker.

### 6.4 Response

```json
{
  "items": [],
  "total": 0,
  "page": 1,
  "page_size": 20,
  "total_pages": 0
}
```

`total` is the count after filtering and before pagination. `total_pages` is zero when `total` is zero.

## 7. Package and version behavior

- Package detail returns package metadata plus a summary of the latest explicit published version. It returns 404 when the name does not exist or the package is not published.
- Version lists contain only versions explicitly present in the repository and marked published.
- Version detail returns 404 for unknown, unpublished, rejected, approved-but-unpublished, or yanked versions.
- The API never synthesizes a version from package summary data.
- Package latest-version metadata must refer to an existing published version. Invalid mock data is treated as repository-data corruption and surfaced as a controlled 500 error in development logs, not fabricated into a response.

The version response contains source, integrity, compatibility, permissions, installation metadata, trust score, scan summary, and timestamps when those values exist. It does not invent missing values.

## 8. Install Manifest v1.0

The endpoint accepts:

| Parameter | Type | Required | Behavior |
|---|---|---|---|
| `version` | semantic-version string | No | Defaults to the package's explicit latest published version |
| `client` | client string | Yes | Selects client-specific target and installation steps |

Unknown parameters and invalid version/client values return 422. A syntactically valid but nonexistent version follows the 404 behavior below.

### 8.1 Canonical shape

```json
{
  "manifest_version": "1.0",
  "name": "code-review-skill",
  "version": "1.0.0",
  "type": "skill",
  "description": "...",
  "source": {
    "type": "github",
    "repository_url": "https://github.com/example/repo",
    "download_url": "https://github.com/example/repo/archive/<commit>.zip",
    "ref": "v1.0.0",
    "commit_hash": "..."
  },
  "integrity": {
    "sha256": "...",
    "download_size_bytes": 1234
  },
  "installation": {
    "method": "copy_directory",
    "steps": [],
    "target_client": "claude-code",
    "pre_install_message": null,
    "post_install_message": null
  },
  "permissions": {},
  "risk_summary": {},
  "trust_score": 92,
  "compatibility": [],
  "dependencies": {}
}
```

### 8.2 Eligibility

The endpoint returns a manifest only when:

1. The package exists and is published.
2. The selected version exists and is published.
3. The version has a supported source and HTTPS download URL.
4. `integrity.sha256` is exactly 64 lowercase hexadecimal characters.
5. The requested target client is listed in compatibility data.
6. Installation has a supported method and at least one structured step.
7. A trust score and risk recommendation exist.
8. The recommendation is not `blocked`.

Unknown or non-public packages/versions return 404 to avoid leaking unpublished registry contents. A published version that lacks safe installation data returns 409 with `install_manifest_unavailable` and a list of missing/invalid fields.

The branch updates at least one published mock version so a valid success manifest can be exercised end to end. It does not fabricate hashes or download locations at request time.

## 9. Trust-score API

`GET /versions/{version_id}/trust-score` returns the full existing trust-score document for a published version. It returns 404 when:

- The version ID does not exist.
- The version is not public.
- No score has been calculated.

It never returns a synthetic zero-score object. This branch changes response mapping and routing only; it does not change scoring rules or recompute scores.

## 10. Package statistics API

`GET /stats/packages/{name}` returns statistics only for a published package:

```json
{
  "package_name": "code-review-skill",
  "install_count": 1280,
  "avg_rating": 4.7,
  "total_versions": 1,
  "latest_version": "1.0.0",
  "status": "published"
}
```

Statistics remain read-only mock values on this branch. Recording installs and ratings belongs to the persistence/authentication branch.

## 11. Error contract

All handled Consumer API errors use:

```json
{
  "error": {
    "code": "package_not_found",
    "message": "Package 'example' was not found.",
    "details": {}
  }
}
```

Canonical error codes include:

- `package_not_found`
- `version_not_found`
- `trust_score_not_found`
- `install_manifest_unavailable`
- `repository_data_invalid`

Validation errors remain FastAPI's standard 422 format so generated clients retain normal framework compatibility.

## 12. Repository architecture

### 12.1 Protocols

The route layer depends on a read-only repository protocol with focused methods:

```python
class PackageRepository(Protocol):
    def list_packages(self) -> Sequence[PackageRecord]: ...
    def get_package(self, name: str) -> PackageRecord | None: ...
    def list_versions(self, name: str) -> Sequence[VersionRecord]: ...
    def get_version(self, name: str, version: str) -> VersionRecord | None: ...
    def get_version_by_id(self, version_id: str) -> VersionRecord | None: ...
```

Filtering and sorting are implemented in a service layer rather than hidden inside JSON-loading code. The repository owns data retrieval; the service owns public visibility and query semantics; routers own HTTP translation.

### 12.2 Mock repository

The JSON-backed mock repository:

- Loads data once at application startup.
- Validates records into internal Pydantic record models.
- Indexes packages and versions by stable keys.
- Does not synthesize missing versions.
- Raises a typed repository-data error for invalid relationships.
- Is injectable in tests so each test can use an isolated fixture repository.

## 13. Module layout

```text
apps/api/src/
  errors.py
  dependencies.py
  models/
    __init__.py
    common.py
    packages.py
    install.py
    trust.py
  repositories/
    __init__.py
    base.py
    mock.py
  services/
    __init__.py
    packages.py
    install.py
  routers/
    packages.py
    install.py
    trust_scores.py
    stats.py
    trust.py              # existing scan router, behavior unchanged
  main.py
  scripts/
    export_openapi.py

packages/schema/openapi/
  consumer-v0.1.json
```

The existing `consumer_router.py`, `data.py`, and monolithic `models.py` are removed after their behavior is migrated. Tests import the application or focused services, not the old router module.

## 14. OpenAPI workflow

1. FastAPI generates OpenAPI from registered Consumer routes and Pydantic models.
2. `export_openapi.py` extracts the public Consumer paths and referenced schemas.
3. Output is serialized deterministically to `packages/schema/openapi/consumer-v0.1.json`.
4. A test regenerates the contract in memory and compares it with the committed snapshot.
5. Any route/model change requires intentionally updating the snapshot in the same commit.

The existing separate documentation repository is updated only after this branch is approved; it is not modified as part of this branch.

## 15. Testing strategy

Tests are written before behavior changes and cover:

### 15.1 Package list

- Default published-only behavior.
- Keyword, type, client, category, and combined filters.
- Every sort field in both directions.
- Null score/rating values always last.
- Stable tie ordering.
- Page and page-size boundaries.
- Invalid enums and ranges return 422.
- Unknown or legacy query parameters return 422 instead of being ignored.

### 15.2 Detail and versions

- Published package/version success.
- Unknown package/version returns 404.
- Non-public package/version returns 404.
- No synthetic version is returned.
- Invalid latest-version relationships produce a controlled repository error.

### 15.3 Install manifest

- Valid manifest matches every required field and nested constraint.
- Unknown/non-public resources return 404.
- Missing download URL, hash, steps, compatibility, or trust result returns 409.
- Invalid hash and blocked recommendation return 409.
- Missing `client` returns 422, an unsupported client returns 409 `install_manifest_unavailable`, and a nonexistent requested version returns 404.

### 15.4 Trust and stats

- Existing public result success.
- Unknown/unscored/non-public version returns 404.
- Stats count explicit published versions only.

### 15.5 Contract quality

- Runtime OpenAPI equals the committed snapshot.
- Expected paths and query parameter names are present.
- Removed legacy paths are absent.
- Test runs contain no Pydantic `__fields__` deprecation warning.

## 16. Migration and compatibility

This is a pre-release v0.1 project with no real Web/CLI API consumer, so correctness takes precedence over preserving current mock paths. The branch intentionally makes breaking changes:

- `/install` becomes `/install-manifest`.
- `/trust-scores/{version_id}` becomes `/versions/{version_id}/trust-score`.
- `sort` becomes `sort_by`.
- `limit` becomes `page_size`.
- Unknown resources change from synthetic 200 responses to 404.
- Package pagination uses `page_size` and includes `total_pages`.

These changes must be documented in the branch summary so later Web and CLI work starts from the canonical contract only.

## 17. Follow-up branches

Recommended sequence after this branch:

1. `consumer-db-feedback` — PostgreSQL repositories, install records, ratings, comments, authentication integration.
2. `consumer-trust-integration` — verified trust signals, real platform inputs, scanner-to-score golden tests.
3. `consumer-web-api` — generated client, real listing/detail/risk UI.
4. `consumer-cli-install` — npm packaging, download, verification, install record, uninstall/update/verify.
5. `consumer-examples-e2e` — safe installable examples and full Consumer E2E.
