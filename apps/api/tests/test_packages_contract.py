import inspect
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel, ValidationError

import src.models as public_models
from src.models import (
    CredentialsPermissions as RootCredentialsPermissions,
    EnvironmentPermissions as RootEnvironmentPermissions,
    PackageDetail as RootPackageDetail,
)
from src.models import common as common_models
from src.models import install as install_models
from src.models import packages as package_models
from src.models.common import PackageListQuery, PackageType, SortField, SortOrder
from src.models.packages import PackageDetail as CanonicalPackageDetail
from src.models.packages import (
    CredentialsPermissions,
    EnvironmentPermissions,
    PackagePage,
    PackageStats,
    PackageSummary,
    TrustScore,
    VersionDetail,
    VersionSummary,
)
from src.repositories.base import RepositoryDataError
from src.repositories.mock import JsonPackageRepository
from src.services.errors import (
    PackageNotFoundError,
    TrustScoreNotFoundError,
    VersionNotFoundError,
)
from src.services.packages import PackageService


ROOT = Path(__file__).resolve().parents[3]
MOCK = ROOT / "packages" / "schema" / "mock"


class FakeRepository:
    def __init__(
        self,
        packages: tuple[PackageSummary, ...],
        versions: tuple[VersionDetail, ...],
    ) -> None:
        self.packages = packages
        self.versions = versions

    def list_packages(self) -> tuple[PackageSummary, ...]:
        return self.packages

    def get_package(self, name: str) -> PackageSummary | None:
        return next((package for package in self.packages if package.name == name), None)

    def list_versions(self, name: str) -> tuple[VersionDetail, ...]:
        package = self.get_package(name)
        if package is None:
            return ()
        return tuple(
            version
            for version in self.versions
            if version.package_id == package.id
        )

    def get_version(self, name: str, version: str) -> VersionDetail | None:
        return next(
            (
                record
                for record in self.list_versions(name)
                if record.version == version
            ),
            None,
        )

    def get_version_by_id(self, version_id: str) -> VersionDetail | None:
        return next(
            (version for version in self.versions if version.id == version_id),
            None,
        )


@pytest.fixture
def fake_repository() -> FakeRepository:
    packages = (
        PackageSummary(
            id="p-alpha",
            name="alpha-package",
            description="Automation assistant",
            type="skill",
            keywords=["Review", "Quality"],
            category="development",
            latest_version="2.0.0",
            status="published",
            trust_score=90,
            install_count=100,
            avg_rating=4.5,
            updated_at="2026-02-01T00:00:00Z",
        ),
        PackageSummary(
            id="p-beta",
            name="beta-package",
            description="Documentation Helper",
            type="prompt",
            keywords=["writing"],
            category="documentation",
            latest_version="1.0.0",
            status="published",
            trust_score=None,
            install_count=50,
            avg_rating=None,
            updated_at=None,
        ),
        PackageSummary(
            id="p-gamma",
            name="Gamma-package",
            description="Deployment helper",
            type="mcp_server",
            keywords=["Cloud"],
            category="development",
            latest_version="1.0.0",
            status="published",
            trust_score=75,
            install_count=100,
            avg_rating=4.5,
            updated_at="2025-01-01T00:00:00+00:00",
        ),
        PackageSummary(
            id="p-private",
            name="private-package",
            description="Not public",
            type="skill",
            keywords=["private"],
            category="development",
            latest_version="1.0.0",
            status="draft",
            trust_score=100,
            install_count=999,
            avg_rating=5,
            updated_at="2027-01-01T00:00:00Z",
        ),
    )
    versions = (
        VersionDetail(
            id="v-alpha-published",
            package_id="p-alpha",
            version="2.0.0",
            status="published",
            compatibility=["claude-code"],
            submitted_at="2026-01-31T00:00:00Z",
            created_at="2026-01-30T00:00:00Z",
            trust_score=TrustScore(score=91, model_version="v2"),
        ),
        VersionDetail(
            id="v-alpha-draft",
            package_id="p-alpha",
            version="3.0.0",
            status="draft",
            compatibility=["codex"],
            trust_score=TrustScore(score=99),
        ),
        VersionDetail(
            id="v-beta-published",
            package_id="p-beta",
            version="1.0.0",
            status="published",
            compatibility=["claude-code"],
            trust_score=None,
        ),
        VersionDetail(
            id="v-gamma-published",
            package_id="p-gamma",
            version="1.0.0",
            status="published",
            compatibility=["codex"],
            trust_score=TrustScore(score=70),
        ),
        VersionDetail(
            id="v-private-published",
            package_id="p-private",
            version="1.0.0",
            status="published",
            compatibility=["claude-code"],
            trust_score=TrustScore(score=100),
        ),
    )
    return FakeRepository(packages, versions)


def test_package_query_defaults_are_public_and_canonical() -> None:
    query = PackageListQuery()
    assert query.q is None
    assert query.status == "published"
    assert query.sort_by is SortField.TRUST_SCORE
    assert query.order is SortOrder.DESC
    assert query.page == 1
    assert query.page_size == 20
    assert set(PackageListQuery.model_fields) == {
        "q",
        "type",
        "client",
        "category",
        "status",
        "sort_by",
        "order",
        "page",
        "page_size",
    }


def test_empty_page_has_zero_total_pages() -> None:
    page = PackagePage(items=[], total=0, page=1, page_size=20, total_pages=0)
    assert page.model_dump()["total_pages"] == 0


@pytest.mark.parametrize("field", ["keyword", "sort", "limit", "unknown"])
def test_package_query_rejects_legacy_and_unknown_fields(field: str) -> None:
    with pytest.raises(ValidationError):
        PackageListQuery(**{field: "value"})


def test_package_query_rejects_non_published_status() -> None:
    with pytest.raises(ValidationError):
        PackageListQuery(status="rejected")


@pytest.mark.parametrize("values", [{"page": 0}, {"page_size": 101}])
def test_package_query_rejects_out_of_range_pagination(
    values: dict[str, int],
) -> None:
    with pytest.raises(ValidationError):
        PackageListQuery(**values)


def test_package_detail_root_export_is_canonical_model() -> None:
    assert RootPackageDetail is CanonicalPackageDetail
    assert RootPackageDetail.__module__ == "src.models.packages"
    assert "latest_version_detail" in CanonicalPackageDetail.model_fields


def test_root_exports_all_canonical_pydantic_models() -> None:
    modules = (common_models, install_models, package_models)
    expected: dict[str, type[BaseModel]] = {
        name: model
        for module in modules
        for name, model in inspect.getmembers(module, inspect.isclass)
        if name.isidentifier()
        and model.__module__ == module.__name__
        and issubclass(model, BaseModel)
    }

    assert set(expected) <= set(public_models.__all__)
    assert all(
        getattr(public_models, name) is model
        for name, model in expected.items()
    )
    assert RootCredentialsPermissions is CredentialsPermissions
    assert RootEnvironmentPermissions is EnvironmentPermissions


def test_list_excludes_non_public_packages(fake_repository: FakeRepository) -> None:
    page = PackageService(fake_repository).list_packages(PackageListQuery())

    assert {item.status for item in page.items} == {"published"}
    assert "private-package" not in {item.name for item in page.items}


@pytest.mark.parametrize("field", [SortField.TRUST_SCORE, SortField.AVG_RATING])
@pytest.mark.parametrize("order", [SortOrder.ASC, SortOrder.DESC])
def test_null_numeric_sort_values_are_always_last(
    fake_repository: FakeRepository,
    field: SortField,
    order: SortOrder,
) -> None:
    page = PackageService(fake_repository).list_packages(
        PackageListQuery(sort_by=field, order=order)
    )

    value = getattr(page.items[-1], field.value)
    assert value is None


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ({"q": "ALPHA"}, {"alpha-package"}),
        ({"q": "documentation"}, {"beta-package"}),
        ({"q": "CLOUD"}, {"Gamma-package"}),
        ({"type": PackageType.PROMPT}, {"beta-package"}),
        ({"category": "development"}, {"alpha-package", "Gamma-package"}),
        ({"category": "Development"}, set()),
        ({"client": "claude-code"}, {"alpha-package", "beta-package"}),
        ({"client": "codex"}, {"Gamma-package"}),
        (
            {
                "q": "AUTOMATION",
                "type": PackageType.SKILL,
                "category": "development",
                "client": "claude-code",
            },
            {"alpha-package"},
        ),
    ],
)
def test_list_filters_public_packages(
    fake_repository: FakeRepository,
    query: dict[str, object],
    expected: set[str],
) -> None:
    page = PackageService(fake_repository).list_packages(PackageListQuery(**query))

    assert {item.name for item in page.items} == expected


@pytest.mark.parametrize(
    ("field", "order", "expected"),
    [
        (SortField.TRUST_SCORE, SortOrder.ASC, ["Gamma-package", "alpha-package", "beta-package"]),
        (SortField.TRUST_SCORE, SortOrder.DESC, ["alpha-package", "Gamma-package", "beta-package"]),
        (SortField.UPDATED_AT, SortOrder.ASC, ["Gamma-package", "alpha-package", "beta-package"]),
        (SortField.UPDATED_AT, SortOrder.DESC, ["alpha-package", "Gamma-package", "beta-package"]),
        (SortField.INSTALL_COUNT, SortOrder.ASC, ["beta-package", "alpha-package", "Gamma-package"]),
        (SortField.INSTALL_COUNT, SortOrder.DESC, ["alpha-package", "Gamma-package", "beta-package"]),
        (SortField.AVG_RATING, SortOrder.ASC, ["alpha-package", "Gamma-package", "beta-package"]),
        (SortField.AVG_RATING, SortOrder.DESC, ["alpha-package", "Gamma-package", "beta-package"]),
        (SortField.NAME, SortOrder.ASC, ["alpha-package", "beta-package", "Gamma-package"]),
        (SortField.NAME, SortOrder.DESC, ["Gamma-package", "beta-package", "alpha-package"]),
    ],
)
def test_list_sorts_every_field_with_deterministic_name_ties(
    fake_repository: FakeRepository,
    field: SortField,
    order: SortOrder,
    expected: list[str],
) -> None:
    page = PackageService(fake_repository).list_packages(
        PackageListQuery(sort_by=field, order=order)
    )

    assert [item.name for item in page.items] == expected


def test_updated_at_sort_normalizes_mixed_naive_and_aware_timestamps(
    fake_repository: FakeRepository,
) -> None:
    naive_alpha = fake_repository.packages[0].model_copy(
        update={"updated_at": "2026-02-01T00:00:00"}
    )
    repository = FakeRepository(
        (naive_alpha, *fake_repository.packages[1:]), fake_repository.versions
    )

    page = PackageService(repository).list_packages(
        PackageListQuery(sort_by=SortField.UPDATED_AT, order=SortOrder.ASC)
    )

    assert [item.name for item in page.items] == [
        "Gamma-package",
        "alpha-package",
        "beta-package",
    ]


def test_updated_at_sort_reports_malformed_timestamp_with_package_context(
    fake_repository: FakeRepository,
) -> None:
    malformed_alpha = fake_repository.packages[0].model_copy(
        update={"updated_at": "not-a-timestamp"}
    )
    repository = FakeRepository(
        (malformed_alpha, *fake_repository.packages[1:]), fake_repository.versions
    )

    with pytest.raises(
        RepositoryDataError, match=r"alpha-package.*updated_at"
    ):
        PackageService(repository).list_packages(
            PackageListQuery(sort_by=SortField.UPDATED_AT)
        )


def test_list_paginates_with_complete_metadata(
    fake_repository: FakeRepository,
) -> None:
    service = PackageService(fake_repository)

    second_page = service.list_packages(PackageListQuery(page=2, page_size=2))
    out_of_range = service.list_packages(PackageListQuery(page=4, page_size=2))
    empty = service.list_packages(
        PackageListQuery(q="missing", page_size=2)
    )

    assert len(second_page.items) == 1
    assert second_page.model_dump(exclude={"items"}) == {
        "total": 3,
        "page": 2,
        "page_size": 2,
        "total_pages": 2,
    }
    assert out_of_range.items == []
    assert out_of_range.total == 3
    assert out_of_range.total_pages == 2
    assert empty.model_dump() == {
        "items": [],
        "total": 0,
        "page": 1,
        "page_size": 2,
        "total_pages": 0,
    }


@pytest.mark.parametrize("name", ["missing", "private-package"])
def test_get_public_package_hides_absent_and_non_public_packages(
    fake_repository: FakeRepository,
    name: str,
) -> None:
    with pytest.raises(PackageNotFoundError) as caught:
        PackageService(fake_repository).get_public_package(name)

    assert caught.value.code == "package_not_found"
    assert not hasattr(caught.value, "status_code")


def test_unknown_or_non_public_version_is_not_synthesized(
    fake_repository: FakeRepository,
) -> None:
    service = PackageService(fake_repository)

    for version in ("9.9.9", "3.0.0"):
        with pytest.raises(VersionNotFoundError) as caught:
            service.get_public_version("alpha-package", version)
        assert caught.value.code == "version_not_found"


def test_public_version_checks_package_visibility_first(
    fake_repository: FakeRepository,
) -> None:
    with pytest.raises(PackageNotFoundError) as caught:
        PackageService(fake_repository).get_public_version(
            "private-package", "1.0.0"
        )

    assert caught.value.code == "package_not_found"


def test_public_package_and_version_lookups_return_explicit_records(
    fake_repository: FakeRepository,
) -> None:
    service = PackageService(fake_repository)

    package = service.get_public_package("alpha-package")
    version = service.get_public_version("alpha-package", "2.0.0")
    version_by_id = service.get_public_version_by_id("v-alpha-published")

    assert package == fake_repository.packages[0]
    assert version == fake_repository.versions[0]
    assert version_by_id == fake_repository.versions[0]


def test_public_package_detail_uses_explicit_published_latest_version(
    fake_repository: FakeRepository,
) -> None:
    detail = PackageService(fake_repository).get_package_detail("alpha-package")

    assert isinstance(detail, CanonicalPackageDetail)
    assert detail.name == "alpha-package"
    assert detail.latest_version_detail == VersionSummary(
        id="v-alpha-published",
        version="2.0.0",
        status="published",
        submitted_at="2026-01-31T00:00:00Z",
        created_at="2026-01-30T00:00:00Z",
        trust_score=91,
    )


def test_broken_latest_version_relationship_raises_repository_error(
    fake_repository: FakeRepository,
) -> None:
    broken = fake_repository.packages[0].model_copy(
        update={"latest_version": "9.9.9"}
    )
    repository = FakeRepository(
        (broken, *fake_repository.packages[1:]), fake_repository.versions
    )

    with pytest.raises(RepositoryDataError, match="invalid latest_version 9.9.9"):
        PackageService(repository).get_package_detail("alpha-package")


def _repository_with_draft_latest(
    fake_repository: FakeRepository,
) -> FakeRepository:
    package = fake_repository.packages[0].model_copy(
        update={"latest_version": "3.0.0"}
    )
    versions = tuple(
        version
        for version in fake_repository.versions
        if version.package_id != package.id or version.status == "draft"
    )
    return FakeRepository((package, *fake_repository.packages[1:]), versions)


def test_list_rejects_public_package_with_draft_latest_version(
    fake_repository: FakeRepository,
) -> None:
    repository = _repository_with_draft_latest(fake_repository)

    with pytest.raises(RepositoryDataError, match="invalid latest_version 3.0.0"):
        PackageService(repository).list_packages(PackageListQuery())


def test_stats_reject_public_package_with_draft_latest_version(
    fake_repository: FakeRepository,
) -> None:
    repository = _repository_with_draft_latest(fake_repository)

    with pytest.raises(RepositoryDataError, match="invalid latest_version 3.0.0"):
        PackageService(repository).get_stats("alpha-package")


def test_list_public_versions_returns_only_explicit_published_summaries(
    fake_repository: FakeRepository,
) -> None:
    versions = PackageService(fake_repository).list_public_versions("alpha-package")

    assert versions == [
        VersionSummary(
            id="v-alpha-published",
            version="2.0.0",
            status="published",
            submitted_at="2026-01-31T00:00:00Z",
            created_at="2026-01-30T00:00:00Z",
            trust_score=91,
        )
    ]


def test_list_public_versions_is_deterministic_descending(
    fake_repository: FakeRepository,
) -> None:
    old_version = VersionDetail(
        id="v-alpha-old",
        package_id="p-alpha",
        version="1.0.0",
        status="published",
    )
    repository = FakeRepository(
        fake_repository.packages,
        (old_version, *fake_repository.versions),
    )

    versions = PackageService(repository).list_public_versions("alpha-package")

    assert [version.version for version in versions] == ["2.0.0", "1.0.0"]


def test_real_json_repository_service_list_is_published_only() -> None:
    repository = JsonPackageRepository(
        MOCK / "packages.json", MOCK / "versions"
    )

    page = PackageService(repository).list_packages(PackageListQuery())

    assert page.total == 6
    assert {package.status for package in page.items} == {"published"}
    assert {"risky-executor", "web-scraper-mcp"}.isdisjoint(
        package.name for package in page.items
    )


@pytest.mark.parametrize("version_id", ["missing", "v-alpha-draft", "v-private-published"])
def test_get_public_version_by_id_hides_invalid_or_non_public_versions(
    fake_repository: FakeRepository,
    version_id: str,
) -> None:
    with pytest.raises(VersionNotFoundError) as caught:
        PackageService(fake_repository).get_public_version_by_id(version_id)

    assert caught.value.code == "version_not_found"


def test_get_trust_score_returns_full_public_score(
    fake_repository: FakeRepository,
) -> None:
    score = PackageService(fake_repository).get_trust_score("v-alpha-published")

    assert score == TrustScore(score=91, model_version="v2")


def test_get_trust_score_reports_absent_score(
    fake_repository: FakeRepository,
) -> None:
    with pytest.raises(TrustScoreNotFoundError) as caught:
        PackageService(fake_repository).get_trust_score("v-beta-published")

    assert caught.value.code == "trust_score_not_found"


def test_stats_count_only_explicit_published_versions(
    fake_repository: FakeRepository,
) -> None:
    stats = PackageService(fake_repository).get_stats("alpha-package")

    assert stats == PackageStats(
        package_name="alpha-package",
        install_count=100,
        avg_rating=4.5,
        total_versions=1,
        latest_version="2.0.0",
        status="published",
    )


def test_http_list_uses_canonical_sort_and_pagination(
    client: TestClient,
) -> None:
    response = client.get(
        "/api/v0/packages",
        params={"sort_by": "name", "order": "asc", "page_size": 2},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["page_size"] == 2
    assert len(body["items"]) == 2
    assert [item["name"] for item in body["items"]] == sorted(
        item["name"] for item in body["items"]
    )


@pytest.mark.parametrize(
    "query",
    [
        {"keyword": "postgresql"},
        {"sort": "name"},
        {"limit": "2"},
        {"unknown": "value"},
    ],
)
def test_http_list_rejects_legacy_and_unknown_query_parameters(
    client: TestClient,
    query: dict[str, str],
) -> None:
    response = client.get("/api/v0/packages", params=query)

    assert response.status_code == 422


def test_http_list_rejects_unknown_limit_with_canonical_sort(
    client: TestClient,
) -> None:
    response = client.get(
        "/api/v0/packages",
        params={"sort_by": "name", "limit": 2},
    )

    assert response.status_code == 422


def test_http_default_list_contains_only_published_packages(
    client: TestClient,
) -> None:
    response = client.get("/api/v0/packages")

    assert response.status_code == 200
    assert {item["status"] for item in response.json()["items"]} == {
        "published"
    }


def test_http_rejected_package_is_hidden_by_canonical_not_found(
    client: TestClient,
) -> None:
    response = client.get("/api/v0/packages/risky-executor")

    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "code": "package_not_found",
            "message": "Package 'risky-executor' was not found.",
            "details": {},
        }
    }


def test_http_unknown_version_uses_canonical_not_found(
    client: TestClient,
) -> None:
    response = client.get(
        "/api/v0/packages/code-review-skill/versions/9.9.9"
    )

    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "code": "version_not_found",
            "message": "Version 'code-review-skill@9.9.9' was not found.",
            "details": {},
        }
    }


def test_http_package_detail_includes_latest_version_detail(
    client: TestClient,
) -> None:
    response = client.get("/api/v0/packages/code-review-skill")

    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "code-review-skill"
    assert body["latest_version_detail"]["version"] == body["latest_version"]
    assert body["latest_version_detail"]["status"] == "published"


def test_http_versions_list_contains_only_published_versions(
    client: TestClient,
) -> None:
    response = client.get("/api/v0/packages/code-review-skill/versions")

    assert response.status_code == 200
    assert response.json()
    assert {version["status"] for version in response.json()} == {"published"}


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        (
            {"client": "claude-code"},
            {
                "code-review-skill",
                "postgres-explorer",
                "dev-toolkit-plugin",
                "demo-filesystem",
                "git-helper-skill",
                "docker-deploy-command",
            },
        ),
        ({"category": "productivity"}, {"dev-toolkit-plugin"}),
        ({"type": "command"}, {"docker-deploy-command"}),
        ({"q": "postgresql"}, {"postgres-explorer"}),
        (
            {"status": "published"},
            {
                "code-review-skill",
                "postgres-explorer",
                "dev-toolkit-plugin",
                "demo-filesystem",
                "git-helper-skill",
                "docker-deploy-command",
            },
        ),
    ],
)
def test_http_list_exposes_canonical_filters(
    client: TestClient,
    query: dict[str, str],
    expected: set[str],
) -> None:
    response = client.get("/api/v0/packages", params=query)

    assert response.status_code == 200
    assert {item["name"] for item in response.json()["items"]} == expected


@pytest.mark.parametrize(
    "query",
    [
        {"type": "not-a-package-type"},
        {"sort_by": "not-a-sort-field"},
        {"status": "rejected"},
        {"order": "sideways"},
        {"page": 0},
        {"page_size": 0},
        {"page_size": 101},
    ],
)
def test_http_list_rejects_invalid_enums_and_ranges(
    client: TestClient,
    query: dict[str, str | int],
) -> None:
    response = client.get("/api/v0/packages", params=query)

    assert response.status_code == 422


def test_http_health_uses_canonical_response(client: TestClient) -> None:
    response = client.get("/api/v0/health")

    assert response.status_code == 200
    assert response.json() == {
        "service": "Trusted Agent Hub API",
        "version": "0.1.0",
        "status": "ok",
    }


def test_http_health_has_canonical_openapi_tag(client: TestClient) -> None:
    operation = client.app.openapi()["paths"]["/api/v0/health"]["get"]

    assert operation["tags"] == ["health"]


def test_http_package_query_names_are_exactly_canonical(
    client: TestClient,
) -> None:
    operation = client.app.openapi()["paths"]["/api/v0/packages"]["get"]

    assert [parameter["name"] for parameter in operation["parameters"]] == [
        "q",
        "type",
        "client",
        "category",
        "status",
        "sort_by",
        "order",
        "page",
        "page_size",
    ]


def test_application_has_no_openapi_visible_options_catch_all(
    client: TestClient,
) -> None:
    assert "/{rest_of_path}" not in client.app.openapi()["paths"]
    assert client.get("/api/v0/not-a-route").status_code == 404


@pytest.mark.parametrize(
    "path",
    [
        "/api/v0/packages/code-review-skill/install",
        "/api/v0/trust-scores/ver-001",
    ],
)
def test_application_does_not_wire_legacy_consumer_routes(
    client: TestClient,
    path: str,
) -> None:
    response = client.get(path)

    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


def test_application_keeps_scan_routes_wired(client: TestClient) -> None:
    paths = client.app.openapi()["paths"]

    assert {
        "/api/v0/scan",
        "/api/v0/scan/{scan_id}",
        "/api/v0/scan/{scan_id}/report",
        "/api/v0/scans",
    }.issubset(paths)


def test_application_keeps_permissive_cors_preflight(client: TestClient) -> None:
    response = client.options(
        "/api/v0/packages",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "*"
    assert "GET" in response.headers["access-control-allow-methods"]
