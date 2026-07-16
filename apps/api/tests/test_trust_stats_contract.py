import pytest
from fastapi.testclient import TestClient

from src.dependencies import get_package_repository
from src.main import create_app
from src.models.packages import PackageSummary, VersionDetail
from src.repositories.mock import JsonPackageRepository


TRUST_SCORE_PATH = "/api/v0/versions/ver-001/trust-score"
STATS_PATH = "/api/v0/stats/packages/code-review-skill"


class RepositoryWithAdditionalVersions:
    def __init__(
        self,
        base: JsonPackageRepository,
        versions: tuple[VersionDetail, ...],
    ) -> None:
        self.base = base
        self.versions = versions

    def list_packages(self) -> tuple[PackageSummary, ...]:
        return tuple(self.base.list_packages())

    def get_package(self, name: str) -> PackageSummary | None:
        return self.base.get_package(name)

    def list_versions(self, name: str) -> tuple[VersionDetail, ...]:
        package = self.get_package(name)
        additional = () if package is None else tuple(
            version
            for version in self.versions
            if version.package_id == package.id
        )
        return (*self.base.list_versions(name), *additional)

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
        for version in self.versions:
            if version.id == version_id:
                return version
        return self.base.get_version_by_id(version_id)


def test_injected_version_lookup_does_not_read_base_repository(
    repository: JsonPackageRepository,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = repository.get_version_by_id("ver-001")
    assert record is not None
    injected = record.model_copy(update={"id": "injected-version"})
    augmented_repository = RepositoryWithAdditionalVersions(
        repository,
        (injected,),
    )

    def fail_if_called(version_id: str) -> VersionDetail | None:
        raise AssertionError(f"unexpected base lookup for {version_id}")

    monkeypatch.setattr(repository, "get_version_by_id", fail_if_called)

    assert augmented_repository.get_version_by_id(injected.id) == injected


def test_trust_score_returns_full_published_score_document(
    client: TestClient,
    repository: JsonPackageRepository,
) -> None:
    response = client.get(TRUST_SCORE_PATH)

    record = repository.get_version_by_id("ver-001")
    assert record is not None
    assert record.trust_score is not None
    assert response.status_code == 200
    assert response.json() == record.trust_score.model_dump(mode="json")
    assert response.json()["score"] == 92


def test_unknown_version_has_canonical_trust_score_not_found(
    client: TestClient,
) -> None:
    response = client.get(
        "/api/v0/versions/nonexistent-version-id/trust-score"
    )

    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "code": "trust_score_not_found",
            "message": (
                "Trust score for version 'nonexistent-version-id' "
                "was not found."
            ),
            "details": {},
        }
    }


def test_nonpublic_version_trust_score_is_hidden(
    client: TestClient,
) -> None:
    response = client.get("/api/v0/versions/ver-005/trust-score")

    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "code": "trust_score_not_found",
            "message": "Trust score for version 'ver-005' was not found.",
            "details": {},
        }
    }
    assert "8" not in response.text


def test_published_version_without_score_is_not_synthesized(
    client: TestClient,
) -> None:
    response = client.get("/api/v0/versions/ver-004/trust-score")

    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "code": "trust_score_not_found",
            "message": "Trust score for version 'ver-004' was not found.",
            "details": {},
        }
    }
    assert "score" not in response.json()["error"]["details"]


def test_legacy_trust_score_route_remains_absent(
    client: TestClient,
) -> None:
    response = client.get("/api/v0/trust-scores/ver-001")

    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


def test_package_stats_return_exact_published_mock_values(
    client: TestClient,
) -> None:
    response = client.get(STATS_PATH)

    assert response.status_code == 200
    assert response.json() == {
        "package_name": "code-review-skill",
        "install_count": 1280,
        "avg_rating": 4.7,
        "total_versions": 1,
        "latest_version": "1.0.0",
        "status": "published",
    }


def test_unknown_package_stats_use_canonical_not_found(
    client: TestClient,
) -> None:
    response = client.get("/api/v0/stats/packages/nonexistent-package")

    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "code": "package_not_found",
            "message": "Package 'nonexistent-package' was not found.",
            "details": {},
        }
    }


def test_nonpublic_package_stats_are_hidden(client: TestClient) -> None:
    response = client.get("/api/v0/stats/packages/risky-executor")

    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "code": "package_not_found",
            "message": "Package 'risky-executor' was not found.",
            "details": {},
        }
    }
    assert "install_count" not in response.text


def test_package_stats_count_only_explicit_published_versions(
    repository: JsonPackageRepository,
) -> None:
    record = repository.get_version_by_id("ver-001")
    assert record is not None
    published = record.model_copy(
        update={
            "id": "ver-code-review-published",
            "version": "1.5.0",
        }
    )
    draft = record.model_copy(
        update={
            "id": "ver-code-review-draft",
            "version": "2.0.0",
            "status": "draft",
            "trust_score": None,
        }
    )
    augmented_repository = RepositoryWithAdditionalVersions(
        repository,
        (published, draft),
    )
    app = create_app()
    app.dependency_overrides[get_package_repository] = (
        lambda: augmented_repository
    )

    with TestClient(app) as client:
        response = client.get(STATS_PATH)

    assert response.status_code == 200
    assert response.json()["total_versions"] == 2


@pytest.mark.parametrize(
    "path",
    [TRUST_SCORE_PATH, STATS_PATH],
)
def test_read_only_contract_routes_reject_unknown_query_parameters(
    client: TestClient,
    path: str,
) -> None:
    response = client.get(path, params={"unexpected": "value"})

    assert response.status_code == 422


def test_trust_score_and_stats_openapi_contract(client: TestClient) -> None:
    paths = client.app.openapi()["paths"]
    trust_operation = paths[
        "/api/v0/versions/{version_id}/trust-score"
    ]["get"]
    stats_operation = paths["/api/v0/stats/packages/{name}"]["get"]

    assert trust_operation["tags"] == ["trust-scores"]
    assert stats_operation["tags"] == ["stats"]
    assert [
        parameter["name"] for parameter in trust_operation["parameters"]
    ] == ["version_id"]
    assert [
        parameter["name"] for parameter in stats_operation["parameters"]
    ] == ["name"]
    assert trust_operation["responses"]["200"]["content"][
        "application/json"
    ]["schema"] == {"$ref": "#/components/schemas/TrustScore"}
    assert stats_operation["responses"]["200"]["content"][
        "application/json"
    ]["schema"] == {"$ref": "#/components/schemas/PackageStats"}
    for operation in (trust_operation, stats_operation):
        assert operation["responses"]["404"]["content"][
            "application/json"
        ]["schema"] == {"$ref": "#/components/schemas/ErrorEnvelope"}
    assert "/api/v0/trust-scores/{version_id}" not in paths
