"""Install Manifest 多安装方式（npm/pip/docker/manual）契约测试。"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.models.packages import (
    Installation,
    InstallationStep,
    Permissions,
    RiskSummary,
    Source,
    TrustScore,
    VersionDetail,
)


class RepositoryWithMethodVersions:
    """在 base fixture 仓库上追加指定版本的已发布版本。"""

    def __init__(self, base, versions):
        self.base = base
        self.versions = versions

    def list_packages(self):
        return tuple(self.base.list_packages())

    def get_package(self, name):
        return self.base.get_package(name)

    def list_versions(self, name):
        package = self.get_package(name)
        additional = () if package is None else tuple(
            v for v in self.versions if v.package_id == package.id
        )
        return (*self.base.list_versions(name), *additional)

    def get_version(self, name, version):
        return next(
            (v for v in self.list_versions(name) if v.version == version),
            None,
        )

    def get_version_by_id(self, version_id):
        for v in self.versions:
            if v.id == version_id:
                return v
        return self.base.get_version_by_id(version_id)


def _method_version(
    version_id: str,
    package_id: str,
    version: str,
    method: str,
    step: dict,
) -> VersionDetail:
    return VersionDetail(
        id=version_id,
        package_id=package_id,
        version=version,
        status="published",
        source=Source(
            type="github",
            repository_url="https://github.com/example/demo",
            ref="main",
        ),
        compatibility=["claude-code"],
        permissions=Permissions(
            filesystem={"read": [], "write": [], "delete": False},
            shell={"allowed": False, "commands": []},
            network={"allowed": False, "domains": []},
        ),
        installation=Installation(
            method=method,
            target_client="claude-code",
            steps=[InstallationStep.model_validate(step)],
        ),
        trust_score=TrustScore(
            model_version="0.2.0",
            risk_summary=RiskSummary(
                level="low_risk",
                grade="B",
                top_risks=[],
                install_recommendation="safe",
                auto_grade="B",
                effective_grade="B",
            ),
            calculated_at="2026-08-03T00:00:00Z",
        ),
        submitted_at="2026-08-01T00:00:00Z",
        published_at="2026-08-02T00:00:00Z",
        created_at="2026-08-01T00:00:00Z",
    )


@pytest.fixture
def method_repository(repository):
    package_id = repository.list_packages()[0].id
    versions = [
        _method_version(
            "ver-npm",
            package_id,
            "2.0.0",
            "npm_install",
            {
                "action": "npm_install",
                "package": "demo-tool",
                "version": "2.0.0",
                "registry": "https://registry.npmjs.org",
            },
        ),
        _method_version(
            "ver-pip",
            package_id,
            "3.0.0",
            "pip_install",
            {
                "action": "pip_install",
                "package": "demo-tool",
                "version": "3.0.0",
                "index_url": "https://pypi.org/simple",
            },
        ),
        _method_version(
            "ver-docker",
            package_id,
            "4.0.0",
            "docker_run",
            {
                "action": "docker_run",
                "image": "demo/app",
                "tag": "4.0.0",
                "ports": ["8080:80"],
                "volumes": [],
                "env": ["KEY=VALUE"],
            },
        ),
        _method_version(
            "ver-manual",
            package_id,
            "5.0.0",
            "manual_steps",
            {
                "action": "manual_steps",
                "title": "demo-tool",
                "text": "1. 下载安装包\n2. 按 README 执行",
            },
        ),
    ]
    return RepositoryWithMethodVersions(repository, versions)


@pytest.fixture
def method_client(method_repository):
    from src.dependencies import get_package_repository
    from src.main import create_app

    app = create_app()
    app.dependency_overrides[get_package_repository] = lambda: method_repository
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _get_manifest(client: TestClient, version: str, name: str):
    return client.get(
        f"/api/v0/packages/{name}/install-manifest",
        params={"client": "claude-code", "version": version},
    )


def _package_name(method_client: TestClient) -> str:
    from src.dependencies import get_package_repository

    repo = method_client.app.dependency_overrides[get_package_repository]()
    return repo.list_packages()[0].name


@pytest.mark.parametrize(
    ("version", "action"),
    [
        ("2.0.0", "npm_install"),
        ("3.0.0", "pip_install"),
        ("4.0.0", "docker_run"),
        ("5.0.0", "manual_steps"),
    ],
)
def test_non_copy_manifest_methods_serve_steps(
    method_client: TestClient,
    version: str,
    action: str,
) -> None:
    response = _get_manifest(
        method_client,
        version,
        _package_name(method_client),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    steps = body["installation"]["steps"]
    assert len(steps) == 1
    assert steps[0]["action"] == action
    # 非 ZIP 方式不强制制品字段
    assert body["integrity"] is None
    assert body["source"]["download_url"] is None
    assert body["source"]["commit_hash"] is None


def test_npm_manifest_keeps_registry_and_version(
    method_client: TestClient,
) -> None:
    response = _get_manifest(
        method_client,
        "2.0.0",
        _package_name(method_client),
    )
    step = response.json()["installation"]["steps"][0]
    assert step["package"] == "demo-tool"
    assert step["version"] == "2.0.0"
    assert step["registry"] == "https://registry.npmjs.org/"


def test_docker_manifest_keeps_image_and_options(
    method_client: TestClient,
) -> None:
    response = _get_manifest(
        method_client,
        "4.0.0",
        _package_name(method_client),
    )
    step = response.json()["installation"]["steps"][0]
    assert step["image"] == "demo/app"
    assert step["tag"] == "4.0.0"
    assert step["ports"] == ["8080:80"]
    assert step["env"] == ["KEY=VALUE"]


def test_method_mismatch_steps_are_rejected(
    method_repository,
) -> None:
    from src.dependencies import get_package_repository
    from src.main import create_app

    pkg_id = method_repository.list_packages()[0].id
    bad = _method_version(
        "ver-bad",
        pkg_id,
        "6.0.0",
        "npm_install",
        {"action": "copy", "source": "x/", "destination": "y/"},
    )
    method_repository.versions = [*method_repository.versions, bad]
    app = create_app()
    app.dependency_overrides[get_package_repository] = lambda: method_repository
    with TestClient(app) as client:
        name = method_repository.list_packages()[0].name
        response = client.get(
            f"/api/v0/packages/{name}/install-manifest",
            params={"client": "claude-code", "version": "6.0.0"},
        )
    assert response.status_code == 409
    assert "installation.steps" in response.json()["error"]["details"][
        "invalid_fields"
    ]


# ── Producer 侧：非 ZIP 方式步骤生成 ─────────────────────────


class FakeProducerRepository:
    def __init__(self, version: dict) -> None:
        self.version = version

    def get_version(self, version_id: str) -> dict | None:
        return dict(self.version)

    def get_package(self, package_id: str) -> dict | None:
        return {"id": package_id, "name": "demo-tool"}

    def update_version_data(self, version_id: str, updates: dict) -> None:
        self.version = {**self.version, **updates}


@pytest.mark.parametrize(
    ("method", "expected_action"),
    [
        ("npm_install", "npm_install"),
        ("pip_install", "pip_install"),
        ("docker_run", "docker_run"),
        ("manual_steps", "manual_steps"),
    ],
)
def test_producer_generates_method_steps(
    method: str,
    expected_action: str,
) -> None:
    from src.services.producer import ProducerService

    repo = FakeProducerRepository(
        {
            "id": "ver-1",
            "package_id": "pkg-1",
            "version": "1.0.0",
            "status": "pending_review",
            "compatibility": ["claude-code"],
            "installation": {"method": method, "target_client": "claude-code"},
        }
    )
    ProducerService(repo)._apply_installation_steps_to_version(
        "ver-1",
        "demo-tool",
        "1.0.0",
        method,
    )
    steps = repo.version["installation"]["steps"]
    assert steps[0]["action"] == expected_action
    if method == "npm_install":
        assert steps[0]["registry"] == "https://registry.npmjs.org"
    if method == "docker_run":
        assert steps[0]["image"] == "demo-tool"
    if method == "manual_steps":
        assert "手动安装" in steps[0]["text"]


def test_producer_keeps_existing_matching_steps() -> None:
    from src.services.producer import ProducerService

    repo = FakeProducerRepository(
        {
            "id": "ver-1",
            "package_id": "pkg-1",
            "version": "1.0.0",
            "status": "pending_review",
            "installation": {
                "method": "npm_install",
                "target_client": "claude-code",
                "steps": [
                    {
                        "action": "npm_install",
                        "package": "custom",
                        "version": "0.9.9",
                        "registry": "https://registry.example.com",
                    }
                ],
            },
        }
    )
    ProducerService(repo)._apply_installation_steps_to_version(
        "ver-1",
        "demo-tool",
        "1.0.0",
        "npm_install",
    )
    assert repo.version["installation"]["steps"][0]["registry"] == (
        "https://registry.example.com"
    )
