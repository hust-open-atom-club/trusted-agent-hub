"""Strict HTTP contract tests for safe install manifests."""

import pytest
from fastapi.testclient import TestClient
from pydantic import TypeAdapter, ValidationError

from src.models.install import ManifestInstallationStep
from src.models.packages import InstallationStep
from src.repositories.mock import JsonPackageRepository


MANIFEST_PATH = "/api/v0/packages/code-review-skill/install-manifest"


def test_install_manifest_defaults_to_latest_published_version(
    client: TestClient,
) -> None:
    response = client.get(MANIFEST_PATH, params={"client": "claude-code"})

    assert response.status_code == 200
    manifest = response.json()
    assert set(manifest) == {
        "manifest_version",
        "name",
        "version",
        "type",
        "description",
        "source",
        "integrity",
        "installation",
        "permissions",
        "risk_summary",
        "compatibility",
        "dependencies",
    }
    assert manifest["manifest_version"] == "1.0"
    assert manifest["name"] == "code-review-skill"
    assert manifest["version"] == "1.0.0"
    assert manifest["type"] == "skill"
    assert manifest["description"]
    assert manifest["source"] == {
        "type": "github",
        "repository_url": (
            "https://github.com/alice-dev/code-review-skill"
        ),
        "download_url": (
            "https://github.com/alice-dev/code-review-skill/archive/"
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0.zip"
        ),
        "ref": "v1.0.0",
        "commit_hash": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    }
    assert manifest["integrity"] == {
        "sha256": (
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        ),
        "download_size_bytes": 18432,
    }
    assert manifest["installation"]["method"] == "copy_directory"
    assert manifest["installation"]["target_client"] == "claude-code"
    assert [
        step["action"] for step in manifest["installation"]["steps"]
    ] == ["download", "verify", "extract", "copy"]
    assert set(manifest["installation"]) == {
        "method",
        "target_client",
        "steps",
        "pre_install_message",
        "post_install_message",
    }
    assert manifest["permissions"]["filesystem"]["delete"] is False
    assert manifest["permissions"]["shell"]["commands"] == [
        "git",
        "diff",
        "grep",
    ]
    assert manifest["permissions"]["network"]["allowed"] is False
    assert manifest["risk_summary"]["install_recommendation"] == "safe"
    assert manifest["risk_summary"]["grade"] == "A"
    assert manifest["compatibility"] == ["claude-code", "cursor"]
    assert manifest["dependencies"] == {
        "npm": None,
        "pip": None,
        "system": ["git"],
        "docker": None,
        "mcp_servers": None,
    }


def test_install_manifest_accepts_explicit_semantic_version(
    client: TestClient,
) -> None:
    response = client.get(
        MANIFEST_PATH,
        params={"client": "claude-code", "version": "1.0.0"},
    )

    assert response.status_code == 200
    assert response.json()["version"] == "1.0.0"


def test_install_manifest_requires_client(client: TestClient) -> None:
    response = client.get(MANIFEST_PATH)

    assert response.status_code == 422


@pytest.mark.parametrize("value", ["", "   "])
def test_install_manifest_rejects_blank_client(
    client: TestClient,
    value: str,
) -> None:
    response = client.get(MANIFEST_PATH, params={"client": value})

    assert response.status_code == 422


def test_install_manifest_rejects_invalid_semantic_version(
    client: TestClient,
) -> None:
    response = client.get(
        MANIFEST_PATH,
        params={"client": "claude-code", "version": "01.0"},
    )

    assert response.status_code == 422


def test_install_manifest_rejects_unknown_query_parameters(
    client: TestClient,
) -> None:
    response = client.get(
        MANIFEST_PATH,
        params={"client": "claude-code", "channel": "stable"},
    )

    assert response.status_code == 422


def test_install_manifest_reports_nonexistent_public_version_canonically(
    client: TestClient,
) -> None:
    response = client.get(
        MANIFEST_PATH,
        params={"client": "claude-code", "version": "9.9.9"},
    )

    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "code": "version_not_found",
            "message": (
                "Version 'code-review-skill@9.9.9' was not found."
            ),
            "details": {},
        }
    }


def test_install_manifest_hides_non_public_package(client: TestClient) -> None:
    response = client.get(
        "/api/v0/packages/risky-executor/install-manifest",
        params={"client": "claude-code"},
    )

    assert response.status_code == 404
    assert response.json() == {
        "error": {
            "code": "package_not_found",
            "message": "Package 'risky-executor' was not found.",
            "details": {},
        }
    }


def test_install_manifest_reports_unsupported_client_fields(
    client: TestClient,
) -> None:
    response = client.get(MANIFEST_PATH, params={"client": "vscode"})

    assert response.status_code == 409
    assert response.json() == {
        "error": {
            "code": "install_manifest_unavailable",
            "message": (
                "Install manifest for 'code-review-skill@1.0.0' "
                "is unavailable."
            ),
            "details": {
                "invalid_fields": [
                    "compatibility",
                    "installation.target_client",
                ]
            },
        }
    }


def test_install_manifest_collects_all_unsafe_fields_deterministically(
    client: TestClient,
) -> None:
    response = client.get(
        "/api/v0/packages/demo-filesystem/install-manifest",
        params={"client": "claude-code"},
    )

    assert response.status_code == 409
    assert response.json() == {
        "error": {
            "code": "install_manifest_unavailable",
            "message": (
                "Install manifest for 'demo-filesystem@1.0.0' "
                "is unavailable."
            ),
            "details": {
                "invalid_fields": [
                    "source.download_url",
                    "integrity.sha256",
                    "installation.steps",
                    "installation.target_client",
                    "installation.method",
                    "permissions",
                    "risk_summary.grade",
                ]
            },
        }
    }


def test_install_manifest_openapi_contract_is_strict(client: TestClient) -> None:
    openapi = client.app.openapi()
    operation = openapi["paths"][
        "/api/v0/packages/{name}/install-manifest"
    ]["get"]

    assert operation["tags"] == ["install"]
    assert [parameter["name"] for parameter in operation["parameters"]] == [
        "name",
        "client",
        "version",
    ]
    assert operation["parameters"][1]["required"] is True
    assert operation["responses"]["200"]["content"][
        "application/json"
    ]["schema"] == {"$ref": "#/components/schemas/InstallManifest"}
    for status in ("404", "409"):
        assert operation["responses"][status]["content"][
            "application/json"
        ]["schema"] == {"$ref": "#/components/schemas/ErrorEnvelope"}

    schemas = openapi["components"]["schemas"]
    for schema_name in (
        "InstallManifest",
        "ManifestSource",
        "ManifestIntegrity",
        "ManifestInstallation",
    ):
        assert schemas[schema_name]["additionalProperties"] is False
    assert schemas["ManifestInstallation"]["properties"]["steps"][
        "items"
    ] == {"$ref": "#/components/schemas/ManifestInstallationStep"}
    step_schema = schemas["ManifestInstallationStep"]
    assert step_schema["discriminator"]["propertyName"] == "action"
    assert {branch["$ref"] for branch in step_schema["oneOf"]} == {
        "#/components/schemas/DownloadInstallationStep",
        "#/components/schemas/VerifyInstallationStep",
        "#/components/schemas/ExtractInstallationStep",
        "#/components/schemas/CopyInstallationStep",
    }
    for schema_name, required in {
        "DownloadInstallationStep": ["action", "url"],
        "VerifyInstallationStep": ["action", "algorithm", "checksum"],
        "ExtractInstallationStep": ["action", "archive"],
        "CopyInstallationStep": ["action", "source", "destination"],
    }.items():
        assert schemas[schema_name]["additionalProperties"] is False
        assert schemas[schema_name]["required"] == required
    assert schemas["InstallManifest"]["required"] == [
        "name",
        "version",
        "type",
        "description",
        "source",
        "integrity",
        "installation",
        "permissions",
        "risk_summary",
        "compatibility",
        "dependencies",
    ]


def test_legacy_install_route_remains_absent(client: TestClient) -> None:
    response = client.get(
        "/api/v0/packages/code-review-skill/install",
        params={"client": "claude-code"},
    )

    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


@pytest.mark.parametrize(
    "step",
    [
        {
            "action": "download",
            "url": "https://example.com/package.zip",
            "totally_unknown": True,
        },
        {"action": "execute_arbitrary"},
        {"action": "download", "url": "http://example.com/package.zip"},
    ],
)
def test_manifest_installation_step_rejects_unsafe_shapes(
    step: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(ManifestInstallationStep).validate_python(step)


@pytest.mark.parametrize(
    "step",
    [
        {"action": "extract", "archive": "/tmp/package.zip"},
        {"action": "extract", "archive": "C:/temp/package.zip"},
        {"action": "copy", "source": "..\\payload", "destination": "safe/"},
        {
            "action": "copy",
            "source": "safe/../payload",
            "destination": "safe/",
        },
        {"action": "copy", "source": "safe\x00payload", "destination": "safe/"},
    ],
    ids=["absolute", "windows-drive", "backslash", "traversal", "nul"],
)
def test_manifest_installation_step_rejects_unsafe_paths(
    step: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(ManifestInstallationStep).validate_python(step)


@pytest.mark.parametrize(
    "steps",
    [
        [
            {
                "action": "download",
                "url": "http://example.com/package.zip",
            }
        ],
        [{"action": "execute_arbitrary", "totally_unknown": True}],
        [
            {
                "action": "download",
                "url": "https://example.com/package.zip",
                "totally_unknown": True,
            }
        ],
        [{"action": "download"}],
    ],
    ids=[
        "unsafe-http",
        "unsupported-action",
        "unknown-field",
        "missing-required-data",
    ],
)
def test_install_manifest_rejects_invalid_repository_steps(
    client: TestClient,
    repository: JsonPackageRepository,
    steps: list[dict[str, object]],
) -> None:
    _replace_installation_steps(repository, steps)

    response = client.get(MANIFEST_PATH, params={"client": "claude-code"})

    assert response.status_code == 409
    assert response.json() == {
        "error": {
            "code": "install_manifest_unavailable",
            "message": (
                "Install manifest for 'code-review-skill@1.0.0' "
                "is unavailable."
            ),
            "details": {"invalid_fields": ["installation.steps"]},
        }
    }


def _replace_installation_steps(
    repository: JsonPackageRepository,
    steps: list[dict[str, object]],
    *,
    method: str | None = None,
) -> None:
    record = repository.get_version("code-review-skill", "1.0.0")
    assert record is not None
    assert record.installation is not None
    update: dict[str, object] = {
        "steps": [InstallationStep.model_validate(step) for step in steps]
    }
    if method is not None:
        update["method"] = method
    installation = record.installation.model_copy(update=update)
    replacement = record.model_copy(update={"installation": installation})
    repository._versions_by_key[("code-review-skill", "1.0.0")] = replacement
    repository._versions_by_id[record.id] = replacement


def _identity_steps(
    *,
    download_url: str = (
        "https://github.com/alice-dev/code-review-skill/archive/"
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0.zip"
    ),
    checksum: str = (
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    ),
    destination: str = "~/.claude/skills/code-review-skill/",
) -> list[dict[str, object]]:
    return [
        {"action": "download", "url": download_url},
        {"action": "verify", "algorithm": "sha256", "checksum": checksum},
        {"action": "extract", "archive": "code-review-skill.zip"},
        {
            "action": "copy",
            "source": "code-review-skill/",
            "destination": destination,
        },
    ]


def test_install_manifest_accepts_canonically_equal_download_urls(
    client: TestClient,
    repository: JsonPackageRepository,
) -> None:
    download_url = "https://downloads.example.test"
    record = repository.get_version("code-review-skill", "1.0.0")
    assert record is not None
    assert record.source is not None
    assert record.installation is not None
    source = record.source.model_copy(update={"download_url": download_url})
    installation = record.installation.model_copy(
        update={
            "steps": [
                InstallationStep.model_validate(step)
                for step in _identity_steps(download_url=download_url)
            ]
        }
    )
    replacement = record.model_copy(
        update={"source": source, "installation": installation}
    )
    repository._versions_by_key[("code-review-skill", "1.0.0")] = replacement
    repository._versions_by_id[record.id] = replacement

    response = client.get(MANIFEST_PATH, params={"client": "claude-code"})

    assert response.status_code == 200
    manifest = response.json()
    assert manifest["source"]["download_url"] == f"{download_url}/"
    assert manifest["installation"]["steps"][0]["url"] == f"{download_url}/"


def test_copy_directory_accepts_exact_install_sequence(
    client: TestClient,
    repository: JsonPackageRepository,
) -> None:
    _replace_installation_steps(repository, _identity_steps())

    response = client.get(MANIFEST_PATH, params={"client": "claude-code"})

    assert response.status_code == 200
    assert [
        step["action"]
        for step in response.json()["installation"]["steps"]
    ] == ["download", "verify", "extract", "copy"]


@pytest.mark.parametrize(
    "steps",
    [
        [
            _identity_steps()[0],
            _identity_steps()[2],
            _identity_steps()[3],
            _identity_steps()[1],
        ],
        [
            _identity_steps()[0],
            _identity_steps()[1],
            _identity_steps()[3],
        ],
        _identity_steps()[:3],
        [*_identity_steps(), _identity_steps()[3]],
        [
            _identity_steps()[0],
            _identity_steps()[1],
            _identity_steps()[3],
            _identity_steps()[2],
        ],
    ],
    ids=[
        "late-verify",
        "missing-extract",
        "missing-copy",
        "duplicate-copy",
        "reordered-copy-extract",
    ],
)
def test_copy_directory_rejects_ambiguous_install_sequence(
    client: TestClient,
    repository: JsonPackageRepository,
    steps: list[dict[str, object]],
) -> None:
    _replace_installation_steps(repository, steps)

    response = client.get(MANIFEST_PATH, params={"client": "claude-code"})

    assert response.status_code == 409
    assert response.json()["error"]["details"] == {
        "invalid_fields": ["installation.steps"]
    }


@pytest.mark.parametrize(
    "destination",
    [
        "~/.ssh/authorized_keys",
        "~root/.ssh/authorized_keys",
        "~/.cursor/skills/code-review-skill/",
        "~/.claude/skills/",
        "~/.claude/skills/../.ssh/authorized_keys",
    ],
    ids=["ssh", "other-home", "wrong-client", "root-itself", "root-escape"],
)
def test_copy_directory_rejects_destination_outside_client_root(
    client: TestClient,
    repository: JsonPackageRepository,
    destination: str,
) -> None:
    _replace_installation_steps(
        repository,
        _identity_steps(destination=destination),
    )

    response = client.get(MANIFEST_PATH, params={"client": "claude-code"})

    assert response.status_code == 409
    assert response.json()["error"]["details"] == {
        "invalid_fields": ["installation.steps"]
    }


@pytest.mark.parametrize(
    ("method", "steps"),
    [
        (
            "manual_steps",
            [
                _identity_steps()[0],
                _identity_steps()[3],
                _identity_steps()[1],
            ],
        ),
        (
            "pip_install",
            [
                _identity_steps()[0],
                _identity_steps()[2],
                _identity_steps()[1],
            ],
        ),
    ],
    ids=["copy-before-verify", "extract-before-verify"],
)
def test_other_methods_reject_artifact_consumption_before_verify(
    client: TestClient,
    repository: JsonPackageRepository,
    method: str,
    steps: list[dict[str, object]],
) -> None:
    _replace_installation_steps(repository, steps, method=method)

    response = client.get(MANIFEST_PATH, params={"client": "claude-code"})

    assert response.status_code == 409
    assert response.json()["error"]["details"] == {
        "invalid_fields": ["installation.steps"]
    }


@pytest.mark.parametrize(
    "steps",
    [
        _identity_steps(download_url="https://example.com/other.zip"),
        _identity_steps(checksum="f" * 64),
        [_identity_steps()[0], *_identity_steps()],
        [_identity_steps()[1], *_identity_steps()],
        [step for step in _identity_steps() if step["action"] != "verify"],
        [_identity_steps()[1], _identity_steps()[0], *_identity_steps()[2:]],
        [
            *_identity_steps()[:3],
            {
                "action": "copy",
                "source": "../payload",
                "destination": "~/.claude/skills/code-review-skill/",
            },
        ],
    ],
    ids=[
        "download-mismatch",
        "checksum-mismatch",
        "duplicate-download",
        "duplicate-verify",
        "missing-verify",
        "verify-before-download",
        "path-traversal",
    ],
)
def test_install_manifest_rejects_untrusted_step_instructions(
    client: TestClient,
    repository: JsonPackageRepository,
    steps: list[dict[str, object]],
) -> None:
    _replace_installation_steps(repository, steps)

    response = client.get(MANIFEST_PATH, params={"client": "claude-code"})

    assert response.status_code == 409
    assert response.json()["error"] == {
        "code": "install_manifest_unavailable",
        "message": (
            "Install manifest for 'code-review-skill@1.0.0' is unavailable."
        ),
        "details": {"invalid_fields": ["installation.steps"]},
    }


def test_install_manifest_rejects_missing_grade(
    client: TestClient,
    repository: JsonPackageRepository,
) -> None:
    record = repository.get_version("code-review-skill", "1.0.0")
    assert record is not None
    assert record.trust_score is not None
    replacement = record.model_copy(
        update={
            "trust_score": record.trust_score.model_copy(
                update={
                    "risk_summary": record.trust_score.risk_summary.model_copy(
                        update={"grade": None}
                    )
                }
            )
        }
    )
    repository._versions_by_key[("code-review-skill", "1.0.0")] = replacement
    repository._versions_by_id[record.id] = replacement

    response = client.get(MANIFEST_PATH, params={"client": "claude-code"})

    assert response.status_code == 409
    assert response.json()["error"] == {
        "code": "install_manifest_unavailable",
        "message": (
            "Install manifest for 'code-review-skill@1.0.0' is unavailable."
        ),
        "details": {"invalid_fields": ["risk_summary.grade"]},
    }
