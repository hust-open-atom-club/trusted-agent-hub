"""Author homepage, project homepage, and client-enum regression coverage."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from pydantic import ValidationError

from packages.schema.extract_skills import extract_single_skill
from schema.constants import CLIENTS
from src.models.common import Client, PackageListQuery, PackageType
from src.models.packages import Author
from src.models.producer import CreatePackageRequest
from src.services.install import CLIENT_INSTALL_ROOTS, get_client_install_root
from src.services.producer import (
    ProducerService,
    ProducerServiceError,
    _backfill_author_license,
    _distinct_homepage,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
SCHEMA_PATH = PROJECT_ROOT / "packages" / "schema" / "agent-package.schema.json"
SCHEMA_EXAMPLES = PROJECT_ROOT / "packages" / "schema" / "examples"


class _VersionRepository:
    def __init__(self, version: dict[str, Any]) -> None:
        self.version = version
        self.updates: list[dict[str, object]] = []

    def get_version(self, version_id: str) -> dict[str, Any] | None:
        assert version_id == "version-1"
        return self.version

    def update_version_data(
        self,
        version_id: str,
        updates: dict[str, object],
    ) -> None:
        assert version_id == "version-1"
        self.updates.append(updates)


class _CreatePackageRepository:
    """Minimal repository used to exercise ProducerService.create_package."""

    def __init__(self) -> None:
        self.created: dict[str, object] = {}

    def package_name_exists(self, name: str) -> bool:
        assert name == "supported-codex-mcp"
        return False

    def create_package(self, **kwargs: object) -> dict[str, object]:
        self.created = kwargs
        return {
            "id": "package-1",
            "name": str(kwargs["name"]),
            "type": kwargs["type"],
            "description": str(kwargs["description"]),
            "status": "draft",
            "license": kwargs.get("license"),
            "keywords": kwargs.get("keywords", []),
            "category": kwargs.get("category"),
            "author": kwargs.get("author"),
            "created_at": "2026-09-08T00:00:00Z",
            "updated_at": "2026-09-08T00:00:00Z",
        }


def test_author_name_and_email_are_optional_legacy_fields() -> None:
    author = Author.model_validate({"url": "https://example.com/author"})

    assert author.model_dump(exclude_none=True) == {
        "url": "https://example.com/author"
    }
    assert Author.model_validate(
        {"name": "Legacy", "email": "legacy@example.com"}
    ).name == "Legacy"


def test_api_client_enum_accepts_codex_and_rejects_unknown_values() -> None:
    request = CreatePackageRequest.model_validate(
        {
            "name": "codex-skill",
            "type": "skill",
            "description": "A Skill that supports Codex installations.",
            "compatibility": ["codex"],
        }
    )

    assert request.compatibility == [Client.CODEX]
    assert PackageListQuery(client="codex").client is Client.CODEX
    with pytest.raises(ValidationError):
        PackageListQuery(client="not-a-client")


def test_api_client_enum_stays_in_sync_with_shared_schema_constants() -> None:
    assert tuple(client.value for client in Client) == CLIENTS


def test_json_schema_accepts_url_only_codex_skill_author() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    skill = json.loads(
        (SCHEMA_EXAMPLES / "skill-basic.json").read_text(encoding="utf-8")
    )
    skill["author"] = {"url": "https://example.com/alice-dev"}
    skill["compatibility"] = ["codex"]
    skill["installation"]["targets"] = [
        {
            "client": "codex",
            "destination": "~/.codex/skills/code-review-skill/",
        }
    ]

    jsonschema.validate(skill, schema)


def test_extractor_uses_codex_target_for_codex_only_skill(
    tmp_path: Path,
) -> None:
    (tmp_path / "SKILL.md").write_text(
        "---\n"
        "name: codex-only-skill\n"
        "description: A Skill intended only for Codex installations.\n"
        "compatibility:\n"
        "  - codex\n"
        "---\n"
        "\n# Codex only skill\n",
        encoding="utf-8",
    )

    metadata = extract_single_skill(tmp_path)

    assert metadata["compatibility"] == ["codex"]
    assert metadata["installation"]["targets"] == [
        {
            "client": "codex",
            "destination": "~/.codex/skills/codex-only-skill/",
        }
    ]


def test_json_schema_accepts_codex_for_mcp_server() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    mcp_server = json.loads(
        (SCHEMA_EXAMPLES / "mcp-server-basic.json").read_text(
            encoding="utf-8"
        )
    )
    mcp_server["compatibility"] = ["claude-code", "codex"]
    mcp_server["installation"]["targets"] = [
        {
            "client": "codex",
            "destination": "~/.trusted-agent-hub/installed/supported-codex-mcp/",
        }
    ]

    jsonschema.validate(mcp_server, schema)


def test_api_install_root_for_codex_skills() -> None:
    assert CLIENT_INSTALL_ROOTS["codex"] == "~/.codex/skills/"
    assert get_client_install_root("codex", "mcp_server") == (
        "~/.trusted-agent-hub/installed/"
    )


def test_create_api_accepts_codex_install_target_for_mcp_server() -> None:
    request = CreatePackageRequest.model_validate(
        {
            "name": "supported-codex-mcp",
            "type": "mcp_server",
            "description": "An MCP server with a valid Codex target.",
            "compatibility": ["claude-code", "codex"],
            "installation": {
                "method": "copy_directory",
                "targets": [
                    {
                        "client": "codex",
                        "destination": "~/.trusted-agent-hub/installed/supported-codex-mcp/",
                    }
                ],
            },
        }
    )

    repository = _CreatePackageRepository()
    service = ProducerService(repository)  # type: ignore[arg-type]
    response = service.create_package(request)
    assert response.id == "package-1"
    assert response.type == PackageType.MCP_SERVER
    installation = repository.created["installation"]
    assert isinstance(installation, dict)
    targets = installation.get("targets")
    assert targets is not None
    assert targets[0]["client"] in ("codex", Client.CODEX)


def test_project_homepage_deduplicates_source_repository() -> None:
    assert _distinct_homepage(
        "https://github.com/Example/Project/",
        "https://github.com/example/project.git",
    ) is None
    assert _distinct_homepage(
        "https://docs.example.com/project",
        "https://github.com/example/project",
    ) == "https://docs.example.com/project"


def test_scanner_cannot_overwrite_existing_author_homepage() -> None:
    repository = _VersionRepository(
        {
            "author": {"url": "https://github.com/user-selected"},
            "field_source": {"author.url": "auto"},
        }
    )

    _backfill_author_license(
        repository,  # type: ignore[arg-type]
        "version-1",
        {
            "author": {
                "name": "Scanner Name",
                "url": "https://github.com/scanner-value",
            }
        },
    )

    assert repository.updates == [
        {
            "author": {
                "url": "https://github.com/user-selected",
                "name": "Scanner Name",
            }
        }
    ]


def test_manually_cleared_author_homepage_stays_empty_after_scan() -> None:
    repository = _VersionRepository(
        {
            "author": None,
            "field_source": {"author.url": "manual"},
        }
    )

    _backfill_author_license(
        repository,  # type: ignore[arg-type]
        "version-1",
        {
            "author": {
                "name": "Scanner Name",
                "url": "https://github.com/scanner-value",
            }
        },
    )

    assert repository.updates == [{"author": {"name": "Scanner Name"}}]


def test_scanner_placeholders_are_never_backfilled() -> None:
    repository = _VersionRepository({"author": None, "license": None})

    _backfill_author_license(
        repository,  # type: ignore[arg-type]
        "version-1",
        {
            "author": {
                "name": "UNKNOWN",
                "email": "unknown@unknown.org",
                "url": "https://github.com/unknown/demo",
            },
            "license": "UNLICENSED",
        },
    )

    assert repository.updates == []
