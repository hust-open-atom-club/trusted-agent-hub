"""Author homepage, project homepage, and client-enum regression coverage."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from pydantic import ValidationError

from schema.constants import CLIENTS
from src.models.common import Client, PackageListQuery
from src.models.packages import Author
from src.models.producer import CreatePackageRequest
from src.services.install import CLIENT_INSTALL_ROOTS
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


def test_author_name_and_email_are_optional_legacy_fields() -> None:
    author = Author.model_validate({"url": "https://github.com/example"})

    assert author.model_dump(exclude_none=True) == {
        "url": "https://github.com/example"
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
    skill["author"] = {"url": "https://github.com/alice-dev"}
    skill["compatibility"] = ["codex"]
    skill["installation"]["targets"] = [
        {
            "client": "codex",
            "destination": "~/.codex/skills/code-review-skill/",
        }
    ]

    jsonschema.validate(skill, schema)


def test_json_schema_rejects_codex_for_mcp_server() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    mcp_server = json.loads(
        (SCHEMA_EXAMPLES / "mcp-server-basic.json").read_text(
            encoding="utf-8"
        )
    )
    mcp_server["compatibility"] = ["claude-code"]
    mcp_server["installation"]["targets"] = [
        {
            "client": "codex",
            "destination": "~/.codex/skills/not-supported/",
        }
    ]

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(mcp_server, schema)


def test_api_install_root_for_codex_skills() -> None:
    assert CLIENT_INSTALL_ROOTS["codex"] == "~/.codex/skills/"


def test_create_api_rejects_codex_install_target_for_mcp_server() -> None:
    request = CreatePackageRequest.model_validate(
        {
            "name": "unsupported-codex-mcp",
            "type": "mcp_server",
            "description": "An MCP server with an invalid Codex target.",
            "compatibility": ["claude-code"],
            "installation": {
                "method": "copy_directory",
                "targets": [
                    {
                        "client": "codex",
                        "destination": "~/.codex/skills/not-supported/",
                    }
                ],
            },
        }
    )

    with pytest.raises(ProducerServiceError):
        ProducerService(object()).create_package(request)  # type: ignore[arg-type]


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
