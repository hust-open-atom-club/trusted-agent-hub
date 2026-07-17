"""Export the deterministic Consumer API OpenAPI contract."""

from __future__ import annotations

import copy
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from fastapi import FastAPI

from ..main import create_app


SCHEMA_REF_PREFIX = "#/components/schemas/"
CONSUMER_PATHS = (
    "/api/v0/health",
    "/api/v0/packages",
    "/api/v0/packages/{name}",
    "/api/v0/packages/{name}/versions",
    "/api/v0/packages/{name}/versions/{version}",
    "/api/v0/packages/{name}/install-manifest",
    "/api/v0/installs",
    "/api/v0/packages/{name}/feedback",
    "/api/v0/versions/{version_id}/trust-score",
    "/api/v0/versions/{version_id}/trust-level",
    "/api/v0/stats/packages/{name}",
)
REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_DESTINATION = (
    REPOSITORY_ROOT
    / "packages"
    / "schema"
    / "openapi"
    / "consumer-v0.1.json"
)


def _schema_refs(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if (
                key == "$ref"
                and isinstance(child, str)
                and child.startswith(SCHEMA_REF_PREFIX)
            ):
                yield child.removeprefix(SCHEMA_REF_PREFIX)
            else:
                yield from _schema_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from _schema_refs(child)


def build_consumer_openapi(app: FastAPI) -> dict[str, Any]:
    """Extract the Consumer API and its exact schema dependency closure."""
    source = app.openapi()
    source_paths = source["paths"]
    source_schemas = source.get("components", {}).get("schemas", {})
    selected_paths = {
        path: copy.deepcopy(source_paths[path])
        for path in sorted(CONSUMER_PATHS)
    }

    pending = set(_schema_refs(selected_paths))
    selected_schema_names: set[str] = set()
    while pending:
        schema_name = pending.pop()
        if schema_name in selected_schema_names:
            continue
        if schema_name not in source_schemas:
            raise KeyError(
                f"OpenAPI schema reference not found: {schema_name}"
            )
        selected_schema_names.add(schema_name)
        pending.update(_schema_refs(source_schemas[schema_name]))

    selected_schemas = {
        schema_name: copy.deepcopy(source_schemas[schema_name])
        for schema_name in sorted(selected_schema_names)
    }
    selected_components: dict[str, Any] = {"schemas": selected_schemas}
    security_schemes = source.get("components", {}).get("securitySchemes")
    if security_schemes is not None:
        selected_components["securitySchemes"] = copy.deepcopy(
            security_schemes
        )
    return {
        "openapi": copy.deepcopy(source["openapi"]),
        "info": copy.deepcopy(source["info"]),
        "paths": selected_paths,
        "components": selected_components,
    }


def write_snapshot(destination: Path) -> None:
    """Write the current Consumer API contract as canonical UTF-8 JSON."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    document = build_consumer_openapi(create_app())
    serialized = (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )
    destination.write_text(serialized, encoding="utf-8", newline="\n")


def main() -> None:
    write_snapshot(DEFAULT_DESTINATION)


if __name__ == "__main__":
    main()
