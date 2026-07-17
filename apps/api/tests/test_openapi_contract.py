from __future__ import annotations

import copy
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from src.main import create_app
from src.scripts.export_openapi import build_consumer_openapi, write_snapshot


ROOT = Path(__file__).resolve().parents[3]
SNAPSHOT = ROOT / "packages" / "schema" / "openapi" / "consumer-v0.1.json"
SCHEMA_REF_PREFIX = "#/components/schemas/"
CONSUMER_PATHS = {
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
}


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


def _expected_schema_closure(source: dict[str, Any]) -> set[str]:
    schemas = source["components"]["schemas"]
    pending = {
        schema_name
        for path in CONSUMER_PATHS
        for schema_name in _schema_refs(source["paths"][path])
    }
    closure: set[str] = set()

    while pending:
        schema_name = pending.pop()
        assert schema_name in schemas, f"missing source schema: {schema_name}"
        if schema_name in closure:
            continue
        closure.add(schema_name)
        pending.update(_schema_refs(schemas[schema_name]))

    return closure


def _canonical_json(document: dict[str, Any]) -> str:
    return (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    )


def test_consumer_openapi_contains_exactly_the_canonical_paths() -> None:
    document = build_consumer_openapi(create_app())

    assert list(document) == ["openapi", "info", "paths", "components"]
    assert list(document["paths"]) == sorted(CONSUMER_PATHS)
    assert set(document["paths"]) == CONSUMER_PATHS
    assert not any("/scan" in path for path in document["paths"])
    assert "/api/v0/packages/{name}/install" not in document["paths"]
    assert "/api/v0/trust-scores/{version_id}" not in document["paths"]


def test_feedback_operations_document_stable_error_responses() -> None:
    document = build_consumer_openapi(create_app())
    paths = document["paths"]

    assert set(paths["/api/v0/packages/{name}/feedback"]["post"]["responses"]) == {
        "200",
        "201",
        "401",
        "404",
        "422",
        "503",
    }
    assert set(paths["/api/v0/packages/{name}/feedback"]["get"]["responses"]) == {
        "200",
        "404",
        "422",
        "503",
    }
    assert set(paths["/api/v0/versions/{version_id}/trust-level"]["get"]["responses"]) == {
        "200",
        "404",
        "422",
        "503",
    }
    schemas = document["components"]["schemas"]
    assert "score" not in schemas["FeedbackRequest"].get("properties", {})
    assert "score" not in schemas["TrustLevelResponse"].get("properties", {})


@pytest.mark.parametrize(
    "path",
    ["/api/v0/installs", "/api/v0/packages/{name}/feedback"],
)
def test_idempotent_posts_document_200_with_the_created_response_model(
    path: str,
) -> None:
    document = build_consumer_openapi(create_app())
    responses = document["paths"][path]["post"]["responses"]

    assert "200" in responses
    assert (
        responses["200"]["content"]["application/json"]["schema"]
        == responses["201"]["content"]["application/json"]["schema"]
    )


def test_consumer_writes_use_bearer_auth_without_exposing_dev_header() -> None:
    document = build_consumer_openapi(create_app())

    assert document["components"]["securitySchemes"] == {
        "bearerAuth": {"type": "http", "scheme": "bearer"}
    }
    assert document["paths"]["/api/v0/installs"]["post"]["security"] == [
        {"bearerAuth": []}
    ]
    assert document["paths"]["/api/v0/packages/{name}/feedback"]["post"][
        "security"
    ] == [{"bearerAuth": []}]
    assert "x-user-id" not in json.dumps(document).lower()


def test_committed_snapshot_exactly_matches_current_consumer_openapi() -> None:
    document = build_consumer_openapi(create_app())
    expected_bytes = _canonical_json(document).encode("utf-8")

    assert json.loads(SNAPSHOT.read_text(encoding="utf-8")) == document
    assert SNAPSHOT.read_bytes() == expected_bytes


def test_consumer_schemas_are_the_exact_resolvable_transitive_closure() -> None:
    app = create_app()
    source = app.openapi()
    document = build_consumer_openapi(app)
    selected_schemas = document["components"]["schemas"]
    expected_schemas = _expected_schema_closure(source)

    assert list(selected_schemas) == sorted(expected_schemas)
    assert set(selected_schemas) == expected_schemas
    assert {"ScanRequest", "ScanResponse", "ScanStatusResponse"}.isdisjoint(
        selected_schemas
    )
    for schema_name in _schema_refs(document):
        assert schema_name in selected_schemas


def test_repeated_builds_are_equal_and_do_not_mutate_cached_source() -> None:
    app = create_app()
    source_before = copy.deepcopy(app.openapi())

    first = build_consumer_openapi(app)
    second = build_consumer_openapi(app)

    assert first == second
    assert app.openapi() == source_before

    first["info"]["title"] = "tampered"
    first["paths"].pop(next(iter(first["paths"])))
    first["components"]["schemas"].pop(
        next(iter(first["components"]["schemas"]))
    )

    assert app.openapi() == source_before
    assert build_consumer_openapi(app) == second


def test_write_snapshot_is_canonical_stable_and_creates_parents(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "nested" / "consumer-v0.1.json"
    expected = _canonical_json(build_consumer_openapi(create_app()))

    write_snapshot(destination)
    first_bytes = destination.read_bytes()
    write_snapshot(destination)

    assert destination.read_bytes() == first_bytes
    assert first_bytes.decode("utf-8") == expected
    assert first_bytes.endswith(b"\n")
    assert not first_bytes.endswith(b"\n\n")


def test_missing_transitive_schema_reference_fails_loudly() -> None:
    app = create_app()
    source = copy.deepcopy(app.openapi())
    source["paths"]["/api/v0/health"]["get"]["responses"]["200"][
        "content"
    ]["application/json"]["schema"] = {
        "$ref": f"{SCHEMA_REF_PREFIX}MissingSchema"
    }
    app.openapi = lambda: source  # type: ignore[method-assign]

    with pytest.raises(KeyError, match="MissingSchema"):
        build_consumer_openapi(app)
