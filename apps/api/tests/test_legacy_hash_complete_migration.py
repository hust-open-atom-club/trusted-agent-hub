"""Regression tests for the legacy integrity marker migration."""

from __future__ import annotations

from copy import deepcopy
import importlib
import json
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import text

from src.database import create_engine_from_url
from src.models.packages import ScanReport, VersionDetail


API_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "migrations"
    / "legacy_hash_complete.json"
)
MIGRATION = importlib.import_module(
    "src.migrations.versions.20260826_0010_migrate_legacy_hash_complete"
)


def _load_fixture() -> dict[str, object]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _alembic_config(database_url: str) -> Config:
    config = Config(str(API_ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def _decode_json(value: object) -> dict[str, object]:
    if isinstance(value, str):
        value = json.loads(value)
    assert isinstance(value, dict)
    return value


def test_normalizer_handles_legacy_mixed_and_unknown_markers() -> None:
    fixture = _load_fixture()
    version_data = deepcopy(fixture["version_data"])
    scan_json = deepcopy(fixture["scan_json"])
    assert isinstance(version_data, dict)
    assert isinstance(scan_json, dict)

    assert MIGRATION._normalize_document(
        version_data,
        MIGRATION._PACKAGE_VERSION_PATHS,
    )
    assert MIGRATION._normalize_document(
        scan_json,
        MIGRATION._SCAN_REPORT_PATHS,
    )

    assert version_data["integrity"]["is_complete"] is True
    assert "hash_complete" not in version_data["integrity"]
    assert version_data["acquisition_facts"]["integrity"]["is_complete"] is False
    assert "hash_complete" not in version_data["acquisition_facts"]["integrity"]
    assert (
        version_data["scan_report"]["provenance"]["acquisition_facts"]
        ["integrity"]["is_complete"]
        is False
    )
    assert (
        "hash_complete"
        not in version_data["scan_report"]["provenance"]["acquisition_facts"]
        ["integrity"]
    )
    assert (
        scan_json["provenance"]["acquisition_facts"]["integrity"]["is_complete"]
        is False
    )
    assert (
        "hash_complete"
        not in scan_json["provenance"]["acquisition_facts"]["integrity"]
    )

    mixed = deepcopy(fixture["mixed_integrity"])
    canonical_null = deepcopy(fixture["canonical_null_integrity"])
    missing = deepcopy(fixture["missing_integrity"])
    assert MIGRATION._normalize_integrity(mixed)
    assert MIGRATION._normalize_integrity(canonical_null)
    assert not MIGRATION._normalize_integrity(missing)
    assert mixed["is_complete"] is False
    assert canonical_null["is_complete"] is False
    assert "hash_complete" not in mixed
    assert "hash_complete" not in canonical_null
    assert "is_complete" not in missing

    normalized_snapshot = deepcopy(version_data)
    assert not MIGRATION._normalize_document(
        version_data,
        MIGRATION._PACKAGE_VERSION_PATHS,
    )
    assert version_data == normalized_snapshot


def test_normalized_records_pass_current_strict_models() -> None:
    version_path = (
        Path(__file__).resolve().parent
        / "fixtures"
        / "mock"
        / "versions"
        / "code-review-skill-1.0.0.json"
    )
    version = json.loads(version_path.read_text(encoding="utf-8"))
    version["integrity"]["hash_complete"] = True
    assert MIGRATION._normalize_document(
        version,
        MIGRATION._PACKAGE_VERSION_PATHS,
    )
    VersionDetail.model_validate(version)

    report = {
        "scan_id": "scan-legacy-marker",
        "scanner_version": "0.3.0",
        "provenance": {
            "acquisition_facts": {
                "source": {},
                "integrity": {
                    "sha256": "a" * 64,
                    "hash_scope": "scanned_source",
                    "hash_complete": True,
                },
                "verification": {
                    "owner": False,
                    "signature": False,
                    "attestation": False,
                    "sbom": False,
                },
                "acquisition_method": "git",
            },
            "package_claims": {},
        },
    }
    assert MIGRATION._normalize_document(
        report,
        MIGRATION._SCAN_REPORT_PATHS,
    )
    ScanReport.model_validate(report)


def test_alembic_migration_rewrites_persisted_json_documents(
    tmp_path: Path,
) -> None:
    fixture = _load_fixture()
    version_data = deepcopy(fixture["version_data"])
    scan_json = deepcopy(fixture["scan_json"])
    mixed = {"integrity": deepcopy(fixture["mixed_integrity"])}
    assert isinstance(version_data, dict)
    assert isinstance(scan_json, dict)
    assert isinstance(mixed, dict)

    database_path = tmp_path / "legacy-marker.db"
    database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"
    config = _alembic_config(database_url)
    command.upgrade(config, "20260826_0001")

    engine = create_engine_from_url(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO packages (id, name, status, latest_version, data)
                    VALUES ('pkg-legacy', 'legacy-package', 'published', '1.0.0', :data)
                    """
                ),
                {"data": json.dumps({})},
            )
            for version_id, data in (
                ("ver-legacy", version_data),
                ("ver-mixed", mixed),
            ):
                connection.execute(
                    text(
                        """
                        INSERT INTO package_versions
                            (id, package_id, version, status, data)
                        VALUES (:id, 'pkg-legacy', :version, 'published', :data)
                        """
                    ),
                    {
                        "id": version_id,
                        "version": "1.0.0" if version_id == "ver-legacy" else "2.0.0",
                        "data": json.dumps(data),
                    },
                )
            connection.execute(
                text(
                    """
                    INSERT INTO scan_reports
                        (version_id, scan_json, report_path, scanned_at)
                    VALUES ('ver-legacy', :scan_json, NULL, CURRENT_TIMESTAMP)
                    """
                ),
                {"scan_json": json.dumps(scan_json)},
            )

        command.upgrade(config, "head")

        with engine.connect() as connection:
            version = _decode_json(
                connection.execute(
                    text("SELECT data FROM package_versions WHERE id = 'ver-legacy'")
                ).scalar_one()
            )
            mixed_after = _decode_json(
                connection.execute(
                    text("SELECT data FROM package_versions WHERE id = 'ver-mixed'")
                ).scalar_one()
            )
            report = _decode_json(
                connection.execute(
                    text("SELECT scan_json FROM scan_reports WHERE version_id = 'ver-legacy'")
                ).scalar_one()
            )

        assert version["integrity"]["is_complete"] is True
        assert "hash_complete" not in version["integrity"]
        assert version["acquisition_facts"]["integrity"]["is_complete"] is False
        assert "hash_complete" not in version["acquisition_facts"]["integrity"]
        assert mixed_after["integrity"]["is_complete"] is False
        assert "hash_complete" not in mixed_after["integrity"]
        assert (
            report["provenance"]["acquisition_facts"]["integrity"]["is_complete"]
            is False
        )
        assert (
            "hash_complete"
            not in report["provenance"]["acquisition_facts"]["integrity"]
        )
    finally:
        engine.dispose()
