"""Database-level persistence contract tests."""

import os
from collections.abc import Iterator
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError

from src.database import create_engine_from_url


API_ROOT = Path(__file__).resolve().parents[1]
BUSINESS_TABLES = {
    "packages",
    "package_versions",
    "trust_levels",
    "install_records",
    "feedback_records",
}
PRODUCER_TABLES = {
    "users",
    "scan_reports",
    "review_records",
    "audit_logs",
}


def _alembic_config(database_url: str) -> Config:
    config = Config(str(API_ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


@pytest.fixture
def migrated_sqlite_engine(tmp_path: Path) -> Iterator[Engine]:
    database_path = tmp_path / "consumer.db"
    database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"
    command.upgrade(_alembic_config(database_url), "head")
    engine = create_engine_from_url(database_url)
    yield engine
    engine.dispose()


def test_migration_foreign_keys_reference_parents_with_cascade(
    migrated_sqlite_engine: Engine,
) -> None:
    inspector = inspect(migrated_sqlite_engine)

    expected_foreign_keys = {
        "package_versions": ("package_id", "packages", "id"),
        "trust_levels": ("version_id", "package_versions", "id"),
        "install_records": ("version_id", "package_versions", "id"),
        "feedback_records": ("package_id", "packages", "id"),
    }
    for table_name, (column, parent_table, parent_column) in expected_foreign_keys.items():
        foreign_keys = inspector.get_foreign_keys(table_name)
        assert len(foreign_keys) == 1
        foreign_key = foreign_keys[0]
        assert foreign_key["constrained_columns"] == [column]
        assert foreign_key["referred_table"] == parent_table
        assert foreign_key["referred_columns"] == [parent_column]
        assert foreign_key["options"]["ondelete"] == "CASCADE"


def test_migrated_sqlite_rejects_orphan_install(
    migrated_sqlite_engine: Engine,
) -> None:
    with migrated_sqlite_engine.begin() as connection:
        with pytest.raises(IntegrityError):
            connection.execute(
                text(
                    """
                    INSERT INTO install_records
                        (id, version_id, user_id, client, install_path,
                         integrity_verified, installed_at)
                    VALUES
                        ('install-1', 'missing-version', 'user-1', 'codex',
                         '/tmp/skill', 1, CURRENT_TIMESTAMP)
                    """
                )
            )


def test_migration_check_rejects_invalid_feedback_level(
    migrated_sqlite_engine: Engine,
) -> None:
    with migrated_sqlite_engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO packages (id, name, status, latest_version, data)
                VALUES ('package-1', 'package-one', 'published', '1.0.0', '{}')
                """
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                text(
                    """
                    INSERT INTO feedback_records
                        (id, package_id, user_id, level, comment,
                         created_at, updated_at)
                    VALUES
                        ('feedback-1', 'package-1', 'user-1', 'excellent', NULL,
                         CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                    """
                )
            )


def test_migration_check_rejects_invalid_trust_level(
    migrated_sqlite_engine: Engine,
) -> None:
    with migrated_sqlite_engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO packages (id, name, status, latest_version, data)
                VALUES ('package-1', 'package-one', 'published', '1.0.0', '{}')
                """
            )
        )
        connection.execute(
            text(
                """
                INSERT INTO package_versions (id, package_id, version, status, data)
                VALUES ('version-1', 'package-1', '1.0.0', 'published', '{}')
                """
            )
        )
        with pytest.raises(IntegrityError):
            connection.execute(
                text(
                    """
                    INSERT INTO trust_levels
                        (version_id, level, install_recommendation, top_risks,
                         explanation, model_version, calculated_at)
                    VALUES
                        ('version-1', 'unknown', 'review', '[]', NULL, 'v1',
                         CURRENT_TIMESTAMP)
                    """
                )
            )


def test_alembic_upgrade_head_creates_exact_consumer_schema(
    migrated_sqlite_engine: Engine,
) -> None:
    inspector = inspect(migrated_sqlite_engine)
    assert set(inspector.get_table_names()) - {"alembic_version"} == (
        BUSINESS_TABLES | PRODUCER_TABLES
    )

    assert {
        constraint["name"]
        for constraint in inspector.get_unique_constraints("package_versions")
    } == {"uq_package_version"}
    assert {
        constraint["name"]
        for constraint in inspector.get_unique_constraints("install_records")
    } == {"uq_install_idempotency"}
    assert {
        constraint["name"]
        for constraint in inspector.get_unique_constraints("feedback_records")
    } == {"uq_feedback_user_package"}
    assert {
        constraint["name"]
        for constraint in inspector.get_check_constraints("trust_levels")
    } == {"ck_trust_levels_level"}
    assert {
        constraint["name"]
        for constraint in inspector.get_check_constraints("feedback_records")
    } == {"ck_feedback_records_level"}

    expected_indexes = {
        "packages": {"ix_packages_name", "ix_packages_status"},
        "package_versions": {
            "ix_package_versions_package_id",
            "ix_package_versions_status",
            "ix_package_versions_version",
        },
        "trust_levels": {"ix_trust_levels_level"},
        "install_records": {
            "ix_install_records_client",
            "ix_install_records_user_id",
            "ix_install_records_version_id",
        },
        "feedback_records": {
            "ix_feedback_records_level",
            "ix_feedback_records_package_id",
            "ix_feedback_records_user_id",
        },
    }
    for table_name, index_names in expected_indexes.items():
        assert {index["name"] for index in inspector.get_indexes(table_name)} == index_names


def test_postgresql_migration_smoke() -> None:
    database_url = os.getenv("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("TEST_DATABASE_URL is not configured")
    if make_url(database_url).get_backend_name() != "postgresql":
        pytest.skip("TEST_DATABASE_URL is not a PostgreSQL URL")

    command.upgrade(_alembic_config(database_url), "head")

    engine = create_engine_from_url(database_url)
    try:
        assert BUSINESS_TABLES.issubset(set(inspect(engine).get_table_names()))
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql://user:pass@localhost/db",
        "postgres://user:pass@localhost/db",
    ],
)
def test_standard_postgresql_urls_select_psycopg_driver(database_url: str) -> None:
    engine = create_engine_from_url(database_url)
    try:
        assert engine.dialect.name == "postgresql"
        assert engine.dialect.driver == "psycopg"
    finally:
        engine.dispose()


def test_explicit_postgresql_driver_is_preserved() -> None:
    from src.database import normalize_database_url

    normalized = normalize_database_url(
        "postgresql+asyncpg://user:pass@localhost/db"
    )

    assert normalized.drivername == "postgresql+asyncpg"


def test_alembic_upgrade_reads_database_url_from_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "environment.db"
    monkeypatch.setenv(
        "DATABASE_URL",
        f"sqlite+pysqlite:///{database_path.as_posix()}",
    )

    command.upgrade(Config(str(API_ROOT / "alembic.ini")), "head")

    engine = create_engine_from_url(
        f"sqlite+pysqlite:///{database_path.as_posix()}"
    )
    try:
        assert BUSINESS_TABLES.issubset(set(inspect(engine).get_table_names()))
    finally:
        engine.dispose()


def test_explicit_alembic_url_takes_precedence_over_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    explicit_path = tmp_path / "explicit.db"
    environment_path = tmp_path / "environment.db"
    monkeypatch.setenv(
        "DATABASE_URL",
        f"sqlite+pysqlite:///{environment_path.as_posix()}",
    )

    command.upgrade(
        _alembic_config(
            f"sqlite+pysqlite:///{explicit_path.as_posix()}"
        ),
        "head",
    )

    explicit_engine = create_engine_from_url(
        f"sqlite+pysqlite:///{explicit_path.as_posix()}"
    )
    try:
        assert BUSINESS_TABLES.issubset(
            set(inspect(explicit_engine).get_table_names())
        )
        assert not environment_path.exists()
    finally:
        explicit_engine.dispose()


def test_built_wheel_contains_and_executes_migrations(tmp_path: Path) -> None:
    wheel_dir = tmp_path / "wheel"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            ".",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheel_dir),
        ],
        cwd=API_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    wheel_path = next(wheel_dir.glob("*.whl"))

    with zipfile.ZipFile(wheel_path) as wheel:
        names = set(wheel.namelist())
        assert "src/migrations/env.py" in names
        assert "src/migrations/script.py.mako" in names
        assert any(
            name.startswith("src/migrations/versions/")
            and name.endswith("_consumer_persistence.py")
            for name in names
        )
        unpacked = tmp_path / "unpacked"
        wheel.extractall(unpacked)

    database_path = tmp_path / "wheel.db"
    environment = os.environ.copy()
    environment["DATABASE_URL"] = (
        f"sqlite+pysqlite:///{database_path.as_posix()}"
    )
    environment["PYTHONPATH"] = str(unpacked)
    subprocess.run(
        [sys.executable, "-m", "src.migrations"],
        cwd=tmp_path,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )

    engine = create_engine_from_url(
        f"sqlite+pysqlite:///{database_path.as_posix()}"
    )
    try:
        assert BUSINESS_TABLES.issubset(set(inspect(engine).get_table_names()))
    finally:
        engine.dispose()
