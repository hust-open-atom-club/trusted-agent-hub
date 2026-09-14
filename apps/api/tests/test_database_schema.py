"""Database-level persistence contract tests."""

import contextlib
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
import io
import os
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError

from src.database import create_engine_from_url
from src.sql import CLEANUP_REFRESH_TOKENS_SQL


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
    "refresh_tokens",
    "scan_reports",
    "scan_tasks",
    "review_records",
    "audit_logs",
}


def _alembic_config(database_url: str) -> Config:
    config = Config(str(API_ROOT / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def test_migration_graph_has_single_base_and_head() -> None:
    script = ScriptDirectory.from_config(_alembic_config("sqlite+pysqlite:///:memory:"))
    assert script.get_bases() == ["20260826_0001"]
    assert script.get_heads() == ["20260913_0001"]
    assert [revision.revision for revision in script.walk_revisions()] == [
        "20260913_0001",
        "20260912_0002",
        "20260912_0001",
        "20260910_0001",
        "20260908_0002",
        "20260908_0001",
        "20260826_0011",
        "20260826_0010",
        "20260826_0001",
    ]


@pytest.fixture
def migrated_sqlite_engine(tmp_path: Path) -> Iterator[Engine]:
    database_path = tmp_path / "consumer.db"
    database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"
    command.upgrade(_alembic_config(database_url), "head")
    engine = create_engine_from_url(database_url)
    yield engine
    engine.dispose()


def test_short_session_migration_invalidates_existing_sessions(tmp_path: Path) -> None:
    database_path = tmp_path / "existing-sessions.db"
    database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"
    config = _alembic_config(database_url)
    command.upgrade(config, "20260908_0002")

    engine = create_engine_from_url(database_url)
    now = datetime.now(timezone.utc)
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO users
                    (id, email, password_hash, role, display_name,
                     auth_version, is_active, created_at)
                VALUES
                    (:id, :email, :password_hash, :role, :display_name,
                     :auth_version, :is_active, :created_at)
                """
            ),
            {
                "id": "user-existing-session",
                "email": "existing-session@example.com",
                "password_hash": "hash",
                "role": "user",
                "display_name": "Existing Session",
                "auth_version": 4,
                "is_active": True,
                "created_at": now,
            },
        )
        connection.execute(
            text(
                """
                INSERT INTO refresh_tokens
                    (jti, user_id, expires_at, used_at, created_at)
                VALUES
                    (:jti, :user_id, :expires_at, NULL, :created_at)
                """
            ),
            {
                "jti": "existing-refresh-token",
                "user_id": "user-existing-session",
                "expires_at": now + timedelta(days=7),
                "created_at": now,
            },
        )
    engine.dispose()

    command.upgrade(config, "head")

    engine = create_engine_from_url(database_url)
    with engine.connect() as connection:
        auth_version = connection.scalar(
            text(
                "SELECT auth_version FROM users "
                "WHERE id = 'user-existing-session'"
            )
        )
        refresh_count = connection.scalar(text("SELECT COUNT(*) FROM refresh_tokens"))
    engine.dispose()

    assert auth_version == 5
    assert refresh_count == 0


def test_refresh_token_cleanup_sql_preserves_valid_sessions(
    migrated_sqlite_engine: Engine,
) -> None:
    now = datetime.now(timezone.utc)

    with migrated_sqlite_engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO users
                    (id, email, password_hash, role, display_name,
                     auth_version, is_active, created_at)
                VALUES
                    (:id, :email, :password_hash, :role, :display_name,
                     0, :is_active, :created_at)
                """
            ),
            {
                "id": "user-cleanup",
                "email": "cleanup@example.com",
                "password_hash": "hash",
                "role": "user",
                "display_name": "Cleanup User",
                "is_active": True,
                "created_at": now,
            },
        )
        connection.execute(
            text(
                """
                INSERT INTO refresh_tokens
                    (jti, user_id, expires_at, used_at, created_at)
                VALUES
                    (:jti, :user_id, :expires_at, :used_at, :created_at)
                """
            ),
            [
                {
                    "jti": "valid-token",
                    "user_id": "user-cleanup",
                    "expires_at": now + timedelta(hours=1),
                    "used_at": None,
                    "created_at": now,
                },
                {
                    "jti": "expired-token",
                    "user_id": "user-cleanup",
                    "expires_at": now - timedelta(minutes=1),
                    "used_at": None,
                    "created_at": now,
                },
                {
                    "jti": "used-token",
                    "user_id": "user-cleanup",
                    "expires_at": now + timedelta(hours=1),
                    "used_at": now,
                    "created_at": now,
                },
            ],
        )
        connection.execute(text(CLEANUP_REFRESH_TOKENS_SQL))
        remaining_tokens = set(
            connection.scalars(text("SELECT jti FROM refresh_tokens"))
        )

    assert remaining_tokens == {"valid-token"}


def test_migration_foreign_keys_reference_parents_with_expected_delete_behavior(
    migrated_sqlite_engine: Engine,
) -> None:
    inspector = inspect(migrated_sqlite_engine)

    expected_foreign_keys = {
        "package_versions": [("package_id", "packages", "id", "CASCADE")],
        "trust_levels": [("version_id", "package_versions", "id", "CASCADE")],
        "install_records": [("version_id", "package_versions", "id", "CASCADE")],
        "feedback_records": [("package_id", "packages", "id", "CASCADE")],
        "review_records": [("version_id", "package_versions", "id", "CASCADE")],
        "scan_reports": [("version_id", "package_versions", "id", "CASCADE")],
        "refresh_tokens": [("user_id", "users", "id", "CASCADE")],
        "scan_tasks": [
            ("owner_user_id", "users", "id", "CASCADE"),
            ("version_id", "package_versions", "id", "SET NULL"),
        ],
    }
    for table_name, expected in expected_foreign_keys.items():
        foreign_keys = inspector.get_foreign_keys(table_name)
        actual = {
            (
                foreign_key["constrained_columns"][0],
                foreign_key["referred_table"],
                foreign_key["referred_columns"][0],
                foreign_key["options"]["ondelete"],
            )
            for foreign_key in foreign_keys
        }
        assert actual == set(expected)


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


def test_alembic_upgrade_head_creates_exact_schema(
    migrated_sqlite_engine: Engine,
) -> None:
    inspector = inspect(migrated_sqlite_engine)
    assert set(inspector.get_table_names()) - {"alembic_version"} == (
        BUSINESS_TABLES | PRODUCER_TABLES
    )

    expected_columns = {
        "packages": {
            "id", "name", "status", "latest_version", "data",
        },
        "package_versions": {
            "id", "package_id", "version", "status", "data",
            "manual_grade", "manual_grade_by", "manual_grade_at",
            "manual_grade_reason",
        },
        "trust_levels": {
            "version_id", "level", "install_recommendation", "top_risks",
            "explanation", "model_version", "model_fingerprint", "calculated_at",
        },
        "install_records": {
            "id", "version_id", "user_id", "client", "event_id",
            "install_path", "integrity_verified", "installed_at",
        },
        "feedback_records": {
            "id", "package_id", "user_id", "level", "comment",
            "created_at", "updated_at",
        },
        "users": {
            "id", "email", "password_hash", "role", "display_name",
            "auth_version", "is_active", "created_at",
        },
        "refresh_tokens": {
            "jti", "user_id", "expires_at", "used_at", "created_at",
        },
        "review_records": {
            "id", "version_id", "reviewer_id", "conclusion", "comment",
            "created_at",
        },
        "scan_reports": {"version_id", "scan_json", "report_path", "scanned_at"},
        "scan_tasks": {
            "id", "owner_user_id", "client_request_id", "repo_url",
            "dedup_repo_url",
            "source_ref", "commit_hash", "source_subdirectory", "version_id",
            "status", "package_name", "created_at", "updated_at", "finished_at",
            "lease_token", "lease_until", "attempt_count",
            "completion_delivered_at", "callback_status",
            "callback_attempt_count", "callback_next_attempt_at",
            "callback_last_error", "expires_at", "summary", "trust_score",
            "llm_review", "metadata_json", "capabilities", "report_json",
            "error",
        },
        "audit_logs": {
            "id", "action", "target_type", "target_id", "operator_id",
            "detail", "timestamp",
        },
    }
    for table_name, column_names in expected_columns.items():
        assert {column["name"] for column in inspector.get_columns(table_name)} == column_names

    expected_nullable = {
        "users": {
            "email": False,
            "display_name": False,
            "is_active": False,
        },
        "refresh_tokens": {
            "jti": False,
            "user_id": False,
            "expires_at": False,
            "used_at": True,
            "created_at": False,
        },
        "install_records": {
            "user_id": True,
            "event_id": False,
            "install_path": True,
        },
        "scan_tasks": {
            "id": False,
            "owner_user_id": False,
            "client_request_id": False,
            "repo_url": False,
            "dedup_repo_url": False,
            "source_ref": True,
            "commit_hash": True,
            "source_subdirectory": True,
            "version_id": True,
            "status": False,
            "package_name": True,
            "created_at": False,
            "updated_at": False,
            "lease_token": True,
            "lease_until": True,
            "attempt_count": False,
            "completion_delivered_at": True,
            "callback_status": True,
            "callback_attempt_count": False,
            "callback_next_attempt_at": True,
            "callback_last_error": True,
            "finished_at": True,
            "expires_at": True,
            "summary": True,
            "trust_score": True,
            "llm_review": True,
            "metadata_json": True,
            "capabilities": True,
            "report_json": True,
            "error": True,
        },
    }
    for table_name, column_nullability in expected_nullable.items():
        actual_nullability = {
            column["name"]: column["nullable"]
            for column in inspector.get_columns(table_name)
            if column["name"] in column_nullability
        }
        assert actual_nullability == column_nullability

    assert {
        constraint["name"]
        for constraint in inspector.get_check_constraints("trust_levels")
    } == {"ck_trust_levels_level"}
    assert {
        constraint["name"]
        for constraint in inspector.get_check_constraints("feedback_records")
    } == {"ck_feedback_records_level"}

    expected_unique_constraints = {
        "package_versions": {"uq_package_version"},
        "install_records": {"uq_install_event_id"},
        "feedback_records": {"uq_feedback_user_package"},
        "users": {"uq_users_email"},
        # scan_tasks: only the plain unique constraint is assertable here.
        # The source-identity index is expression-based (COALESCE(...));
        # SQLite skips reflecting expression indexes entirely (and the
        # SQLite dialect also cannot query them via PRAGMA), so a separate
        # functional test covers the uniqueness behavior instead.
        "scan_tasks": {
            "uq_scan_tasks_owner_request",
        },
    }
    for table_name, constraint_names in expected_unique_constraints.items():
        assert {
            constraint["name"]
            for constraint in inspector.get_unique_constraints(table_name)
        } == constraint_names

    expected_indexes = {
        "packages": {"ix_packages_name", "ix_packages_status"},
        "package_versions": {
            "ix_package_versions_manual_grade",
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
        "users": {"ix_users_role"},
        "refresh_tokens": {
            "ix_refresh_tokens_expires_at",
            "ix_refresh_tokens_used_at",
            "ix_refresh_tokens_user_id",
        },
        "review_records": {
            "ix_review_records_conclusion",
            "ix_review_records_version_id",
        },
        "scan_reports": set(),
        "scan_tasks": {
            "ix_scan_tasks_expires_at",
            "ix_scan_tasks_lease_until",
            "ix_scan_tasks_owner_user_id",
            "ix_scan_tasks_status",
            "ix_scan_tasks_version_id",
            "ix_scan_tasks_callback_next_attempt_at",
        },
        "audit_logs": {"ix_audit_logs_target", "ix_audit_logs_timestamp"},
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
        assert "src/sql/cleanup_refresh_tokens.sql" in names
        assert "src/sql/cleanup_scan_tasks.sql" in names
        migration_files = {
            name.removeprefix("src/migrations/versions/")
            for name in names
            if name.startswith("src/migrations/versions/") and name.endswith(".py")
        }
        assert migration_files == {
            "__init__.py",
            "20260826_0001_initial_schema.py",
            "20260826_0010_migrate_legacy_hash_complete.py",
            "20260826_0011_add_trust_model_fingerprint.py",
            "20260908_0001_add_user_auth_version.py",
            "20260908_0002_add_refresh_token_store.py",
            "20260910_0001_enforce_short_sessions.py",
            "20260912_0001_add_scan_tasks.py",
            "20260912_0002_add_scan_identity_and_callback_delivery.py",
            "20260913_0001_add_scan_dedup_identity.py",
        }
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




def _seed_scan_task_owner(connection) -> None:
    connection.execute(
        text(
            """
            INSERT INTO users
                (id, email, password_hash, role, display_name,
                 auth_version, is_active, created_at)
            VALUES
                (:id, :email, :password_hash, :role, :display_name,
                 :auth_version, :is_active, :created_at)
            """
        ),
        {
            "id": "scan-user-seed",
            "email": "scan-user-seed@example.com",
            "password_hash": "hash",
            "role": "submitter",
            "display_name": "Scan Seed",
            "auth_version": 4,
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
        },
    )
def _seed_scan_task_row(
    connection,
    *,
    task_id: str,
    request_id: str,
    repo_url: str,
    created_at: datetime,
    status: str = "complete",
    version_id=None,
    callback_status=None,
) -> None:
    connection.execute(
        text(
            """
            INSERT INTO scan_tasks
                (id, owner_user_id, client_request_id, repo_url,
                 version_id, status, created_at, updated_at,
                 attempt_count, callback_status)
            VALUES
                (:id, :owner_user_id, :client_request_id, :repo_url,
                 :version_id, :status, :created_at, :created_at,
                 0, :callback_status)
            """
        ),
        {
            "id": task_id,
            "owner_user_id": "scan-user-seed",
            "client_request_id": request_id,
            "repo_url": repo_url,
            "version_id": version_id,
            "status": status,
            "created_at": created_at,
            "callback_status": callback_status,
        },
    )


def test_dedup_migration_keeps_attached_row_and_cleans_detached_duplicates(
    tmp_path: Path,
) -> None:
    """The 20260913_0001 backfill prefers a version-attached row as keeper.

    Pre-dedup deployments could hold a version-attached duplicate next to
    detached standalone duplicates. The attached row wins the keeper slot
    (the review workflow depends on it); the detached terminal rows are
    cleaned automatically. No data the review workflow needs is deleted.
    """
    database_path = tmp_path / "dedup-backfill.db"
    database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"
    config = _alembic_config(database_url)
    command.upgrade(config, "20260912_0002")

    engine = create_engine_from_url(database_url)
    now = datetime.now(timezone.utc)
    try:
        with engine.begin() as connection:
            _seed_scan_task_owner(connection)
            # A version row the attached duplicate points at.
            connection.execute(
                text(
                    "INSERT INTO packages (id, name, status, "
                    "latest_version, data) VALUES "
                    "(:pkg_id, :pkg_name, :pkg_status, :pkg_version, :pkg_data)"
                ),
                {
                    "pkg_id": "pkg-dedup",
                    "pkg_name": "pkg-dedup",
                    "pkg_status": "draft",
                    "pkg_version": "1.0.0",
                    "pkg_data": "{}",
                },
            )
            connection.execute(
                text(
                    "INSERT INTO package_versions (id, package_id, "
                    "version, status, data) VALUES "
                    "(:version_id, :package_id, :version_name, "
                    ":version_status, :version_data)"
                ),
                {
                    "version_id": "version-dedup",
                    "package_id": "pkg-dedup",
                    "version_name": "1.0.0",
                    "version_status": "scanning",
                    "version_data": "{}",
                },
            )
            # Detached standalone duplicates: safe to clean.
            _seed_scan_task_row(
                connection,
                task_id="scan-keep",
                request_id="request-keep",
                repo_url="https://github.com/AcMe/Demo.git",
                created_at=now - timedelta(minutes=10),
            )
            _seed_scan_task_row(
                connection,
                task_id="scan-detached-dup",
                request_id="request-detached-dup",
                repo_url="https://github.com/acme/demo/",
                created_at=now - timedelta(minutes=5),
            )
            # Version-attached task with a pending callback: becomes the
            # keeper even though its id sorts last.
            _seed_scan_task_row(
                connection,
                task_id="scan-attached",
                request_id="request-attached",
                repo_url="https://github.com/acme/demo",
                created_at=now - timedelta(minutes=1),
                version_id="version-dedup",
                callback_status="pending",
            )
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_engine_from_url(database_url)
    try:
        with engine.connect() as connection:
            rows = connection.execute(
                text(
                    "SELECT id, dedup_repo_url, version_id "
                    "FROM scan_tasks"
                )
            ).fetchall()
            # The attached row survived as the keeper; both detached
            # duplicates were removed and every spelling normalized to
            # the same dedup key.
            assert rows == [
                ("scan-attached", "https://github.com/acme/demo",
                 "version-dedup"),
            ]
    finally:
        engine.dispose()


def test_dedup_migration_aborts_when_two_attached_tasks_share_a_source(
    tmp_path: Path,
) -> None:
    """Two version-attached duplicates cannot be resolved automatically.

    Deleting either row would break that version scan-task lookup, so
    the migration must abort (rolling back all changes) and leave the
    decision to an operator.
    """
    database_path = tmp_path / "dedup-attached-conflict.db"
    database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"
    config = _alembic_config(database_url)
    command.upgrade(config, "20260912_0002")

    engine = create_engine_from_url(database_url)
    now = datetime.now(timezone.utc)
    try:
        with engine.begin() as connection:
            _seed_scan_task_owner(connection)
            for suffix in ("one", "two"):
                connection.execute(
                    text(
                        "INSERT INTO packages (id, name, status, "
                        "latest_version, data) VALUES "
                        "(:pkg_id, :pkg_name, :pkg_status, "
                        ":pkg_version, :pkg_data)"
                    ),
                    {
                        "pkg_id": f"pkg-dedup-{suffix}",
                        "pkg_name": f"pkg-dedup-{suffix}",
                        "pkg_status": "draft",
                        "pkg_version": "1.0.0",
                        "pkg_data": "{}",
                    },
                )
                connection.execute(
                    text(
                        "INSERT INTO package_versions (id, package_id, "
                        "version, status, data) VALUES "
                        "(:version_id, :package_id, :version_name, "
                        ":version_status, :version_data)"
                    ),
                    {
                        "version_id": f"version-dedup-{suffix}",
                        "package_id": f"pkg-dedup-{suffix}",
                        "version_name": "1.0.0",
                        "version_status": "scanning",
                        "version_data": "{}",
                    },
                )
            _seed_scan_task_row(
                connection,
                task_id="scan-attached-one",
                request_id="request-attached-one",
                repo_url="https://github.com/acme/demo",
                created_at=now - timedelta(minutes=10),
                version_id="version-dedup-one",
                callback_status="pending",
            )
            _seed_scan_task_row(
                connection,
                task_id="scan-attached-two",
                request_id="request-attached-two",
                repo_url="https://github.com/ACME/Demo.git",
                created_at=now - timedelta(minutes=5),
                version_id="version-dedup-two",
                callback_status="pending",
            )
    finally:
        engine.dispose()

    with pytest.raises(RuntimeError, match="retained duplicate scan tasks"):
        command.upgrade(config, "head")

    # The failed migration rolled back the data: both attached rows are
    # intact and the version stamp did not advance, so a rerun after
    # manual resolution re-applies the migration cleanly. (SQLite ADD
    # COLUMN is non-transactional DDL, so the column itself may remain;
    # what matters is that no data was destroyed.)
    engine = create_engine_from_url(database_url)
    try:
        with engine.connect() as connection:
            ids = {
                row[0]
                for row in connection.execute(
                    text("SELECT id FROM scan_tasks")
                )
            }
            assert ids == {"scan-attached-one", "scan-attached-two"}
            version = connection.scalar(
                text("SELECT version_num FROM alembic_version")
            )
            assert version == "20260912_0002"
    finally:
        engine.dispose()


def test_dedup_migration_succeeds_when_only_detached_duplicates_exist(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "dedup-clean.db"
    database_url = f"sqlite+pysqlite:///{database_path.as_posix()}"
    config = _alembic_config(database_url)
    command.upgrade(config, "20260912_0002")

    engine = create_engine_from_url(database_url)
    now = datetime.now(timezone.utc)
    try:
        with engine.begin() as connection:
            _seed_scan_task_owner(connection)
            _seed_scan_task_row(
                connection,
                task_id="scan-first",
                request_id="request-first",
                repo_url="https://github.com/acme/demo",
                created_at=now - timedelta(minutes=10),
            )
            _seed_scan_task_row(
                connection,
                task_id="scan-second",
                request_id="request-second",
                repo_url="https://github.com/ACME/Demo.git/",
                created_at=now - timedelta(minutes=5),
            )
    finally:
        engine.dispose()

    command.upgrade(config, "head")

    engine = create_engine_from_url(database_url)
    try:
        with engine.connect() as connection:
            rows = connection.execute(
                text("SELECT id, dedup_repo_url FROM scan_tasks")
            ).fetchall()
            # The earliest row is kept and both URL spellings normalize
            # to the same dedup key.
            assert rows == [("scan-first", "https://github.com/acme/demo")]
    finally:
        engine.dispose()

def test_dedup_migration_offline_mode_emits_ddl_without_backfill(
    tmp_path: Path,
) -> None:
    """``alembic upgrade --sql`` cannot inspect data, so it emits DDL only.

    Offline mode must not silently run the duplicate cleanup (it has no
    rows to inspect) and must not crash; an operator upgrading an existing
    database offline has to backfill first, which the migration documents.
    """
    database_url = f"sqlite+pysqlite:///{(tmp_path / 'offline.db').as_posix()}"
    config = _alembic_config(database_url)
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        command.upgrade(config, "head", sql=True)
    emitted = buffer.getvalue()
    assert "dedup_repo_url" in emitted
    assert "uq_scan_tasks_source_identity" in emitted
    assert "DELETE FROM scan_tasks" not in emitted


def test_cleanup_scan_tasks_sql_deletes_only_eligible_rows() -> None:
    sql = (API_ROOT / "src" / "sql" / "cleanup_scan_tasks.sql").read_text(
        encoding="utf-8"
    )
    engine = create_engine_from_url("sqlite+pysqlite:///:memory:")
    rows = [
        {
            "id": "active",
            "status": "scanning",
            "expires_at": "2000-01-01 00:00:00",
            "version_id": None,
            "callback_status": "not_required",
        },
        {
            "id": "failed_pending",
            "status": "error",
            "expires_at": "2999-01-01 00:00:00",
            "version_id": "version-pending",
            "callback_status": "pending",
        },
        {
            "id": "failed_delivered",
            "status": "error",
            "expires_at": "2000-01-01 00:00:00",
            "version_id": None,
            "callback_status": "delivered",
        },
        {
            "id": "complete_detached",
            "status": "complete",
            "expires_at": "2000-01-01 00:00:00",
            "version_id": None,
            "callback_status": "not_required",
        },
        {
            "id": "complete_attached",
            "status": "complete",
            "expires_at": "2000-01-01 00:00:00",
            "version_id": "version-complete",
            "callback_status": "delivered",
        },
        {
            "id": "expired_callback_pending",
            "status": "total_timeout",
            "expires_at": "2000-01-01 00:00:00",
            "version_id": "version-timeout",
            "callback_status": "pending",
        },
    ]
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE scan_tasks ("
                    "id TEXT PRIMARY KEY, status TEXT NOT NULL, "
                    "expires_at TIMESTAMP, version_id TEXT, "
                    "callback_status TEXT)"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO scan_tasks "
                    "(id, status, expires_at, version_id, callback_status) "
                    "VALUES (:id, :status, :expires_at, :version_id, "
                    ":callback_status)"
                ),
                rows,
            )
            connection.execute(text(sql))
            remaining = set(
                connection.scalars(text("SELECT id FROM scan_tasks")).all()
            )
    finally:
        engine.dispose()

    all_ids = {str(row["id"]) for row in rows}
    assert all_ids - remaining == {"failed_delivered", "complete_detached"}
