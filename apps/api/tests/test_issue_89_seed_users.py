from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from src.auth import verify_password
from src.database import create_engine_from_url, create_session_factory
from src.repositories.orm_producer import UserRow
from src.scripts.seed_producer import seed_users
from src.settings import REPOSITORY_ROOT, Settings


def test_seed_producer_imports_from_documented_working_directory() -> None:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)

    completed = subprocess.run(
        [sys.executable, "-c", "import src.scripts.seed_producer"],
        cwd=REPOSITORY_ROOT / "apps" / "api",
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


def test_seed_users_creates_configured_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database_url = f"sqlite+pysqlite:///{(tmp_path / 'seed.db').as_posix()}"
    config = Config(str(REPOSITORY_ROOT / "apps" / "api" / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")
    settings = Settings(
        database_url=database_url,
        seed_submitter_email="Seed-Submit@Example.com",
        seed_submitter_password="seed-password",
    )
    monkeypatch.setattr("src.scripts.seed_producer.get_settings", lambda: settings)

    assert seed_users() == 1
    assert seed_users() == 0

    engine = create_engine_from_url(database_url)
    session = create_session_factory(engine)()
    try:
        user = session.scalar(
            select(UserRow).where(UserRow.email == "seed-submit@example.com")
        )
        assert user is not None
        assert user.role == "submitter"
        assert verify_password("seed-password", user.password_hash)
    finally:
        session.close()
        engine.dispose()
