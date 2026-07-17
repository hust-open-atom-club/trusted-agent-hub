"""Alembic migration environment."""

from logging.config import fileConfig
import os

from alembic import context

from src.database import Base, create_engine_from_url, normalize_database_url
from src.repositories import orm  # noqa: F401 - registers ORM metadata


config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def configured_database_url() -> str:
    """Resolve and normalize the migration database URL."""
    database_url = config.get_main_option("sqlalchemy.url", "").strip()
    if not database_url:
        database_url = os.getenv("DATABASE_URL", "").strip()
    if not database_url:
        database_url = "sqlite+pysqlite:///./trusted-agent-hub.db"
    return normalize_database_url(database_url).render_as_string(
        hide_password=False
    )


def run_migrations_offline() -> None:
    context.configure(
        url=configured_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine_from_url(configured_database_url())
    try:
        with connectable.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
