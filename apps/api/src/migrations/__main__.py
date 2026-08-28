"""Upgrade a configured database to the latest packaged schema."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from src.settings import Settings


def main() -> None:
    """Run all packaged migrations against ``DATABASE_URL``."""
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parent))
    config.set_main_option(
        "sqlalchemy.url",
        Settings.from_environment().database_url
        or "sqlite+pysqlite:///./trusted-agent-hub.db",
    )
    command.upgrade(config, "head")


if __name__ == "__main__":
    main()
