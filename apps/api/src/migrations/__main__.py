"""Upgrade a configured database to the latest packaged schema."""

import os
from pathlib import Path

from alembic import command
from alembic.config import Config


def main() -> None:
    """Run all packaged migrations against ``DATABASE_URL``."""
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).parent))
    config.set_main_option(
        "sqlalchemy.url",
        os.getenv("DATABASE_URL", "").strip()
        or "sqlite+pysqlite:///./trusted-agent-hub.db",
    )
    command.upgrade(config, "head")


if __name__ == "__main__":
    main()
