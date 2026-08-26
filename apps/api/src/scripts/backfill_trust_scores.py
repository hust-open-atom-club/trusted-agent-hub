"""Backfill published trust scores after a model implementation change."""

from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Callable
from typing import Any

from sqlalchemy import text

from src.database import create_engine_from_url, create_session_factory
from src.repositories.producer_sqlalchemy import ProducerRepository
from src.repositories.sqlalchemy import SqlAlchemyPackageRepository
from src.services.trust_refresh import (
    TrustScoreBackfillService,
    TrustScoreRefreshService,
)
from src.settings import get_settings


_BACKFILL_LOCK_NAME = "trusted-agent-hub:trust-score-backfill"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Idempotently recompute published versions whose trust-score "
            "model fingerprint is not the active fingerprint."
        )
    )
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--max-attempts", type=int, default=3)
    return parser.parse_args()


def _run_with_backfill_lock(
    database_url: str,
    engine: Any,
    callback: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Run the backfill under a cross-process PostgreSQL advisory lock.

    The lock connection uses a separate engine so a small application pool
    cannot deadlock while the refresh service opens its own sessions.  SQLite
    is used in local tests and has no equivalent advisory-lock primitive, so
    the callback runs directly there.
    """
    if engine.dialect.name != "postgresql":
        return callback()

    lock_engine = create_engine_from_url(database_url)
    try:
        with lock_engine.connect() as connection:
            connection.execute(
                text(
                    "SELECT pg_advisory_lock(hashtext(:lock_name))"
                ),
                {"lock_name": _BACKFILL_LOCK_NAME},
            )
            connection.commit()
            try:
                return callback()
            finally:
                connection.execute(
                    text(
                        "SELECT pg_advisory_unlock(hashtext(:lock_name))"
                    ),
                    {"lock_name": _BACKFILL_LOCK_NAME},
                )
                connection.commit()
    finally:
        lock_engine.dispose()


def main() -> None:
    args = _parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    settings = get_settings()
    if not settings.database_url:
        raise SystemExit("DATABASE_URL is required")

    engine = create_engine_from_url(settings.database_url)
    session_factory = create_session_factory(engine)
    producer_repo = ProducerRepository(session_factory)
    consumer_repo = SqlAlchemyPackageRepository(session_factory)
    refresh = TrustScoreRefreshService(producer_repo, consumer_repo)
    summary = _run_with_backfill_lock(
        settings.database_url,
        engine,
        lambda: TrustScoreBackfillService(refresh).run(
            batch_size=args.batch_size,
            max_attempts=args.max_attempts,
        ),
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    if summary["failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
