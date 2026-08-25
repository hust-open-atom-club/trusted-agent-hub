"""Backfill published trust scores after a model-version upgrade."""

from __future__ import annotations

import argparse
import json
import logging

from src.database import create_engine_from_url, create_session_factory
from src.repositories.producer_sqlalchemy import ProducerRepository
from src.repositories.sqlalchemy import SqlAlchemyPackageRepository
from src.services.trust_refresh import (
    TrustScoreBackfillService,
    TrustScoreRefreshService,
)
from src.settings import get_settings


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Idempotently recompute published versions whose trust-score "
            "model is not the active version."
        )
    )
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--max-attempts", type=int, default=3)
    return parser.parse_args()


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
    summary = TrustScoreBackfillService(refresh).run(
        batch_size=args.batch_size,
        max_attempts=args.max_attempts,
    )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    if summary["failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
