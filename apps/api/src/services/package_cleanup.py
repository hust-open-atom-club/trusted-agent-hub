"""Periodic maintenance for package records that no longer contain data."""

from __future__ import annotations

from collections.abc import Callable
import logging
import threading

from src.database import create_session_factory, get_runtime_engine
from src.repositories.producer_sqlalchemy import ProducerRepository
from src.settings import get_settings


_logger = logging.getLogger(__name__)
EMPTY_PACKAGE_CLEANUP_INTERVAL_SECONDS = 24 * 60 * 60


def _get_producer_repository() -> ProducerRepository | None:
    database_url = get_settings().database_url
    if not database_url:
        return None
    engine = get_runtime_engine(database_url)
    return ProducerRepository(create_session_factory(engine))


def run_empty_package_cleanup(
    repository_factory: Callable[[], ProducerRepository | None] = _get_producer_repository,
) -> int:
    """Run one empty-package cleanup pass and return the deleted count."""
    repository = repository_factory()
    if repository is None:
        return 0
    deleted = repository.delete_empty_draft_packages()
    if deleted:
        _logger.info("Deleted %s empty draft package(s)", deleted)
    return deleted


def run_empty_package_cleanup_loop(
    stop_event: threading.Event,
    *,
    interval_seconds: float = EMPTY_PACKAGE_CLEANUP_INTERVAL_SECONDS,
    repository_factory: Callable[[], ProducerRepository | None] = _get_producer_repository,
) -> None:
    """Run empty-package cleanup once per day until the application stops."""
    wait_seconds = max(1.0, float(interval_seconds))
    while not stop_event.wait(wait_seconds):
        try:
            run_empty_package_cleanup(repository_factory)
        except Exception:  # pragma: no cover - defensive worker boundary
            _logger.exception("Periodic empty package cleanup failed")
