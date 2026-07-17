"""Database helpers for Consumer persistence."""

from collections.abc import Callable
from functools import lru_cache
from threading import RLock

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    """Base class for SQLAlchemy ORM models."""


def normalize_database_url(database_url: str) -> URL:
    """Return a SQLAlchemy URL with standard PostgreSQL schemes on psycopg 3."""
    url = make_url(database_url)
    if url.drivername in {"postgres", "postgresql"}:
        return url.set(drivername="postgresql+psycopg")
    return url


def create_engine_from_url(database_url: str) -> Engine:
    """Create a SQLAlchemy engine for the configured database URL."""
    url = normalize_database_url(database_url)
    if url.get_backend_name() == "sqlite":
        connect_args = {"check_same_thread": False}
        if url.database in (None, "", ":memory:"):
            engine = create_engine(
                url,
                future=True,
                connect_args=connect_args,
                poolclass=StaticPool,
            )
        else:
            engine = create_engine(url, future=True, connect_args=connect_args)

        @event.listens_for(engine, "connect")
        def enable_sqlite_foreign_keys(dbapi_connection: object, _: object) -> None:
            cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
            finally:
                cursor.close()

        return engine
    return create_engine(url, future=True)


def create_session_factory(engine: Engine) -> Callable[[], Session]:
    """Create a session factory bound to an engine."""
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


_runtime_engines: set[Engine] = set()
_runtime_engine_lock = RLock()


@lru_cache(maxsize=None)
def _get_runtime_engine_cached(database_url: str) -> Engine:
    engine = create_engine_from_url(database_url)
    _runtime_engines.add(engine)
    return engine


def get_runtime_engine(database_url: str) -> Engine:
    """Atomically return the process-wide engine for a database URL."""
    with _runtime_engine_lock:
        return _get_runtime_engine_cached(database_url)


def dispose_runtime_engines() -> None:
    """Dispose all cached runtime engines and clear their cache."""
    with _runtime_engine_lock:
        engines = tuple(_runtime_engines)
        _runtime_engines.clear()
        _get_runtime_engine_cached.cache_clear()
        for engine in engines:
            engine.dispose()
