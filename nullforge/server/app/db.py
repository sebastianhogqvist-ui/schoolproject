"""SQLAlchemy 2.0 engine, session factory and FastAPI session dependency.

SQLite needs a little coaxing to behave like a real database: foreign keys are
off by default and concurrent readers block writers. The ``connect`` listener
below turns on ``foreign_keys`` and WAL journalling for SQLite URLs only, and
SQLite uses :class:`~sqlalchemy.pool.NullPool` because its connections are not
safe to hand between threads.

For PostgreSQL/MySQL, pool settings can be tuned per-service via settings:
- DB_POOL_SIZE: Maximum number of connections to keep
- DB_MAX_OVERFLOW: Additional connections allowed beyond pool_size
- DB_POOL_TIMEOUT: Seconds to wait for a connection
- DB_POOL_RECYCLE: Seconds after which a connection is recycled
"""

import threading
from collections.abc import Generator
from typing import Annotated

from fastapi import Depends
from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import NullPool

from app.config import get_settings

SQLITE_FOREIGN_KEYS_PRAGMA = "PRAGMA foreign_keys=ON"
SQLITE_JOURNAL_PRAGMA = "PRAGMA journal_mode=WAL"
SQLITE_SYNCHRONOUS_PRAGMA = "PRAGMA synchronous=NORMAL"
SQLITE_BUSY_TIMEOUT_PRAGMA = "PRAGMA busy_timeout=5000"
DEFAULT_POOL_RECYCLE_SECONDS = 1800

_engine_lock = threading.Lock()


class Base(DeclarativeBase):
    """Declarative base carrying the metadata that Alembic migrates."""


def _build_engine(url: str, settings=None) -> Engine:
    """Create an engine for ``url``, tuned for SQLite where it matters.

    For non-SQLite databases, pool settings are read from settings if provided.
    """
    if url.startswith("sqlite"):
        return create_engine(
            url,
            poolclass=NullPool,
            connect_args={"check_same_thread": False, "timeout": 5.0},
            future=True,
        )

    # Non-SQLite: use configurable pool settings
    if settings is not None:
        pool_size = getattr(settings, "DB_POOL_SIZE", 5)
        max_overflow = getattr(settings, "DB_MAX_OVERFLOW", 10)
        pool_timeout = getattr(settings, "DB_POOL_TIMEOUT", 30)
        pool_recycle = getattr(settings, "DB_POOL_RECYCLE", DEFAULT_POOL_RECYCLE_SECONDS)
    else:
        pool_size = 5
        max_overflow = 10
        pool_timeout = 30
        pool_recycle = DEFAULT_POOL_RECYCLE_SECONDS

    return create_engine(
        url,
        pool_pre_ping=True,
        pool_recycle=pool_recycle,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout=pool_timeout,
        future=True,
    )


def _install_sqlite_pragmas(target: Engine) -> None:
    """Enable foreign keys, WAL and a busy timeout on every new SQLite connection.

    SQLite leaves foreign keys *off* by default, so without this the cascade
    deletes declared in the schema would silently do nothing.
    """

    @event.listens_for(target, "connect")
    def _set_sqlite_pragmas(dbapi_connection: object, _connection_record: object) -> None:
        """Apply this application's PRAGMAs to one freshly opened connection."""
        cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(SQLITE_FOREIGN_KEYS_PRAGMA)
            cursor.execute(SQLITE_JOURNAL_PRAGMA)
            cursor.execute(SQLITE_SYNCHRONOUS_PRAGMA)
            cursor.execute(SQLITE_BUSY_TIMEOUT_PRAGMA)
        finally:
            cursor.close()


def _build_session_factory(bind: Engine) -> sessionmaker[Session]:
    """Create a session factory bound to ``bind``."""
    return sessionmaker(
        bind=bind,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
        class_=Session,
        future=True,
    )


def _create_engine_and_session_factory(url: str, settings=None) -> tuple[Engine, sessionmaker[Session]]:
    """Create engine and session factory for a given URL and settings."""
    engine = _build_engine(url, settings)
    if url.startswith("sqlite"):
        _install_sqlite_pragmas(engine)
    session_factory = _build_session_factory(engine)
    return engine, session_factory


_initial_url = get_settings().DATABASE_URL
engine: Engine
SessionLocal: sessionmaker[Session]
engine, SessionLocal = _create_engine_and_session_factory(_initial_url)


def configure_database(url: str, settings=None) -> None:
    """Rebind the process engine and session factory to ``url``.

    Used by the test suite to give every test its own temporary database, and by
    any tooling that must retarget the process elsewhere. Safe to call
    repeatedly; the previous engine is disposed.
    """
    global engine, SessionLocal

    with _engine_lock:
        replacement_engine, replacement_factory = _create_engine_and_session_factory(url, settings)
        previous = engine
        engine = replacement_engine
        SessionLocal = replacement_factory

    if previous is not replacement_engine:
        previous.dispose()


def get_db() -> Generator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    session = SessionLocal()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


DbSession = Annotated[Session, Depends(get_db)]
