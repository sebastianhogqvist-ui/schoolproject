"""SQLAlchemy 2.0 engine, session factory and FastAPI session dependency.

SQLite needs a little coaxing to behave like a real database: foreign keys are
off by default and concurrent readers block writers. The ``connect`` listener
below turns on ``foreign_keys`` and WAL journalling for SQLite URLs only, and
SQLite uses :class:`~sqlalchemy.pool.NullPool` because its connections are not
safe to hand between threads.
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
POOL_RECYCLE_SECONDS = 1800

_engine_lock = threading.Lock()


class Base(DeclarativeBase):
    """Declarative base carrying the metadata that Alembic migrates."""


def _build_engine(url: str) -> Engine:
    """Create an engine for ``url``, tuned for SQLite where it matters."""
    if url.startswith("sqlite"):
        return create_engine(
            url,
            poolclass=NullPool,
            connect_args={"check_same_thread": False, "timeout": 5.0},
            future=True,
        )
    return create_engine(
        url,
        pool_pre_ping=True,
        pool_recycle=POOL_RECYCLE_SECONDS,
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


_initial_url = get_settings().DATABASE_URL
engine: Engine = _build_engine(_initial_url)
if _initial_url.startswith("sqlite"):
    _install_sqlite_pragmas(engine)

SessionLocal = _build_session_factory(engine)


def configure_database(url: str) -> None:
    """Rebind the process engine and session factory to ``url``.

    Used by the test suite to give every test its own temporary database, and by
    any tooling that must retarget the process elsewhere. Safe to call
    repeatedly; the previous engine is disposed.
    """
    global engine, SessionLocal

    with _engine_lock:
        replacement = _build_engine(url)
        if url.startswith("sqlite"):
            _install_sqlite_pragmas(replacement)
        previous = engine
        engine = replacement
        SessionLocal = _build_session_factory(replacement)

    if previous is not replacement:
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
