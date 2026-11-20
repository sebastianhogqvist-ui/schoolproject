"""Alembic environment wired to the app's declarative metadata.

The database URL comes from ``DATABASE_URL`` (or, if already set on the Alembic
config, from there) so ``alembic.ini`` never needs to hold credentials.
"""

import logging
import sys
from logging.config import fileConfig
from pathlib import Path

from sqlalchemy import engine_from_config, pool

from alembic import context

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import models  # noqa: F401  (imported for its side effect: table registration)
from app.config import get_settings
from app.db import Base

config = context.config
if config.config_file_name is not None and not logging.getLogger().handlers:
    # fileConfig clears root handlers, so defer to the app's JSON logging when
    # it is already installed (that is the case when invoked via app.cli).
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = Base.metadata

RENDER_AS_BATCH = True
COMPARE_TYPE = True


def get_url() -> str:
    """Resolve the database URL from the Alembic config, else from settings."""
    configured = config.get_main_option("sqlalchemy.url", None)
    return configured or get_settings().DATABASE_URL


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting to a database."""
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=RENDER_AS_BATCH,
        compare_type=COMPARE_TYPE,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live connection."""
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = get_url()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=RENDER_AS_BATCH,
            compare_type=COMPARE_TYPE,
        )
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
