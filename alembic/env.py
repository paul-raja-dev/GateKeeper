"""
Alembic Environment Configuration

This file is run by Alembic every time a migration command is executed.
It's configured to:
1. Read DATABASE_URL from our Pydantic Settings (not alembic.ini)
2. Use async engine (since we use asyncpg)
3. Import Base.metadata for autogenerate support

Usage:
    alembic revision --autogenerate -m "add users table"
    alembic upgrade head
    alembic downgrade -1
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.ext.asyncio import create_async_engine

import app.models  # noqa: F401 — registers all models with Base.metadata
from app.config import get_settings
from app.database import Base

# ---------------------------------------------------------------------------
# Alembic Config
# ---------------------------------------------------------------------------

# This is the Alembic Config object, which provides access to alembic.ini
config = context.config

settings = get_settings()

# NOTE: We intentionally do NOT call config.set_main_option("sqlalchemy.url", ...)
# because configparser treats '%' as interpolation syntax, which breaks
# passwords containing URL-encoded characters (e.g., %40 for @).
# Instead, we create the engine directly from our settings in run_async_migrations().

# Interpret the config file for Python logging (from alembic.ini)
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# The metadata object used by autogenerate.
# When you run `alembic revision --autogenerate`, Alembic compares
# this metadata against the actual database schema to generate migrations.
target_metadata = Base.metadata


# ---------------------------------------------------------------------------
# Migration Runners
# ---------------------------------------------------------------------------


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.

    This generates SQL scripts without connecting to the database.
    Useful for reviewing migration SQL before applying it.

    Usage: alembic upgrade head --sql
    """
    context.configure(
        url=settings.DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    """Configure and run migrations with the given connection."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """
    Run migrations in 'online' mode using an async engine.

    We create the engine directly from settings.DATABASE_URL instead of
    using Alembic's config, to avoid configparser's % interpolation issues.
    """
    connectable = create_async_engine(
        settings.DATABASE_URL,
        poolclass=pool.NullPool,  # Don't pool connections for migrations
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Entry point for online migrations — delegates to async runner."""
    asyncio.run(run_async_migrations())


# ---------------------------------------------------------------------------
# Execute
# ---------------------------------------------------------------------------

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
