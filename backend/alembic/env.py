"""Alembic environment.

The database URL comes from the application settings rather than from
``alembic.ini``, so no credential is ever stored in a tracked file. The URL is
never printed: only a redacted form appears in log output.
"""

from __future__ import annotations

import logging
from logging.config import fileConfig

from alembic import context
from app.core.config import get_settings
from app.models.base import Base
from sqlalchemy import engine_from_config, pool

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

logger = logging.getLogger("alembic.env")

# Target metadata for --autogenerate. Empty today: this milestone defines no
# domain tables. Future models imported into Base.metadata are detected here.
target_metadata = Base.metadata


def _database_url() -> str:
    """Resolve the migration URL from settings, never from alembic.ini."""
    settings = get_settings()
    return settings.alembic_database_url or settings.database_url_sync


def _redact(url: str) -> str:
    """Mask the password so a log line cannot leak it."""
    from app.core.config import Settings

    return Settings._redact_url(url)


def run_migrations_offline() -> None:
    """Run migrations without a DBAPI connection (emits SQL)."""
    url = _database_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live database."""
    url = _database_url()
    logger.info("migrating against %s", _redact(url))

    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = url

    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
