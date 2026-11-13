#!/usr/bin/env python
"""Create the PHISHGUARD integration-test database if it does not exist.

Run from ``backend/``:

    .venv/bin/python scripts/bootstrap_test_db.py

The script is idempotent: running it repeatedly leaves the database and its
contents untouched. It never drops or recreates a database.

Safety, in order, before any connection is opened:

1. the configured target URL is validated by :func:`app.db.target.validate_test_target`;
2. the target must be the PHISHGUARD service on 127.0.0.1:5434;
3. the target must be the test database, never the development database;
4. ports 5432 and 5433 are refused outright because they belong to other
   PostgreSQL instances on this host.

No password is ever printed, and no connection URL is echoed.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# Allow "python scripts/bootstrap_test_db.py" from the backend directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import get_settings  # noqa: E402
from app.db.target import (  # noqa: E402
    EXPECTED_TEST_DATABASE,
    UnsafeTargetError,
    is_valid_database_name,
    validate_test_target,
)
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402


async def _database_exists(admin_url: str, database: str) -> bool:
    """Return True when the database is already present."""
    engine = create_async_engine(admin_url, pool_pre_ping=True)
    try:
        async with engine.connect() as connection:
            result = await connection.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"),
                {"name": database},
            )
            return result.scalar() is not None
    finally:
        await engine.dispose()


async def _create_database(admin_url: str, database: str) -> None:
    """Create the database.

    The name is passed as a bind parameter, never interpolated into SQL text.
    PostgreSQL does not accept a parameter in a CREATE DATABASE statement, so
    the name is validated as a safe identifier first and then quoted by
    SQLAlchemy's identifier preparer.
    """
    engine = create_async_engine(admin_url, pool_pre_ping=True)
    try:
        async with engine.begin() as connection:
            quoted = await connection.scalar(
                text("SELECT format('%I', :name)"),
                {"name": database},
            )
            await connection.execute(text(f"CREATE DATABASE {quoted}"))  # noqa: S608
    finally:
        await engine.dispose()


async def main() -> int:
    try:
        settings = get_settings()
    except Exception as exc:
        # A configuration error is reported as one clean line, not a traceback.
        # Only the error type is named: the message can quote a URL.
        print(f"cannot read the configuration: {type(exc).__name__}", file=sys.stderr)
        print("see docs/DATABASE.md for the required .env values", file=sys.stderr)
        return 1

    target_url = settings.database_url_test
    try:
        validate_test_target(target_url)
    except UnsafeTargetError as exc:
        print(f"refusing to continue: {exc}", file=sys.stderr)
        return 1

    database = settings.postgres_test_db
    if not is_valid_database_name(database):
        print(
            f"refusing to continue: {database!r} is not a valid database identifier",
            file=sys.stderr,
        )
        return 1

    if database != EXPECTED_TEST_DATABASE:
        print(
            f"refusing to continue: expected database {EXPECTED_TEST_DATABASE!r}, got {database!r}",
            file=sys.stderr,
        )
        return 1

    # The maintenance connection uses the development database as its entry
    # point, because CREATE DATABASE cannot run inside the database it creates.
    admin_url = settings.database_url
    try:
        validate_test_target(admin_url.replace(f"/{settings.postgres_db}", f"/{database}"))
    except UnsafeTargetError as exc:
        print(f"refusing to continue: {exc}", file=sys.stderr)
        return 1

    try:
        if await _database_exists(admin_url, database):
            print(f"test database {database!r} already exists; nothing to do")
            return 0
        await _create_database(admin_url, database)
    except Exception as exc:
        # The type name only: a connection error can carry a password.
        print(f"could not prepare the test database: {type(exc).__name__}", file=sys.stderr)
        return 1

    print(f"test database {database!r} created")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
