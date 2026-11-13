"""Database integration tests.

Marker: ``integration``. Requires the PHISHGUARD PostgreSQL service on
127.0.0.1:5434. Run with:

    pytest -m integration

Unit tests remain independent of this module and of Docker.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from app.core.config import get_settings
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

pytestmark = pytest.mark.integration

# Alembic is invoked as a module in the same interpreter running the tests, not
# as a fixed binary path. A hardcoded ``backend/.venv/bin/alembic`` exists on
# this machine but not on a GitHub Actions runner, where dependencies are
# installed into the system Python and no project virtual environment is
# created. ``sys.executable`` resolves to whatever interpreter is running the
# test, so the command works locally and in CI alike.
BACKEND_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def alembic_test_env() -> dict[str, str]:
    """Alembic environment pointed at the test database.

    Alembic reads ALEMBIC_DATABASE_URL. The override keeps the migration run on
    the isolated test database, never the development database.
    """
    settings = get_settings()
    return {
        **os.environ,
        "ALEMBIC_DATABASE_URL": settings.database_url_test.replace(
            "postgresql+asyncpg://", "postgresql+psycopg://"
        ),
    }


async def test_database_connects(integration_engine: AsyncEngine) -> None:
    async with integration_engine.connect() as connection:
        result = await connection.execute(text("SELECT 1"))
        assert result.scalar() == 1


async def test_select_one_returns_expected_value(integration_engine: AsyncEngine) -> None:
    async with integration_engine.connect() as connection:
        assert (await connection.execute(text("SELECT 1"))).scalar() == 1
        assert (await connection.execute(text("SELECT 2 + 2"))).scalar() == 4


async def test_session_factory_creates_sessions(integration_engine: AsyncEngine) -> None:
    from app.db.session import create_session_factory

    factory: async_sessionmaker[AsyncSession] = create_session_factory(integration_engine)
    async with factory() as session:
        assert (await session.execute(text("SELECT 1"))).scalar() == 1


async def test_session_lifecycle_commit_and_rollback(
    integration_engine: AsyncEngine,
) -> None:
    from app.db.session import create_session_factory

    factory = create_session_factory(integration_engine)

    # A committed session keeps its work.
    async with factory() as session, session.begin():
        await session.execute(text("SELECT 1"))

    # A failed session rolls back cleanly and can be reused. Division by zero
    # is a deterministic failure trigger. The exact driver exception class
    # differs between asyncpg and psycopg, so the SQLAlchemy base class
    # DBAPIError is the correct contract to assert on.
    from sqlalchemy.exc import DBAPIError

    async with factory() as session:
        with pytest.raises(DBAPIError):
            async with session.begin():
                await session.execute(text("SELECT 1/0"))
        assert (await session.execute(text("SELECT 1"))).scalar() == 1


async def test_readiness_service_succeeds(integration_engine: AsyncEngine) -> None:
    from app.services.readiness import DatabaseReadinessService

    assert await DatabaseReadinessService(integration_engine).check() is True


async def test_alembic_migration_runs_and_records_version(
    alembic_test_env: dict[str, str],
) -> None:
    """Upgrade to head, then confirm the revision is recorded."""
    import asyncio
    import subprocess

    from app.core.config import get_settings
    from sqlalchemy import text

    settings = get_settings()

    def _run(*args: str) -> subprocess.CompletedProcess[str]:
        # Interpreter and arguments are fixed constants; no user input reaches here.
        return subprocess.run(  # noqa: S603 - static interpreter and static args
            [sys.executable, "-m", "alembic", *args],
            cwd=BACKEND_ROOT,
            capture_output=True,
            text=True,
            timeout=120,
            env=alembic_test_env,
        )

    upgrade = await asyncio.to_thread(_run, "upgrade", "head")
    assert upgrade.returncode == 0, f"alembic upgrade failed: {upgrade.stderr}"
    # The connection URL must never appear in Alembic output.
    assert settings.postgres_password.get_secret_value() not in upgrade.stdout
    assert settings.postgres_password.get_secret_value() not in upgrade.stderr

    current = await asyncio.to_thread(_run, "current")
    assert current.returncode == 0
    assert "0001_baseline" in current.stdout, current.stdout

    # The alembic_version table now exists in the test database.
    from sqlalchemy.ext.asyncio import create_async_engine

    engine = create_async_engine(settings.database_url_test)
    try:
        async with engine.connect() as connection:
            version = (
                await connection.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar()
            assert version == "0001_baseline"
    finally:
        await engine.dispose()


async def test_database_isolation_between_suites(integration_engine: AsyncEngine) -> None:
    """The test database is not the development database."""
    from app.core.config import get_settings
    from sqlalchemy import text

    settings = get_settings()
    assert settings.postgres_test_db != settings.postgres_db

    async with integration_engine.connect() as connection:
        current_db = (await connection.execute(text("SELECT current_database()"))).scalar()
        assert current_db == settings.postgres_test_db
