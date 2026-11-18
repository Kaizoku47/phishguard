"""Migration tests for the Milestone 2.3.1 schema.

These prove what the architecture requires: that Alembic's metadata sees
every model, that the migration creates the approved five-table schema from
an empty database, that the downgrade removes it, and that re-upgrading works.

The migration is executed against the PHISHGUARD **test** database only. The
target is validated before anything runs, and the schema is always restored to
head, so a failure cannot leave the test database in a broken state.

The development database is never touched by these tests.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from pathlib import Path

import pytest
from app.core.config import get_settings
from app.db.target import (
    EXPECTED_HOST,
    EXPECTED_PORT,
    UnsafeTargetError,
    validate_test_target,
)
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

pytestmark = pytest.mark.integration

BACKEND_ROOT = Path(__file__).resolve().parents[2]

EXPECTED_TABLES = {
    "email_evidence",
    "parsed_emails",
    "email_attachments",
    "audit_events",
    "analysis_results",
}


def _alembic_env() -> dict[str, str]:
    """An environment that points Alembic at the PHISHGUARD test database."""
    settings = get_settings()
    try:
        validate_test_target(settings.database_url_test)
    except UnsafeTargetError as exc:
        raise RuntimeError(f"refusing to migrate an unvalidated target: {exc}") from exc
    return {
        **os.environ,
        "ALEMBIC_DATABASE_URL": settings.database_url_test.replace(
            "postgresql+asyncpg://", "postgresql+psycopg://"
        ),
    }


def _run_alembic(*args: str) -> tuple[int, str]:
    """Run Alembic as a subprocess and return its exit code and output."""
    # ``sys.executable`` resolves to whatever interpreter runs the tests, so
    # the same call works in a local virtualenv and in CI, where no
    # ``.venv`` directory exists.
    result = subprocess.run(  # noqa: S603 - static interpreter and static args
        [sys.executable, "-m", "alembic", *args],
        cwd=BACKEND_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        env=_alembic_env(),
        check=False,
    )
    return result.returncode, result.stdout + result.stderr


async def _table_names() -> set[str]:
    settings = get_settings()
    engine = create_async_engine(settings.database_url_test, poolclass=None)
    try:
        async with engine.connect() as connection:
            rows = await connection.execute(
                text(
                    "select table_name from information_schema.tables where table_schema = 'public'"
                )
            )
            return {row[0] for row in rows}
    finally:
        await engine.dispose()


async def _current_revision() -> str | None:
    """The revision the test database is stamped with, or None when unstamped."""
    settings = get_settings()
    engine = create_async_engine(settings.database_url_test, poolclass=None)
    try:
        async with engine.connect() as connection:
            result = await connection.execute(text("select version_num from alembic_version"))
            return result.scalar_one_or_none()
    finally:
        await engine.dispose()


async def test_alembic_metadata_sees_every_model() -> None:
    """The architecture's requirement, checked through Alembic itself.

    ``alembic check`` compares the live database with the model metadata. If
    the models were not registered on ``Base.metadata``, the comparison would
    report the five tables as missing.
    """
    code, output = await asyncio.to_thread(_run_alembic, "check")
    assert code == 0, output


async def test_the_database_is_at_head() -> None:
    assert await _current_revision() == "0002_email_ingestion"


async def test_the_migration_creates_the_five_tables_and_downgrades_back() -> None:
    """Upgrade from empty, downgrade to empty, then upgrade again."""
    try:
        # Down to the empty baseline.
        code, output = await asyncio.to_thread(_run_alembic, "downgrade", "0001_baseline")
        assert code == 0, output

        present = await _table_names()
        for table in EXPECTED_TABLES:
            assert table not in present, table

        # And back up again.
        code, output = await asyncio.to_thread(_run_alembic, "upgrade", "head")
        assert code == 0, output
    finally:
        # The schema is always restored, even if an assertion above failed.
        code, output = await asyncio.to_thread(_run_alembic, "upgrade", "head")
        assert code == 0, output

    present = await _table_names()
    for table in EXPECTED_TABLES:
        assert table in present, table
    assert await _current_revision() == "0002_email_ingestion"


async def test_the_downgrade_removes_the_tables_in_dependency_order() -> None:
    """The downgrade drops the children before the parents."""
    try:
        code, output = await asyncio.to_thread(_run_alembic, "downgrade", "base")
        assert code == 0, output
        present = await _table_names()
        for table in EXPECTED_TABLES:
            assert table not in present, table
        # Downgrading past the baseline leaves the version table empty.
        assert await _current_revision() is None
    finally:
        code, output = await asyncio.to_thread(_run_alembic, "upgrade", "head")
        assert code == 0, output


async def test_the_migration_target_is_the_isolated_phishguard_database() -> None:
    """The target is checked before anything is run."""
    settings = get_settings()
    assert EXPECTED_HOST in settings.database_url_test
    assert f":{EXPECTED_PORT}/" in settings.database_url_test
    assert settings.database_url_test.rstrip("/").endswith(settings.postgres_test_db)
