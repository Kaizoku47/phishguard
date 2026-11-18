"""Integration test fixtures.

These tests require the PHISHGUARD PostgreSQL service from docker-compose.yml
on 127.0.0.1:5434. They never connect to the native PostgreSQL on 5432, to any
other project's container, or to any other host.

Safety rule for destructive operations: before dropping or recreating anything,
the target database name and connection target are validated against an
allow-list. A wrong configuration refuses to run rather than deleting data.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from app.core.config import get_settings
from app.db.target import UnsafeTargetError, validate_test_target
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine


@pytest_asyncio.fixture
async def integration_engine() -> AsyncIterator[AsyncEngine]:
    """Engine bound to the current test's event loop.

    Function-scoped on purpose: pytest-asyncio gives each test its own event
    loop, and an engine pooled across loops raises "attached to a different
    loop". The pool is small and closed after each test, so the cost is one
    connection handshake.
    """
    settings = get_settings()
    url = settings.database_url_test
    try:
        validate_test_target(url)
    except UnsafeTargetError as exc:
        raise RuntimeError(f"refusing to run integration tests: {exc}") from exc

    engine = create_async_engine(url, pool_pre_ping=True, poolclass=None)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest_asyncio.fixture
async def clean_tables(integration_engine: AsyncEngine) -> AsyncIterator[None]:
    """Give each test an empty schema.

    The Milestone 2.3.1 tables are truncated in one statement, children
    first, so a truncate never has to follow a dependency chain.

    The target is validated before anything is touched: the fixture refuses
    to run against anything other than the PHISHGUARD test database.
    """
    settings = get_settings()
    try:
        validate_test_target(settings.database_url_test)
    except UnsafeTargetError as exc:
        raise RuntimeError(f"refusing to truncate an unvalidated target: {exc}") from exc

    async with integration_engine.begin() as connection:
        await connection.execute(
            text(
                "TRUNCATE email_attachments, parsed_emails, analysis_results, "
                "audit_events, email_evidence CASCADE"
            )
        )
    yield


@pytest.fixture(scope="session")
def test_database_target() -> dict[str, str | int]:
    """Expose the validated target so tests can assert on it."""
    from app.db.target import EXPECTED_HOST, EXPECTED_PORT

    settings = get_settings()
    try:
        validate_test_target(settings.database_url_test)
    except UnsafeTargetError as exc:
        raise RuntimeError(f"refusing to run integration tests: {exc}") from exc
    return {
        "host": EXPECTED_HOST,
        "port": EXPECTED_PORT,
        "database": settings.postgres_test_db,
    }
