"""Database wiring.

Only the engine and session factory live here; no tables are declared and no
schema is created. The persistence milestone adds models and Alembic
migrations. Nothing in this module connects to the database at import time, so
tests run without PostgreSQL.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import get_settings


def create_engine(url: str | None = None) -> AsyncEngine:
    """Build an async engine. No connection is opened until first use."""
    settings = get_settings()
    return create_async_engine(url or settings.database_url, pool_pre_ping=True)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


async def session_scope(
    factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """Yield a session and guarantee rollback on failure."""
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
