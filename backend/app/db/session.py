"""SQLAlchemy 2 async database infrastructure.

Importing this module creates no network connection. The engine is created only
when the application factory or a test explicitly asks for it. Passwords never
enter logs or exception responses.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Final

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Settings, get_settings

POOL_SIZE: Final[int] = 5
# Overflow is the burst allowance above the steady pool. Two spare connections
# cover a short burst (a page load issuing two queries) without letting the
# application approach PostgreSQL's max_connections of 20, which other
# processes on this host may also need.
MAX_OVERFLOW: Final[int] = 2
POOL_TIMEOUT_SECONDS: Final[int] = 30


def create_engine(settings: Settings | None = None, url: str | None = None) -> AsyncEngine:
    """Build an async PostgreSQL engine without connecting during import."""
    resolved = settings or get_settings()
    return create_async_engine(
        url or resolved.database_url,
        pool_pre_ping=True,
        pool_size=POOL_SIZE,
        max_overflow=MAX_OVERFLOW,
        pool_timeout=POOL_TIMEOUT_SECONDS,
        pool_recycle=1800,
    )


def create_session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    """Create a reusable async session factory."""
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)


async def session_scope(
    factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """Yield a session and roll back if the caller raises."""
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


async def dispose_engine(engine: AsyncEngine) -> None:
    """Close pooled connections during application shutdown."""
    await engine.dispose()
