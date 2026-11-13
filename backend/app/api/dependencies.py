"""Shared FastAPI dependencies."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import Settings, get_settings


def get_session_factory(request: Request) -> async_sessionmaker[AsyncSession]:
    """Return the session factory created by the application lifespan."""
    return request.app.state.session_factory


SettingsDep = Annotated[Settings, Depends(get_settings)]
SessionFactoryDep = Annotated[async_sessionmaker[AsyncSession], Depends(get_session_factory)]


async def provide_session(
    factory: SessionFactoryDep,
) -> AsyncIterator[AsyncSession]:
    """Yield a request-scoped session and roll back on failure."""
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


SessionDep = Annotated[AsyncSession, Depends(provide_session)]
