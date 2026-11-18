"""Shared FastAPI dependencies."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.auth import bearer_token, token_is_valid
from app.core.config import Settings
from app.core.exceptions import AuthenticationRequiredError


def get_session_factory(request: Request) -> async_sessionmaker[AsyncSession]:
    """Return the session factory created by the application lifespan."""
    return request.app.state.session_factory


def get_request_settings(request: Request) -> Settings:
    """Return the settings bound to this application instance."""
    return request.app.state.settings


SettingsDep = Annotated[Settings, Depends(get_request_settings)]
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


async def require_bearer_token(request: Request, settings: SettingsDep) -> None:
    """Require a valid bearer token for A4-A9.

    A token in the query string is rejected as authentication failure; the
    credential is accepted only from the Authorization header.
    """
    token_keys = {"token", "access_token", "api_token"}
    if any(key in request.query_params for key in token_keys):
        raise AuthenticationRequiredError

    presented = bearer_token(request.headers.get("authorization"))
    if not token_is_valid(presented, settings):
        raise AuthenticationRequiredError


AuthDep = Annotated[None, Depends(require_bearer_token)]
