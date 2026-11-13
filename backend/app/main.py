"""Application factory and lifespan.

The factory pattern keeps the app importable without side effects: constructing
it opens no database connection and starts no background work. That is what lets
tests build a throwaway instance per test.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.health import router as root_health_router
from app.api.v1.router import api_v1_router
from app.core.config import Settings, get_settings
from app.core.exceptions import PhishGuardError
from app.core.logging import configure_logging
from app.db.session import create_engine, create_session_factory, dispose_engine

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup and shutdown hooks.

    The engine is created here without opening a connection, so an unavailable
    database never blocks startup. Connection attempts happen on first use.
    """
    settings = app.state.settings
    engine = create_engine(settings)
    app.state.engine = engine
    app.state.session_factory = create_session_factory(engine)

    logger.info("service starting: %s", settings.service_name)
    try:
        yield
    finally:
        await dispose_engine(engine)
        logger.info("service stopping: %s", settings.service_name)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build a configured application instance."""
    resolved = settings or get_settings()
    configure_logging(resolved.log_level)

    app = FastAPI(
        title="PHISHGUARD API",
        description="Autonomous phishing investigation platform.",
        version=resolved.version,
        debug=resolved.debug,
        lifespan=lifespan,
    )
    app.state.settings = resolved

    # CORS is added only when explicit origins are configured. An empty list
    # installs no middleware at all, so no permissive header is ever emitted.
    if resolved.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=resolved.cors_origins,
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Content-Type"],
        )

    app.include_router(root_health_router)
    app.include_router(api_v1_router)

    _register_exception_handlers(app)
    return app


def _register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(PhishGuardError)
    async def _handle_domain_error(_: Request, exc: PhishGuardError) -> JSONResponse:
        # Domain errors are safe to describe; unknown errors are not.
        logger.warning("domain error: %s", type(exc).__name__)
        return JSONResponse(status_code=400, content={"detail": "Request could not be processed."})

    @app.exception_handler(Exception)
    async def _handle_unexpected_error(_: Request, exc: Exception) -> JSONResponse:
        # Log the type for operators, return nothing internal to the caller.
        logger.exception("unhandled error: %s", type(exc).__name__)
        return JSONResponse(status_code=500, content={"detail": "Internal server error."})
