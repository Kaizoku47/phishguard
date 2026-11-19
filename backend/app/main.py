"""Application factory and lifespan.

The factory pattern keeps the app importable without side effects: constructing
it opens no database connection and starts no background work. That is what lets
tests build a throwaway instance per test.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.health import router as root_health_router
from app.api.v1.router import api_v1_router
from app.core.config import Settings, get_settings
from app.core.exceptions import (
    AnalysisNotPerformedError,
    AuthenticationRequiredError,
    EmptyPayloadError,
    EvidenceStorageError,
    NotFoundError,
    ParsingNotCompleteError,
    PayloadTooLargeError,
    PhishGuardError,
    UnsupportedMediaTypeError,
)
from app.core.logging import configure_logging
from app.db.session import create_engine, create_session_factory, dispose_engine
from app.services.evidence import EvidenceStore
from app.services.ingestion import run_startup_recovery

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
    app.state.evidence_store = EvidenceStore(settings.evidence_root, settings.max_upload_bytes)
    # Process-local only: the MVP runs one Uvicorn worker.
    app.state.upload_semaphore = asyncio.Semaphore(settings.max_concurrent_uploads)

    # Runs before the server accepts requests. It is idempotent and never
    # removes orphan evidence files.
    await run_startup_recovery(settings, app.state.evidence_store, app.state.session_factory)

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
    def _fixed(status: int, detail: str, headers: dict[str, str] | None = None) -> JSONResponse:
        return JSONResponse(status_code=status, content={"detail": detail}, headers=headers)

    @app.exception_handler(AuthenticationRequiredError)
    async def _handle_auth_error(_: Request, exc: Exception) -> JSONResponse:
        logger.warning("authentication failure")
        return _fixed(
            401,
            "Authentication required.",
            {"WWW-Authenticate": "Bearer"},
        )

    @app.exception_handler(NotFoundError)
    async def _handle_not_found(_: Request, exc: Exception) -> JSONResponse:
        return _fixed(404, "Not found.")

    @app.exception_handler(ParsingNotCompleteError)
    async def _handle_not_parsed(_: Request, exc: Exception) -> JSONResponse:
        return _fixed(409, "Parsed data is not available.")

    @app.exception_handler(AnalysisNotPerformedError)
    async def _handle_not_analysed(_: Request, exc: Exception) -> JSONResponse:
        return _fixed(409, "Analysis has not been performed yet.")

    @app.exception_handler(PayloadTooLargeError)
    async def _handle_too_large(_: Request, exc: Exception) -> JSONResponse:
        return _fixed(413, "Message exceeds the maximum allowed size.")

    @app.exception_handler(UnsupportedMediaTypeError)
    async def _handle_bad_media_type(_: Request, exc: Exception) -> JSONResponse:
        return _fixed(415, "Unsupported media type.")

    @app.exception_handler(EmptyPayloadError)
    async def _handle_empty(_: Request, exc: Exception) -> JSONResponse:
        return _fixed(422, "Request could not be processed.")

    @app.exception_handler(EvidenceStorageError)
    async def _handle_storage_error(_: Request, exc: Exception) -> JSONResponse:
        logger.warning("evidence storage failure")
        return _fixed(503, "Service temporarily unavailable.")

    @app.exception_handler(PhishGuardError)
    async def _handle_domain_error(_: Request, exc: PhishGuardError) -> JSONResponse:
        # Domain errors are safe to describe; unknown errors are not.
        logger.warning("domain error: %s", type(exc).__name__)
        return _fixed(400, "Request could not be processed.")

    @app.exception_handler(Exception)
    async def _handle_unexpected_error(_: Request, exc: Exception) -> JSONResponse:
        # Log the type for operators, return nothing internal to the caller.
        logger.exception("unhandled error: %s", type(exc).__name__)
        return _fixed(500, "Internal server error.")
