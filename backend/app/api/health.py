"""Health routes.

Two paths expose the same check: ``/health`` for infrastructure probes and
``/api/v1/health`` inside the versioned API surface. ``/ready`` is the
readiness check: it answers whether the application can reach its database.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.api.dependencies import SettingsDep
from app.schemas.health import HealthResponse
from app.services.health import HealthService
from app.services.readiness import DatabaseReadinessService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness and dependency health",
)
def health(settings: SettingsDep) -> HealthResponse:
    """Return service health without touching any external dependency."""
    report = HealthService(settings.service_name, settings.version).report()
    return HealthResponse.model_validate(report.to_dict())


@router.get(
    "/ready",
    responses={503: {"description": "Database is not reachable"}},
    summary="Readiness: can the application reach its database?",
)
async def ready(request: Request) -> JSONResponse:
    """Return 200 when the database is reachable, 503 otherwise.

    The response body is deliberately minimal: it must never contain a
    connection string, password or internal exception detail.
    """
    engine = getattr(request.app.state, "engine", None)
    if engine is None:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "detail": "database engine not initialised"},
        )

    try:
        await DatabaseReadinessService(engine).check()
    except Exception:
        logger.warning("readiness probe failed: database unreachable")
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "detail": "database unreachable"},
        )

    return JSONResponse(status_code=200, content={"status": "ready"})
