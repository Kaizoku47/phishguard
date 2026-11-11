"""Health routes.

Two paths expose the same check: ``/health`` for infrastructure probes and
``/api/v1/health`` inside the versioned API surface.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.dependencies import SettingsDep
from app.schemas.health import HealthResponse
from app.services.health import HealthService

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
