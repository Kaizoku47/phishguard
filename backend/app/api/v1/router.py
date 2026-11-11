"""Version 1 API router.

New feature routers are mounted here so their URL shape is defined in one place.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.health import router as health_router

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(health_router)
