"""Health response schemas."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ComponentCheckSchema(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    status: str


class HealthResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    status: str = Field(description="Aggregate status: ok or degraded.")
    service: str
    version: str
    checks: list[ComponentCheckSchema] = Field(
        default_factory=list,
        description="Dependency probes. Empty means no dependency is wired up yet.",
    )


class ErrorResponse(BaseModel):
    """Generic error envelope. Never carries internal exception detail."""

    model_config = ConfigDict(frozen=True)

    detail: str
