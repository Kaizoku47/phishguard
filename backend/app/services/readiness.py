"""Database readiness logic, independent of FastAPI route definitions."""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine


class DatabaseReadinessService:
    """Run the smallest useful database readiness probe."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def check(self) -> bool:
        """Return true only when the configured database accepts SELECT 1."""
        async with self._engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        return True
