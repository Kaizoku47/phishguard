"""Shared pytest fixtures.

Unit tests must run without PostgreSQL, Redis or any network dependency.
Application lifespan startup recovery is a production operation that queries
the database, so it is disabled here for tests not marked ``integration``.
Integration tests keep the real lifespan and run only after CI has created and
migrated the isolated test database.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from app.main import create_app
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def isolate_unit_test_lifespan(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep non-integration tests independent of production startup recovery."""
    if request.node.get_closest_marker("integration") is not None:
        return

    async def _noop_recovery(*args: Any, **kwargs: Any) -> None:
        return None

    monkeypatch.setattr("app.main.run_startup_recovery", _noop_recovery)


@pytest.fixture
def client() -> Iterator[TestClient]:
    """HTTP client bound to a freshly built application instance."""
    with TestClient(create_app()) as test_client:
        yield test_client
