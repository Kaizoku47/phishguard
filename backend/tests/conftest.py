"""Shared pytest fixtures.

Tests must run without PostgreSQL, Redis, or any network dependency. The
health endpoints deliberately require no database, so no DB fixture exists
yet; one arrives with the persistence milestone.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from app.main import create_app
from fastapi.testclient import TestClient


@pytest.fixture
def client() -> Iterator[TestClient]:
    """HTTP client bound to a freshly built application instance."""
    with TestClient(create_app()) as test_client:
        yield test_client
