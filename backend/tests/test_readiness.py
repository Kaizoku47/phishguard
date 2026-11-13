"""Readiness endpoint unit tests.

These verify contract behaviour that does not need a database: the endpoints
exist, succeed when the probe succeeds, and fail without leaking internals
when it does not.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from app.main import create_app
from fastapi.testclient import TestClient


@pytest.fixture
def client_without_db(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """Client whose readiness probe always fails, simulating an outage."""
    from app.services.readiness import DatabaseReadinessService

    async def _fail(self: Any) -> bool:
        raise OSError("simulated outage")

    monkeypatch.setattr(DatabaseReadinessService, "check", _fail)
    # Entering the context runs lifespan, which sets app.state.engine.
    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture
def client_with_db(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """Client whose readiness probe always succeeds."""

    async def _ok(self: Any) -> bool:
        return True

    from app.services.readiness import DatabaseReadinessService

    monkeypatch.setattr(DatabaseReadinessService, "check", _ok)
    with TestClient(create_app()) as test_client:
        yield test_client


def test_ready_endpoint_exists(client: TestClient) -> None:
    """The route is registered, whatever the database state."""
    response = client.get("/ready")
    assert response.status_code in {200, 503}


def test_ready_endpoint_has_no_credential_in_body_or_error(
    client: TestClient,
) -> None:
    """Contract: no URL, password, or traceback may ever appear."""
    body = client.get("/ready").text
    for leak in (
        "postgresql",
        "asyncpg",
        "psycopg",
        "password",
        "@",
        "Traceback",
        "site-packages",
    ):
        assert leak not in body, f"leaked {leak!r}"


def test_ready_endpoint_versioned_prefix(client: TestClient) -> None:
    assert client.get("/api/v1/ready").status_code in {200, 503}


def test_ready_returns_200_when_database_reachable(client_with_db: TestClient) -> None:
    response = client_with_db.get("/ready")

    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_ready_returns_503_when_database_unreachable(client_without_db: TestClient) -> None:
    """An outage must never produce a successful readiness result."""
    response = client_without_db.get("/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"


def test_ready_failure_body_does_not_leak_internals(client_without_db: TestClient) -> None:
    body = client_without_db.get("/ready").text

    for leak in ("postgresql", "asyncpg", "password", "Traceback", "simulated outage"):
        assert leak not in body, f"leaked {leak!r}"


def test_liveness_stays_200_during_database_outage(client_without_db: TestClient) -> None:
    """Liveness must not depend on the database."""
    assert client_without_db.get("/health").status_code == 200


def test_settings_repr_does_not_leak_database_url_password() -> None:
    from app.core.config import get_settings

    settings = get_settings()

    assert repr(settings)
    assert "***" in repr(settings)


def test_redacted_url_masks_password() -> None:
    from app.core.config import Settings

    redacted = Settings._redact_url("postgresql+asyncpg://user:secret-value@127.0.0.1:5434/db")

    assert "secret-value" not in redacted
    assert "***" in redacted
