"""Application startup and wiring tests."""

from __future__ import annotations

from app.main import create_app
from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_create_app_returns_fastapi_instance() -> None:
    assert isinstance(create_app(), FastAPI)


def test_app_starts_and_serves_requests() -> None:
    """Startup and shutdown must complete cleanly with no external services."""
    with TestClient(create_app()) as client:
        assert client.get("/health").status_code == 200


def test_app_is_not_in_debug_mode_by_default() -> None:
    assert create_app().debug is False


def test_factory_produces_independent_instances() -> None:
    """A factory, not a module-level singleton: each call yields a fresh app."""
    assert create_app() is not create_app()


def test_openapi_schema_is_generated() -> None:
    schema = create_app().openapi()

    assert schema["info"]["title"] == "PHISHGUARD API"
    assert "/health" in schema["paths"]
    assert "/api/v1/health" in schema["paths"]


def test_cors_is_not_wildcard(client_headers: dict[str, str] | None = None) -> None:
    """With no configured origins, no permissive CORS header is emitted."""
    with TestClient(create_app()) as client:
        response = client.get("/health", headers={"Origin": "https://evil.example"})

    assert response.headers.get("access-control-allow-origin") is None
