"""Application startup and wiring tests."""

from __future__ import annotations

from app.core.config import Settings
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


def _cors_app() -> FastAPI:
    """Application with one explicitly approved cross-origin dashboard."""
    settings = Settings(
        _env_file=None,
        PHISHGUARD_SECRET_KEY="test-secret-key-value",
        PHISHGUARD_ENVIRONMENT="test",
        PHISHGUARD_CORS_ORIGINS=["http://localhost:5173"],
    )
    return create_app(settings)


def test_approved_origin_can_preflight_content_type() -> None:
    with TestClient(_cors_app()) as client:
        response = client.options(
            "/api/v1/emails",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "POST" in response.headers["access-control-allow-methods"]
    assert response.headers.get("access-control-allow-headers") is not None
    assert "*" not in response.headers["access-control-allow-origin"]


def test_unapproved_origin_gets_no_permission() -> None:
    with TestClient(_cors_app()) as client:
        response = client.options(
            "/api/v1/emails",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type",
            },
        )
    assert response.headers.get("access-control-allow-origin") is None


def test_authorization_header_is_not_exposed_cross_origin() -> None:
    """2.3.8 has no frontend yet; cross-origin bearer auth is deliberately off."""
    with TestClient(_cors_app()) as client:
        response = client.options(
            "/api/v1/emails",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization",
            },
        )
    assert response.status_code == 400
    allowed = response.headers.get("access-control-allow-headers", "").lower()
    assert "authorization" not in allowed
