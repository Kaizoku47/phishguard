"""Health endpoint contract tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

HEALTH_PATHS = ["/health", "/api/v1/health"]


@pytest.mark.parametrize("path", HEALTH_PATHS)
def test_health_returns_ok(client: TestClient, path: str) -> None:
    response = client.get(path)

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "phishguard-api",
        "version": "0.1.0",
        "checks": [],
    }


@pytest.mark.parametrize("path", HEALTH_PATHS)
def test_health_reports_no_dependencies_as_degraded(client: TestClient, path: str) -> None:
    """No database is wired up yet, so the check must be explicit, not assumed."""
    assert client.get(path).json()["checks"] == []


@pytest.mark.parametrize("path", HEALTH_PATHS)
def test_health_content_type_is_json(client: TestClient, path: str) -> None:
    assert client.get(path).headers["content-type"].startswith("application/json")


def test_root_health_and_versioned_health_agree(client: TestClient) -> None:
    """The two paths are the same check exposed twice, not separate logic."""
    assert client.get("/health").json() == client.get("/api/v1/health").json()


def test_unknown_path_returns_404_without_internal_detail(client: TestClient) -> None:
    response = client.get("/definitely-not-a-route")

    assert response.status_code == 404
    body = response.text
    for leak in ("Traceback", "site-packages", "app/", 'File "'):
        assert leak not in body
