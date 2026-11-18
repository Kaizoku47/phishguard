"""Unit tests for authenticated email endpoints A4-A9.

These tests never connect to PostgreSQL and never write to the real evidence
directory. The database and startup recovery are stubbed at the application
boundary; integration behaviour is covered in test_emails_api.py.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from app.api.v1 import emails as emails_module
from app.core.config import SYNTHETIC_TEST_TOKEN, Settings
from app.main import create_app
from fastapi.testclient import TestClient


def _settings(root: Path, max_upload_bytes: int = 1024 * 1024) -> Settings:
    return Settings(
        _env_file=None,
        PHISHGUARD_SECRET_KEY="test-secret-key-value",
        PHISHGUARD_API_TOKEN=SYNTHETIC_TEST_TOKEN,
        PHISHGUARD_EVIDENCE_ROOT=str(root),
        PHISHGUARD_MAX_UPLOAD_BYTES=max_upload_bytes,
    )


@pytest.fixture
def make_client(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    async def _noop_recovery(*args: object, **kwargs: object) -> None:
        return None

    async def _noop_dispose(*args: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr("app.main.create_engine", lambda settings: object())
    monkeypatch.setattr("app.main.create_session_factory", lambda engine: object())
    monkeypatch.setattr("app.main.dispose_engine", _noop_dispose)
    monkeypatch.setattr("app.main.run_startup_recovery", _noop_recovery)

    def factory(root: Path | None = None, max_upload_bytes: int = 1024 * 1024) -> TestClient:
        settings = _settings(root or tmp_path / "evidence", max_upload_bytes)
        return TestClient(create_app(settings))

    return factory


def _headers(token: str = SYNTHETIC_TEST_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_missing_token_returns_fixed_401(make_client) -> None:
    with make_client() as client:
        response = client.post(
            "/api/v1/emails", content=b"x", headers={"Content-Type": "message/rfc822"}
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required."}
    assert response.headers["www-authenticate"] == "Bearer"
    assert SYNTHETIC_TEST_TOKEN not in response.text


def test_wrong_scheme_and_wrong_token_return_identical_401(make_client) -> None:
    with make_client() as client:
        wrong_scheme = client.post(
            "/api/v1/emails",
            content=b"x",
            headers={
                "Authorization": f"Basic {SYNTHETIC_TEST_TOKEN}",
                "Content-Type": "message/rfc822",
            },
        )
        wrong_token = client.post(
            "/api/v1/emails",
            content=b"x",
            headers=_headers("x" * 40) | {"Content-Type": "message/rfc822"},
        )

    assert wrong_scheme.status_code == wrong_token.status_code == 401
    assert wrong_scheme.json() == wrong_token.json() == {"detail": "Authentication required."}
    assert wrong_scheme.headers["www-authenticate"] == "Bearer"
    assert wrong_token.headers["www-authenticate"] == "Bearer"


def test_query_parameter_token_is_rejected(make_client) -> None:
    with make_client() as client:
        response = client.post(
            "/api/v1/emails?token=" + SYNTHETIC_TEST_TOKEN,
            content=b"x",
            headers=_headers() | {"Content-Type": "message/rfc822"},
        )

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required."}


def test_wrong_content_type_returns_415(make_client) -> None:
    with make_client() as client:
        response = client.post(
            "/api/v1/emails", content=b"x", headers=_headers() | {"Content-Type": "text/plain"}
        )

    assert response.status_code == 415
    assert response.json() == {"detail": "Unsupported media type."}


def test_missing_content_type_is_accepted(make_client, monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict[str, Any] = {}

    async def fake_ingest(chunks, content_type, settings, store, session_factory, semaphore=None):
        called["content_type"] = content_type
        return {
            "id": "6f1c2e44-1b6d-4b3f-9d21-6f2a9b7c1d40",
            "status": "parsed",
            "parse_status": "ok",
            "size_bytes": 4,
            "sha256": "0" * 64,
            "received_at": None,
        }

    monkeypatch.setattr(emails_module, "ingest_message", fake_ingest)
    with make_client() as client:
        response = client.post("/api/v1/emails", content=b"body", headers=_headers())

    assert response.status_code == 201
    assert called["content_type"] is None
    assert "storage_id" not in response.text


def test_oversized_upload_is_rejected_before_database(make_client, tmp_path: Path) -> None:
    with make_client(tmp_path / "evidence", max_upload_bytes=10) as client:
        response = client.post(
            "/api/v1/emails",
            content=b"x" * 11,
            headers=_headers() | {"Content-Type": "message/rfc822"},
        )

    assert response.status_code == 413
    assert response.json() == {"detail": "Message exceeds the maximum allowed size."}


def test_empty_upload_is_rejected(make_client) -> None:
    with make_client() as client:
        response = client.post(
            "/api/v1/emails",
            content=b"",
            headers=_headers() | {"Content-Type": "message/rfc822"},
        )

    assert response.status_code == 422
    assert response.json() == {"detail": "Request could not be processed."}


def test_health_endpoints_remain_public(make_client) -> None:
    with make_client() as client:
        assert client.get("/health").status_code == 200
        assert client.get("/api/v1/health").status_code == 200
