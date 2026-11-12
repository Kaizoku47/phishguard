"""Configuration tests.

Settings must fail loudly on unsafe or malformed input rather than falling back
to a permissive default.
"""

from __future__ import annotations

import pytest
from app.core.config import Settings
from pydantic import ValidationError


def _settings(**overrides: object) -> Settings:
    """Build Settings from an explicit mapping, ignoring any local .env file."""
    base: dict[str, object] = {
        "PHISHGUARD_SECRET_KEY": "test-secret-key-value",
        "PHISHGUARD_CORS_ORIGINS": [],
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


def test_defaults_are_safe() -> None:
    settings = _settings()

    assert settings.service_name == "phishguard-api"
    assert settings.version == "0.1.0"
    assert settings.debug is False
    assert settings.cors_origins == []


def test_missing_secret_key_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """Startup must fail rather than run without a signing secret."""
    monkeypatch.delenv("PHISHGUARD_SECRET_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)  # type: ignore[call-arg]


def test_empty_secret_key_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _settings(PHISHGUARD_SECRET_KEY="   ")


def test_wildcard_cors_origin_is_rejected() -> None:
    with pytest.raises(ValidationError, match="wildcard"):
        _settings(PHISHGUARD_CORS_ORIGINS=["*"])


def test_non_http_cors_origin_is_rejected() -> None:
    with pytest.raises(ValidationError):
        _settings(PHISHGUARD_CORS_ORIGINS=["ftp://example.com"])


def test_valid_cors_origins_are_accepted() -> None:
    settings = _settings(PHISHGUARD_CORS_ORIGINS=["http://localhost:5173"])

    assert settings.cors_origins == ["http://localhost:5173"]


def test_secret_key_is_not_exposed_in_repr() -> None:
    secret = "super-secret-value-that-must-not-leak"
    settings = _settings(PHISHGUARD_SECRET_KEY=secret)

    assert secret not in repr(settings)
    assert secret not in str(settings)


def test_database_url_default_targets_postgres_async_driver() -> None:
    """The default must be async Postgres, never SQLite, so drift is visible."""
    url = _settings().database_url

    assert url.startswith("postgresql+asyncpg://")


def test_placeholder_secret_is_rejected() -> None:
    """A copied .env.example must not start the service."""
    with pytest.raises(ValidationError, match="placeholder"):
        _settings(PHISHGUARD_SECRET_KEY="replace-me-with-a-generated-value")


def test_debug_is_rejected_in_production() -> None:
    with pytest.raises(ValidationError, match="debug"):
        _settings(PHISHGUARD_ENVIRONMENT="production", debug=True)
