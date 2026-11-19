"""Configuration consistency tests.

The connection parts (POSTGRES_HOST, POSTGRES_PORT, POSTGRES_USER,
POSTGRES_DB) and the connection URLs describe the same target. When they
disagree the application would talk to a different database than the operator
configured, so the settings refuse to start.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from app.core.config import Settings
from pydantic import ValidationError

BASE = {
    "PHISHGUARD_SECRET_KEY": "x-not-a-real-secret-0123456789",
    "PHISHGUARD_ENVIRONMENT": "test",
}


def _settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, **{**BASE, **overrides})  # type: ignore[arg-type]


def test_matching_parts_and_urls_are_accepted() -> None:
    assert _settings() is not None


def test_port_mismatch_is_rejected() -> None:
    with pytest.raises(ValidationError, match="POSTGRES_PORT"):
        _settings(POSTGRES_PORT="9999")


def test_host_mismatch_is_rejected() -> None:
    with pytest.raises(ValidationError, match="POSTGRES_HOST"):
        _settings(DATABASE_URL="postgresql+asyncpg://phishguard:x@127.0.0.2:5434/phishguard")


def test_user_mismatch_is_rejected() -> None:
    with pytest.raises(ValidationError, match="POSTGRES_USER"):
        _settings(DATABASE_URL="postgresql+asyncpg://bob:x@127.0.0.1:5434/phishguard")


def test_database_mismatch_is_rejected() -> None:
    with pytest.raises(ValidationError, match="configured database"):
        _settings(DATABASE_URL="postgresql+asyncpg://phishguard:x@127.0.0.1:5434/other")


def test_test_database_mismatch_is_rejected() -> None:
    with pytest.raises(ValidationError, match="DATABASE_URL_TEST"):
        _settings(DATABASE_URL_TEST="postgresql+asyncpg://phishguard:x@127.0.0.1:5434/phishguard")


def test_alembic_url_may_target_the_test_database() -> None:
    """A migration run against the test database is legitimate."""
    settings = _settings(
        ALEMBIC_DATABASE_URL="postgresql+psycopg://phishguard:x@127.0.0.1:5434/phishguard_test"
    )

    assert settings.alembic_database_url.endswith("phishguard_test")


def test_alembic_url_must_still_match_host_and_port() -> None:
    with pytest.raises(ValidationError, match="ALEMBIC_DATABASE_URL"):
        _settings(
            ALEMBIC_DATABASE_URL="postgresql+psycopg://phishguard:x@127.0.0.1:5432/phishguard"
        )


def test_placeholder_password_is_rejected_outside_test_environment() -> None:
    with pytest.raises(ValidationError, match="placeholder"):
        _settings(
            PHISHGUARD_ENVIRONMENT="development",
            POSTGRES_PASSWORD="replace-me-before-first-run",
        )


def test_placeholder_password_is_allowed_in_test_environment() -> None:
    """The test environment holds no real credential by design."""
    settings = _settings(POSTGRES_PASSWORD="replace-me-before-first-run")

    assert settings.postgres_password.get_secret_value() == "replace-me-before-first-run"


def test_shipped_placeholder_is_in_the_rejected_set() -> None:
    """The value .env.example ships must actually be rejected."""
    from app.core.config import _SECRET_PLACEHOLDERS

    assert "replace-me-before-first-run" in _SECRET_PLACEHOLDERS


BACKEND_ROOT = Path(__file__).parents[1]


def _locked_packages() -> list[str]:
    lines = [
        line.strip()
        for line in (BACKEND_ROOT / "requirements.lock.txt").read_text().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    for line in lines:
        assert re.fullmatch(r"[A-Za-z0-9_.-]+==[^\s;]+", line), line
    return [line.split("==", 1)[0].lower() for line in lines]


def test_dependency_lockfile_exists_and_is_fully_pinned() -> None:
    assert _locked_packages()


def test_dependency_lockfile_covers_direct_requirements() -> None:
    locked = set(_locked_packages())
    for name in (
        "fastapi",
        "sqlalchemy",
        "pydantic",
        "pydantic-settings",
        "pytest",
        "pytest-asyncio",
        "ruff",
        "asyncpg",
        "psycopg",
    ):
        assert name in locked, name
