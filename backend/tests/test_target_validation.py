"""Tests for database target validation and configuration consistency.

These guard the safety rules that keep PHISHGUARD away from other projects'
databases on this host. They need no database and no Docker.
"""

from __future__ import annotations

import pytest
from app.db.target import (
    EXPECTED_TEST_DATABASE,
    UnsafeTargetError,
    is_valid_database_name,
    validate_test_target,
)

VALID_URL = f"postgresql+asyncpg://phishguard:secret@127.0.0.1:5434/{EXPECTED_TEST_DATABASE}"


def test_valid_target_is_accepted() -> None:
    validate_test_target(VALID_URL)


@pytest.mark.parametrize(
    "url",
    [
        # Native PostgreSQL on this host.
        f"postgresql+asyncpg://phishguard:secret@127.0.0.1:5432/{EXPECTED_TEST_DATABASE}",
        # Another project's container.
        f"postgresql+asyncpg://phishguard:secret@127.0.0.1:5433/{EXPECTED_TEST_DATABASE}",
        # A port that is not the PHISHGUARD service.
        f"postgresql+asyncpg://phishguard:secret@127.0.0.1:5435/{EXPECTED_TEST_DATABASE}",
        # A different host.
        f"postgresql+asyncpg://phishguard:secret@localhost:5434/{EXPECTED_TEST_DATABASE}",
        # The development database.
        "postgresql+asyncpg://phishguard:secret@127.0.0.1:5434/phishguard",
        # A different database on the right server.
        "postgresql+asyncpg://phishguard:secret@127.0.0.1:5434/somewhere_else",
        # A missing port.
        f"postgresql+asyncpg://phishguard:secret@127.0.0.1/{EXPECTED_TEST_DATABASE}",
        # Not PostgreSQL at all.
        f"mysql://phishguard:secret@127.0.0.1:5434/{EXPECTED_TEST_DATABASE}",
    ],
    ids=[
        "native-postgres-5432",
        "other-project-5433",
        "wrong-port",
        "wrong-host",
        "development-database",
        "other-database",
        "missing-port",
        "wrong-scheme",
    ],
)
def test_unsafe_targets_are_refused(url: str) -> None:
    with pytest.raises(UnsafeTargetError):
        validate_test_target(url)


def test_refusal_never_contains_the_password() -> None:
    """A refusal message must not echo the credential back to the terminal."""
    url = "postgresql+asyncpg://phishguard:super-secret-value@127.0.0.1:5432/phishguard_test"

    with pytest.raises(UnsafeTargetError) as exc_info:
        validate_test_target(url)

    assert "super-secret-value" not in str(exc_info.value)


@pytest.mark.parametrize(
    ("name", "valid"),
    [
        ("phishguard_test", True),
        ("_leading_underscore", True),
        ("Mixed_Case_9", True),
        ("9starts_with_digit", False),
        ("", False),
        ("has space", False),
        ("has-dash", False),
        ("has;semicolon", False),
        ('has"quote', False),
        ("a" * 64, False),
    ],
)
def test_database_name_validation(name: str, valid: bool) -> None:
    assert is_valid_database_name(name) is valid


def test_sync_driver_url_is_accepted() -> None:
    """Alembic uses the psycopg driver against the same server."""
    validate_test_target(
        f"postgresql+psycopg://phishguard:secret@127.0.0.1:5434/{EXPECTED_TEST_DATABASE}"
    )
