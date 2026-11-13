"""Shared validation for the PHISHGUARD integration-test database target.

Both the bootstrap script and the integration test fixtures use these rules, so
there is exactly one definition of "this is a safe target".

The rules exist because this machine hosts several PostgreSQL instances:
a native one on 5432, another project's container on 5433, and PHISHGUARD's own
on 5434. A mistyped port must fail loudly, not quietly create or destroy a
database somewhere else.
"""

from __future__ import annotations

from urllib.parse import urlparse

# The PHISHGUARD PostgreSQL service, as published by docker-compose.yml.
EXPECTED_HOST = "127.0.0.1"
EXPECTED_PORT = 5434

# The only database the integration suite may touch.
EXPECTED_TEST_DATABASE = "phishguard_test"

# The development database, which the integration suite must never touch.
DEVELOPMENT_DATABASE = "phishguard"

# Ports that belong to other software on this host and must never be used.
FORBIDDEN_PORTS = frozenset({5432, 5433})


class UnsafeTargetError(RuntimeError):
    """Raised when a requested database target is not the intended one."""


def validate_test_target(url: str, expected_database: str = EXPECTED_TEST_DATABASE) -> None:
    """Validate that a URL points at the PHISHGUARD test database.

    Raises :class:`UnsafeTargetError` before any connection is attempted.
    """
    parsed = urlparse(url)

    if parsed.scheme not in {"postgresql+asyncpg", "postgresql+psycopg"}:
        raise UnsafeTargetError(f"expected a PostgreSQL URL, got scheme {parsed.scheme!r}")

    if parsed.hostname != EXPECTED_HOST:
        raise UnsafeTargetError(
            f"refusing to use host {parsed.hostname!r}; the PHISHGUARD service is {EXPECTED_HOST!r}"
        )

    # A malformed port must be refused, not crash the caller.
    try:
        port = parsed.port
    except ValueError:
        raise UnsafeTargetError("the target URL has no valid port") from None

    if port in FORBIDDEN_PORTS:
        raise UnsafeTargetError(
            f"refusing to use port {port}; it belongs to another PostgreSQL instance on this host"
        )

    if port != EXPECTED_PORT:
        raise UnsafeTargetError(
            f"refusing to use port {port}; the PHISHGUARD service is published on {EXPECTED_PORT}"
        )

    database = parsed.path.lstrip("/")
    if not database:
        raise UnsafeTargetError("the target URL has no database name")

    if database == DEVELOPMENT_DATABASE:
        raise UnsafeTargetError(
            "refusing to use the development database; "
            "integration tests must use a separate test database"
        )

    if database != expected_database:
        raise UnsafeTargetError(
            f"refusing to use database {database!r}; "
            f"the integration test database is {expected_database!r}"
        )


def is_valid_database_name(name: str) -> bool:
    """True when a database name is safe to interpolate into an identifier.

    PostgreSQL identifiers may contain letters, digits and underscores, and may
    not start with a digit. Restricting to that set means a name can never
    carry a quote, a semicolon or whitespace.
    """
    if not name or len(name) > 63:
        return False
    if not name[0].isalpha() and name[0] != "_":
        return False
    return all(char.isalnum() or char == "_" for char in name)
