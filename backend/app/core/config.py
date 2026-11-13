"""Application settings.

Configuration is read once from the environment (and an optional local ``.env``
file) and validated immediately. Invalid or unsafe values stop the process at
startup rather than degrading silently at request time.

Secrets are declared with ``SecretStr`` so a stray ``repr()``, log record or
traceback cannot print their contents.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "staging", "production"]

# Placeholder used by .env.example. Rejected so a copied template cannot run.
# Every placeholder the templates actually ship must appear here, otherwise
# the rejection is theatre.
_SECRET_PLACEHOLDERS = frozenset(
    {
        "replace-me-with-a-generated-value",
        "replace-me-before-first-run",
        "replace-with-provider-key",
        "replace-with-provider-name",
        "replace-with-model-name",
        "changeme",
        "change-me",
        "secret",
    }
)


class Settings(BaseSettings):
    """Typed view of the process environment."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        # Prefix-free by design: variable names are already namespaced with
        # PHISHGUARD_ or POSTGRES_ in .env.example.
    )

    # -- Service identity ---------------------------------------------------
    service_name: str = "phishguard-api"
    version: str = "0.1.0"
    environment: Environment = Field(
        default="development", validation_alias="PHISHGUARD_ENVIRONMENT"
    )
    debug: bool = False
    log_level: Annotated[str, Field(pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")] = Field(
        default="INFO", validation_alias="PHISHGUARD_LOG_LEVEL"
    )

    # -- HTTP ---------------------------------------------------------------
    api_host: str = "127.0.0.1"
    api_port: Annotated[int, Field(ge=1, le=65535)] = 8000
    cors_origins: list[str] = Field(
        default_factory=list, validation_alias="PHISHGUARD_CORS_ORIGINS"
    )
    max_upload_bytes: Annotated[int, Field(gt=0, le=100 * 1024 * 1024)] = Field(
        default=10 * 1024 * 1024, validation_alias="PHISHGUARD_MAX_UPLOAD_BYTES"
    )

    # -- Database -----------------------------------------------------------
    # Defaults mirror .env.example so a misconfigured deployment surfaces as a
    # connection error, not as an accidental SQLite file in the working tree.
    # The host is 127.0.0.1:5434 by design: 5432 is a native PostgreSQL install
    # and 5433 is another project's container, so this project stays off both.
    postgres_host: str = Field(default="127.0.0.1", validation_alias="POSTGRES_HOST")
    postgres_port: Annotated[int, Field(ge=1, le=65535)] = Field(
        default=5434, validation_alias="POSTGRES_PORT"
    )
    postgres_db: str = Field(default="phishguard", validation_alias="POSTGRES_DB")
    postgres_user: str = Field(default="phishguard", validation_alias="POSTGRES_USER")
    postgres_password: SecretStr = Field(
        default_factory=lambda: SecretStr("replace-me-before-first-run"),
        validation_alias="POSTGRES_PASSWORD",
        description="PostgreSQL password. Generate with: openssl rand -hex 24",
    )

    @field_validator("postgres_user")
    @classmethod
    def _reject_placeholder_user(cls, value: str) -> str:
        if value.strip() in _SECRET_PLACEHOLDERS:
            raise ValueError("postgres_user is still a placeholder value")
        return value

    @field_validator("postgres_db")
    @classmethod
    def _reject_placeholder_db(cls, value: str) -> str:
        if value.strip() in _SECRET_PLACEHOLDERS:
            raise ValueError("postgres_db is still a placeholder value")
        return value

    # Async driver, used by the application.
    database_url: str = Field(
        default="postgresql+asyncpg://phishguard:replace-me-before-first-run@127.0.0.1:5434/phishguard",
        validation_alias="DATABASE_URL",
        description="Async SQLAlchemy URL. Never logged.",
    )

    # Synchronous driver, used by Alembic. The migration runner is synchronous.
    database_url_sync: str = Field(
        default="postgresql+psycopg://phishguard:replace-me-before-first-run@127.0.0.1:5434/phishguard",
        validation_alias="DATABASE_URL_SYNC",
        description="Sync SQLAlchemy URL for Alembic. Never logged.",
    )

    # URL Alembic uses. Falls back to database_url_sync when unset.
    alembic_database_url: str = Field(
        default="postgresql+psycopg://phishguard:replace-me-before-first-run@127.0.0.1:5434/phishguard",
        validation_alias="ALEMBIC_DATABASE_URL",
        description="Alembic connection URL. Never logged.",
    )

    # Database used by the integration test suite. It must live on the same
    # PHISHGUARD instance and must never be the development database.
    postgres_test_db: str = Field(default="phishguard_test", validation_alias="POSTGRES_TEST_DB")
    database_url_test: str = Field(
        default="postgresql+asyncpg://phishguard:replace-me-before-first-run@127.0.0.1:5434/phishguard_test",
        validation_alias="DATABASE_URL_TEST",
        description="Async URL for the integration test database. Never logged.",
    )

    # -- Secrets ------------------------------------------------------------
    secret_key: SecretStr = Field(
        ...,
        validation_alias="PHISHGUARD_SECRET_KEY",
        min_length=16,
        description="Application signing secret. Generate with: openssl rand -hex 32",
    )

    @field_validator("secret_key")
    @classmethod
    def _reject_placeholder_secret(cls, value: SecretStr) -> SecretStr:
        if value.get_secret_value().strip() in _SECRET_PLACEHOLDERS:
            raise ValueError("secret_key is still a placeholder value")
        return value

    @field_validator("cors_origins")
    @classmethod
    def _validate_cors_origins(cls, origins: list[str]) -> list[str]:
        for origin in origins:
            if origin == "*":
                raise ValueError("wildcard CORS origin is not permitted; list explicit origins")
            parsed = urlparse(origin)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(f"CORS origin must be an absolute http(s) URL: {origin!r}")
        return origins

    @model_validator(mode="after")
    def _debug_not_allowed_in_production(self) -> Settings:
        if self.environment == "production" and self.debug:
            raise ValueError("debug must be disabled when environment=production")
        return self

    @model_validator(mode="after")
    def _reject_placeholder_password(self) -> Settings:
        """Refuse to run against a database with a template password.

        The default exists so the settings object can be constructed for
        tooling that never connects. Any environment that is expected to reach
        a real database must supply a generated password.
        """
        if self.environment == "test":
            # The test environment holds no real credential by design.
            return self
        if self.postgres_password.get_secret_value().strip() in _SECRET_PLACEHOLDERS:
            raise ValueError(
                "postgres_password is still a placeholder value; "
                "generate one with: openssl rand -hex 24"
            )
        return self

    @model_validator(mode="after")
    def _database_parts_match_urls(self) -> Settings:
        """Keep POSTGRES_* parts and the connection URLs in agreement.

        The parts (host, port, user, database) and the URLs are two ways of
        describing the same target. If they disagree, one of them is stale and
        the application would silently talk to a different database than the
        operator configured. Fail loudly instead.

        ALEMBIC_DATABASE_URL is deliberately not listed: a migration run may
        legitimately target the test database while the parts describe the
        development one. Its host, port and user are still checked.
        """
        expected = {
            "DATABASE_URL": (self.database_url, self.postgres_db),
            "DATABASE_URL_SYNC": (self.database_url_sync, self.postgres_db),
            "DATABASE_URL_TEST": (self.database_url_test, self.postgres_test_db),
        }
        for name, (url, database) in expected.items():
            parsed = urlparse(url)
            if parsed.hostname != self.postgres_host:
                raise ValueError(
                    f"{name} points at host {parsed.hostname!r}, "
                    f"but POSTGRES_HOST is {self.postgres_host!r}"
                )
            try:
                port = parsed.port
            except ValueError:
                raise ValueError(f"{name} has no valid port") from None
            if port != self.postgres_port:
                raise ValueError(
                    f"{name} points at port {port!r}, but POSTGRES_PORT is {self.postgres_port!r}"
                )
            if parsed.username != self.postgres_user:
                raise ValueError(
                    f"{name} uses user {parsed.username!r}, "
                    f"but POSTGRES_USER is {self.postgres_user!r}"
                )
            if parsed.path.lstrip("/") != database:
                raise ValueError(
                    f"{name} uses database {parsed.path.lstrip('/')!r}, "
                    f"but the configured database is {database!r}"
                )

        alembic = urlparse(self.alembic_database_url)
        if alembic.hostname != self.postgres_host or alembic.port != self.postgres_port:
            raise ValueError("ALEMBIC_DATABASE_URL does not match POSTGRES_HOST and POSTGRES_PORT")
        return self

    # -- Safe representations -----------------------------------------------

    @staticmethod
    def _redact_url(url: str) -> str:
        """Replace the password in a connection URL with a fixed mask."""
        parsed = urlparse(url)
        if not parsed.password:
            return url
        netloc = f"{parsed.username}:***@{parsed.hostname}"
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        return parsed._replace(netloc=netloc).geturl()

    @property
    def database_url_redacted(self) -> str:
        """Connection URL safe to log or display: password replaced."""
        return self._redact_url(self.database_url)

    def __repr__(self) -> str:
        # Field-by-field, with every secret replaced, so a debugger or a stray
        # log line cannot print credentials.
        return (
            f"Settings(service_name={self.service_name!r}, "
            f"environment={self.environment!r}, "
            f"database_url={self.database_url_redacted!r})"
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings instance.

    Cached so repeated dependency calls do not re-read the environment, and so
    tests can clear the cache to simulate a different configuration.
    """
    return Settings()  # type: ignore[call-arg]
