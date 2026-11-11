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
_SECRET_PLACEHOLDERS = frozenset(
    {
        "replace-me-with-a-generated-value",
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
    # Default mirrors .env.example so a misconfigured deployment surfaces as a
    # connection error, not as an accidental SQLite file in the working tree.
    database_url: str = (
        "postgresql+asyncpg://phishguard:replace-me-before-first-run@localhost:5432/phishguard"
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


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings instance.

    Cached so repeated dependency calls do not re-read the environment, and so
    tests can clear the cache to simulate a different configuration.
    """
    return Settings()  # type: ignore[call-arg]
