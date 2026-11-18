"""Application settings.

Configuration is read once from the environment (and an optional local ``.env``
file) and validated immediately. Invalid or unsafe values stop the process at
startup rather than degrading silently at request time.

Secrets are declared with ``SecretStr`` so a stray ``repr()``, log record or
traceback cannot print their contents.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.services.email.limits import ParserLimits

Environment = Literal["development", "test", "staging", "production"]


def default_evidence_root() -> Path:
    """The default evidence root.

    ``XDG_DATA_HOME`` is honoured when it is set, as the XDG base directory
    specification requires. Otherwise the default is
    ``~/.local/share/phishguard/evidence``.

    The root lives outside the Git repository on purpose: ``.gitignore``
    covers ``evidence/`` and ``uploads/`` but not ``data/``, and a default
    inside the working tree would put evidence bytes into a directory that is
    easy to commit by accident.
    """
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    if xdg_data_home:
        return Path(xdg_data_home) / "phishguard" / "evidence"
    return Path.home() / ".local" / "share" / "phishguard" / "evidence"


def _project_root() -> Path:
    """The PHISHGUARD project tree, used to refuse an evidence root inside it.

    The repository root is located by walking up from this file until a
    directory holding a ``.git`` entry is found. When the package is
    installed outside a checkout the nearest parent is used instead, which is
    still the right answer for the "inside the project tree" rule.
    """
    here = Path(__file__).resolve()
    for candidate in here.parents:
        if (candidate / ".git").exists():
            return candidate
    return here.parents[2]


def validate_evidence_root(root: Path) -> Path:
    """Refuse an evidence root that is dangerous.

    Three roots are refused, because each one would put untrusted email bytes
    somewhere they do not belong: the filesystem root, a home directory
    itself, and anything inside the PHISHGUARD project tree.

    The comparison uses resolved paths, so a symlink cannot disguise a
    dangerous root. An unsafe root is never silently relocated: the process
    fails to start and the operator fixes the configuration.
    """
    resolved = root.expanduser().resolve()

    if resolved == Path(resolved.anchor):
        raise ValueError("PHISHGUARD_EVIDENCE_ROOT must not be the filesystem root")

    try:
        home = Path.home().resolve()
    except (RuntimeError, OSError):  # pragma: no cover - no home directory
        home = None
    if home is not None and resolved == home:
        raise ValueError("PHISHGUARD_EVIDENCE_ROOT must not be the home directory")

    project = _project_root().resolve()
    if resolved == project or resolved.is_relative_to(project):
        raise ValueError("PHISHGUARD_EVIDENCE_ROOT must not be inside the PHISHGUARD project tree")

    return resolved


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

    # -- Email parser limits -------------------------------------------------
    # These mirror app.services.email.limits. Depth and part count bound
    # extraction, not construction of the MIME tree. The deadline is a monitor
    # and never terminates a synchronous parse.
    max_mime_depth: Annotated[int, Field(ge=1, le=100)] = Field(
        default=10, validation_alias="PHISHGUARD_MAX_MIME_DEPTH"
    )
    max_mime_parts: Annotated[int, Field(ge=1, le=10000)] = Field(
        default=500, validation_alias="PHISHGUARD_MAX_MIME_PARTS"
    )
    max_header_count: Annotated[int, Field(ge=1, le=10000)] = Field(
        default=200, validation_alias="PHISHGUARD_MAX_HEADER_COUNT"
    )
    max_header_length: Annotated[int, Field(ge=1, le=1024 * 1024)] = Field(
        default=16 * 1024, validation_alias="PHISHGUARD_MAX_HEADER_LENGTH"
    )
    max_decoded_body_bytes: Annotated[int, Field(gt=0, le=100 * 1024 * 1024)] = Field(
        default=10 * 1024 * 1024, validation_alias="PHISHGUARD_MAX_DECODED_BODY_BYTES"
    )
    max_concurrent_uploads: Annotated[int, Field(ge=1, le=64)] = Field(
        default=4, validation_alias="PHISHGUARD_MAX_CONCURRENT_UPLOADS"
    )
    parser_deadline_seconds: Annotated[int, Field(ge=1, le=3600)] = Field(
        default=30, validation_alias="PHISHGUARD_PARSER_DEADLINE_SECONDS"
    )

    def to_parser_limits(self) -> ParserLimits:
        """Build :class:`ParserLimits` from these validated settings.

        ``max_concurrent_uploads`` is ingestion concurrency control and is
        deliberately not copied here. ``magic_sniff_bytes`` keeps its constant.
        The parser itself does not import Settings; the ingestion service in
        Milestone 2.3.4 will call this at the boundary.
        """
        return ParserLimits(
            max_upload_bytes=self.max_upload_bytes,
            max_mime_depth=self.max_mime_depth,
            max_mime_parts=self.max_mime_parts,
            max_header_count=self.max_header_count,
            max_header_length=self.max_header_length,
            max_decoded_body_bytes=self.max_decoded_body_bytes,
            deadline_seconds=self.parser_deadline_seconds,
        )

    # -- Evidence storage ---------------------------------------------------
    # Where uploaded messages are stored. The root is outside the Git
    # repository and outside any served directory. Startup refuses "/" , a home
    # directory and anything inside the project tree.
    evidence_root: Path = Field(
        default_factory=default_evidence_root,
        validation_alias="PHISHGUARD_EVIDENCE_ROOT",
        description="Filesystem root for stored evidence. Never inside the project tree.",
    )

    @field_validator("evidence_root")
    @classmethod
    def _reject_dangerous_evidence_root(cls, value: Path) -> Path:
        return validate_evidence_root(value)

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
