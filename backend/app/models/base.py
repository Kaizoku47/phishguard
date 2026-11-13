"""SQLAlchemy 2.0 declarative base and naming conventions.

This module defines the single shared metadata for PHISHGUARD. It deliberately
contains no domain tables: email analysis, phishing evidence, threat
intelligence, risk scoring, investigation jobs and AI agent tables all belong
to later milestones. Adding them here would create speculative schema.

Naming conventions are applied here so every table, constraint and index
created in the future follows one rule set, which makes migration history
readable and lets Alembic generate consistent names.
"""

from __future__ import annotations

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

# Naming conventions. Applied to every table, unique constraint, check
# constraint, index and foreign key that is created from this metadata.
# Alembic's `--autogenerate` then produces stable, descriptive names instead of
# opaque auto-generated ones such as "ix_table_column_1".
NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(table_name)s_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Shared declarative base for every PHISHGUARD ORM model."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


__all__ = ["Base", "NAMING_CONVENTION"]
