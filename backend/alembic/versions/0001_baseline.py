"""Baseline: empty PHISHGUARD schema.

Establishes alembic tracking with no domain tables. Email analysis, phishing
evidence, threat intelligence, risk scoring, investigation and AI agent tables
belong to later milestones.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-11-12 03:47:09
"""

from collections.abc import Sequence

revision: str = "0001_baseline"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Intentionally empty. The schema is definitionally empty at this milestone.
    pass


def downgrade() -> None:
    # Nothing to remove: no domain tables exist yet.
    pass
