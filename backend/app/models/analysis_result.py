"""The ``analysis_results`` table: one current result per evidence record.

The deterministic analysis writes this row: the score, the risk band, the
signals and the intelligence results. The AI agent may later fill in the
narrative, and touches only the three narrative columns.

There is no history and no versioned collection. A re-analysis replaces the
row.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.models.email_evidence import EmailEvidence

RISK_BAND_LOW = "low"
RISK_BAND_MEDIUM = "medium"
RISK_BAND_HIGH = "high"
RISK_BAND_CRITICAL = "critical"

ANALYSIS_RISK_BANDS: tuple[str, ...] = (
    RISK_BAND_LOW,
    RISK_BAND_MEDIUM,
    RISK_BAND_HIGH,
    RISK_BAND_CRITICAL,
)

NARRATIVE_AVAILABLE = "available"
NARRATIVE_UNAVAILABLE = "unavailable"
NARRATIVE_DISABLED = "disabled"
NARRATIVE_FAILED = "failed"

ANALYSIS_NARRATIVE_STATUSES: tuple[str, ...] = (
    NARRATIVE_AVAILABLE,
    NARRATIVE_UNAVAILABLE,
    NARRATIVE_DISABLED,
    NARRATIVE_FAILED,
)


class AnalysisResult(Base):
    """The deterministic result for one evidence record, plus the narrative."""

    __tablename__ = "analysis_results"

    __table_args__ = (
        UniqueConstraint("email_evidence_id", name="uq_analysis_results_email_evidence_id"),
        CheckConstraint("score BETWEEN 0 AND 100", name="score"),
        CheckConstraint(
            "risk_band IN ('low','medium','high','critical')",
            name="band",
        ),
        CheckConstraint(
            "(narrative_status = 'available' AND narrative IS NOT NULL) "
            "OR (narrative_status <> 'available' AND narrative IS NULL)",
            name="narrative_state",
        ),
        Index("ix_analysis_results_email_evidence_id", "email_evidence_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, server_default=text("gen_random_uuid()")
    )
    email_evidence_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("email_evidence.id", ondelete="CASCADE"),
        nullable=False,
    )
    # The deterministic total. Reproducible from the same bytes and the same
    # engine_version.
    score: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    risk_band: Mapped[str] = mapped_column(String(16), nullable=False)
    # Each entry is {id, severity, contribution, reason, evaluated}. A signal
    # with evaluated=false contributes nothing to the score.
    signals: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False)
    # {domains: {...}, hashes: {...}, missing: [...]}
    intelligence_results: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    # Supplementary. AI-generated prose. It explains; it does not decide.
    narrative: Mapped[str | None] = mapped_column(Text, nullable=True)
    narrative_status: Mapped[str] = mapped_column(String(24), nullable=False)
    # A short sanitised reason, so "unavailable" can be told apart from
    # "not yet produced".
    narrative_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The provenance of the score.
    engine_version: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    email_evidence: Mapped[EmailEvidence] = relationship(back_populates="analysis_result")


__all__ = [
    "ANALYSIS_NARRATIVE_STATUSES",
    "ANALYSIS_RISK_BANDS",
    "AnalysisResult",
]
