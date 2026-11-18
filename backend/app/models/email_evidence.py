"""The ``email_evidence`` table: one accepted upload.

A row is created in the first ingestion transaction with ``status='parsing'``.
The parse transaction then sets the terminal status. The explicit delete
operation tombstones the row: it is marked ``status='deleted'`` and kept, so the
digest and the size survive for audit and so audit events stay linked to it.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import (
    CHAR,
    BigInteger,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.models.analysis_result import AnalysisResult
    from app.models.audit_event import AuditEvent
    from app.models.parsed_email import ParsedEmail

# The lifecycle states of one accepted upload. Kept as a plain tuple so the
# check constraint below and the model cannot drift apart.
STATUS_PARSING = "parsing"
STATUS_PARSED = "parsed"
STATUS_PARSE_FAILED = "parse_failed"
STATUS_DELETED = "deleted"

EMAIL_EVIDENCE_STATUSES: tuple[str, ...] = (
    STATUS_PARSING,
    STATUS_PARSED,
    STATUS_PARSE_FAILED,
    STATUS_DELETED,
)


class EmailEvidence(Base):
    """One accepted upload: its bytes, its digest, and its parse state."""

    __tablename__ = "email_evidence"

    __table_args__ = (
        CheckConstraint(
            "status IN ('parsing','parsed','parse_failed','deleted')",
            name="status",
        ),
        CheckConstraint(
            "(status = 'deleted' AND deleted_at IS NOT NULL) "
            "OR (status <> 'deleted' AND deleted_at IS NULL)",
            name="deleted_state",
        ),
        Index("ix_email_evidence_sha256", "sha256"),
        Index("ix_email_evidence_received_at", "received_at"),
        Index("ix_email_evidence_status", "status"),
        Index("ix_email_evidence_deleted_at", "deleted_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, server_default=text("gen_random_uuid()")
    )
    received_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    # The application sets this explicitly on update; the column default only
    # covers the insert.
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
    sha256: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    storage_id: Mapped[str] = mapped_column(String(128), nullable=False)
    # Attacker-controlled and possibly personal. Cleared on deletion.
    original_filename: Mapped[str | None] = mapped_column(String(512), nullable=True)
    declared_content_type: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    parser_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    defect_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    limit_exceeded: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Machine-readable. Never a traceback and never message content.
    failure_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    deleted_at: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships. The database owns every cascade (see the foreign keys), so
    # ``passive_deletes`` keeps the ORM from duplicating that work.
    parsed_email: Mapped[ParsedEmail | None] = relationship(
        back_populates="email_evidence",
        uselist=False,
        passive_deletes=True,
    )
    analysis_result: Mapped[AnalysisResult | None] = relationship(
        back_populates="email_evidence",
        uselist=False,
        passive_deletes=True,
    )
    audit_events: Mapped[list[AuditEvent]] = relationship(
        back_populates="email_evidence",
        passive_deletes=True,
    )


__all__ = ["EMAIL_EVIDENCE_STATUSES", "EmailEvidence"]
