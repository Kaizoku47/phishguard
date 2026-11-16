"""The ``audit_events`` table: the security-relevant audit trail.

Every row records that something security-relevant happened: an upload, a
deletion, an integrity failure, a re-parse. The ``detail`` column holds
counts, digests and reason codes - never email content, never a credential.

Rows are append-only. The ``email_evidence_id`` foreign key uses
``ON DELETE SET NULL`` so that an audit record survives even a physical
deletion of its subject. In the normal MVP flow the evidence row is
*tombstoned* rather than deleted, so the link stays intact.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.models.email_evidence import EmailEvidence

EVENT_UPLOADED = "uploaded"
EVENT_DELETED = "deleted"
EVENT_INTEGRITY_FAILURE = "integrity_failure"
EVENT_REPARSE_COMPLETED = "reparse_completed"

AUDIT_EVENT_TYPES: tuple[str, ...] = (
    EVENT_UPLOADED,
    EVENT_DELETED,
    EVENT_INTEGRITY_FAILURE,
    EVENT_REPARSE_COMPLETED,
)


class AuditEvent(Base):
    """One append-only audit record."""

    __tablename__ = "audit_events"

    __table_args__ = (
        Index("ix_audit_events_occurred_at", "occurred_at"),
        Index("ix_audit_events_email_evidence_id", "email_evidence_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, server_default=text("gen_random_uuid()")
    )
    occurred_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # Nullable: an audit record may outlive a physical deletion of its subject.
    email_evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid,
        ForeignKey("email_evidence.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Counts, digests and reason codes only. Never content.
    detail: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    actor: Mapped[str | None] = mapped_column(String(128), nullable=True)

    email_evidence: Mapped[EmailEvidence | None] = relationship(back_populates="audit_events")


__all__ = ["AUDIT_EVENT_TYPES", "AuditEvent"]
