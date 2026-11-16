"""The ``parsed_emails`` table: the normalised view of one parsed message.

One row per evidence object. The ``email_evidence_id`` foreign key is unique,
so the row is never shared between uploads. This is the highest-sensitivity
table in the schema: it holds the subject, the addresses, every header, both
bodies and the link list. It is hard-deleted with its evidence.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
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
    from app.models.email_attachment import EmailAttachment
    from app.models.email_evidence import EmailEvidence


class ParsedEmail(Base):
    """The parsed, normalised content of one evidence object."""

    __tablename__ = "parsed_emails"

    __table_args__ = (
        UniqueConstraint("email_evidence_id", name="uq_parsed_emails_email_evidence_id"),
        Index("ix_parsed_emails_created_at", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, server_default=text("gen_random_uuid()")
    )
    email_evidence_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("email_evidence.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    parser_version: Mapped[str] = mapped_column(String(32), nullable=False)

    # Untrusted sender-controlled values, stored verbatim.
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    from_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    from_display_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    to_addresses: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    cc_addresses: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    reply_to_addresses: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)
    # The raw header is preserved; the parsed value is null when unparseable.
    date_header: Mapped[str | None] = mapped_column(Text, nullable=True)
    date_parsed: Mapped[DateTime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Verbatim and not trusted: the sender controls it and it is not unique.
    message_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    headers: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    text_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Stored as data. Never rendered by the API.
    html_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_charset: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # URLs as text. Never fetched.
    links: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB, nullable=True)
    multipart: Mapped[bool] = mapped_column(Boolean, nullable=False)
    part_count: Mapped[int] = mapped_column(Integer, nullable=False)
    max_depth: Mapped[int] = mapped_column(Integer, nullable=False)
    defect_count: Mapped[int] = mapped_column(Integer, nullable=False)
    # Class names only, never the defect values.
    defect_types: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)

    email_evidence: Mapped[EmailEvidence] = relationship(back_populates="parsed_email")
    attachments: Mapped[list[EmailAttachment]] = relationship(
        back_populates="parsed_email",
        passive_deletes=True,
    )


__all__ = ["ParsedEmail"]
