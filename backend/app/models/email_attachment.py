"""The ``email_attachments`` table: metadata for each leaf MIME part.

Attachment bytes are never stored separately. The original ``.eml`` evidence
already holds them. This table records the metadata only, and the decoded
SHA-256 when - and only when - the decoded bytes could be established
reliably.

The ``decode_ok``/``sha256`` pair is enforced by a check constraint, so the
contradictory combinations cannot exist in the database.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import (
    CHAR,
    Boolean,
    CheckConstraint,
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
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.models.parsed_email import ParsedEmail

CATEGORY_ATTACHMENT = "attachment"
CATEGORY_INLINE = "inline"
CATEGORY_UNKNOWN = "unknown"

EMAIL_ATTACHMENT_CATEGORIES: tuple[str, ...] = (
    CATEGORY_ATTACHMENT,
    CATEGORY_INLINE,
    CATEGORY_UNKNOWN,
)


class EmailAttachment(Base):
    """Metadata for one leaf part of a parsed message."""

    __tablename__ = "email_attachments"

    __table_args__ = (
        UniqueConstraint(
            "parsed_email_id",
            "part_index",
            name="uq_email_attachments_parsed_email_id_part_index",
        ),
        CheckConstraint(
            "(decode_ok = true AND sha256 IS NOT NULL) OR (decode_ok = false AND sha256 IS NULL)",
            name="digest_state",
        ),
        CheckConstraint(
            "category IN ('attachment','inline','unknown')",
            name="category",
        ),
        Index("ix_email_attachments_parsed_email_id", "parsed_email_id"),
        Index("ix_email_attachments_sha256", "sha256"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, server_default=text("gen_random_uuid()")
    )
    parsed_email_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("parsed_emails.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    part_index: Mapped[int] = mapped_column(Integer, nullable=False)
    category: Mapped[str] = mapped_column(String(16), nullable=False)
    # Verbatim, attacker-controlled. Never used to construct a path.
    filename: Mapped[str | None] = mapped_column(Text, nullable=True)
    declared_content_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    detected_content_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_disposition: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_transfer_encoding: Mapped[str | None] = mapped_column(Text, nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Null when the decoded bytes could not be established reliably.
    sha256: Mapped[str | None] = mapped_column(CHAR(64), nullable=True)
    decode_ok: Mapped[bool] = mapped_column(Boolean, nullable=False)

    parsed_email: Mapped[ParsedEmail] = relationship(back_populates="attachments")


__all__ = ["EMAIL_ATTACHMENT_CATEGORIES", "EmailAttachment"]
