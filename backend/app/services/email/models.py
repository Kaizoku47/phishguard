"""Result types for the email parser.

These dataclasses mirror the fields the ingestion layer will persist. They are
plain data: no ORM objects, no network handles and no parsed attachment bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

PARSER_CATEGORIES = frozenset(
    {"container", "body", "inline", "attachment", "attached_message", "unknown"}
)
PERSISTED_CATEGORIES = frozenset({"attachment", "inline", "unknown"})

# Parser category -> persisted category. Bodies and containers are absent
# because they are never stored as attachment rows.
PERSISTED_CATEGORY_MAP = {
    "attachment": "attachment",
    "attached_message": "attachment",
    "inline": "inline",
    "unknown": "unknown",
}

# Parser-result-only body decoding states. The architecture defines no
# persisted field for these; they let a caller distinguish trustworthy body
# text from partial or unavailable content without inventing a database column.
BODY_DECODE_OK = "ok"
BODY_DECODE_MALFORMED = "malformed"
BODY_DECODE_UNDECODABLE = "undecodable"


@dataclass(frozen=True, slots=True)
class AttachmentMetadata:
    """Untrusted metadata for one leaf part.

    ``sha256`` is NULL exactly when ``decode_ok`` is false (Q-2). A zero-length
    but successfully decoded part has the digest of the empty string, which is
    a different state from an unavailable digest.
    """

    part_index: int
    category: str
    filename: str | None
    declared_content_type: str | None
    detected_content_type: str | None
    content_disposition: str | None
    content_transfer_encoding: str | None
    size_bytes: int | None
    sha256: str | None
    decode_ok: bool


@dataclass(frozen=True, slots=True)
class Link:
    """A URL found in a message body. Never fetched."""

    url: str
    host: str

    def as_dict(self) -> dict[str, str]:
        return {"url": self.url, "host": self.host}


@dataclass(slots=True)
class ParseResult:
    """The complete, deterministic result of parsing one raw message.

    ``status`` is ``parsed`` or ``parse_failed``. A failed parse still carries
    whatever metadata was collected before the failure; the raw evidence is
    preserved outside the parser.
    """

    status: str
    parser_version: str
    subject: str | None = None
    from_address: str | None = None
    from_display_name: str | None = None
    to_addresses: list[str] = field(default_factory=list)
    cc_addresses: list[str] = field(default_factory=list)
    reply_to_addresses: list[str] = field(default_factory=list)
    date_header: str | None = None
    date_parsed: datetime | None = None
    date_assumed_utc: bool = False
    message_id: str | None = None
    headers: dict[str, list[str]] = field(default_factory=dict)
    text_body: str | None = None
    html_body: str | None = None
    body_charset: str | None = None
    # Aggregate over body parts: ok, malformed, undecodable, or None when there
    # was no body. Malformed/undecodable bodies are not stored as body text.
    body_decode_status: str | None = None
    links: list[dict[str, str]] = field(default_factory=list)
    multipart: bool = False
    part_count: int = 0
    max_depth: int = 0
    # defect_count is the total number of defect occurrences. defect_types is
    # the deduplicated list of defect class names; defect values are never kept.
    defect_count: int = 0
    defect_types: list[str] = field(default_factory=list)
    attachments: list[AttachmentMetadata] = field(default_factory=list)
    limit_exceeded: str | None = None
    failure_reason: str | None = None

    @property
    def defect_types_json(self) -> list[str]:
        """Class names only; defect values may contain attacker input."""
        return list(self.defect_types)
