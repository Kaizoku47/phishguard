"""Parser resource limits.

The architecture (Revision 5.2.1, §8.7) is explicit about what these limits do
and do not bound:

- The 10 MiB upload cap is the primary control. It bounds the parser's input,
  and therefore the MIME tree and every allocation derived from it.
- MIME depth and part count are applied during **traversal**, after
  ``BytesParser.parsebytes()`` has already constructed the whole tree. They do
  not bound tree construction.
- The 30-second deadline is a wall-clock monitor. Parsing is synchronous, so an
  asyncio timeout cannot interrupt it. The monitor logs an overrun; it does not
  terminate the parse.
"""

from __future__ import annotations

from dataclasses import dataclass

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_MIME_DEPTH = 10
MAX_MIME_PART_COUNT = 500
MAX_HEADER_COUNT = 200
MAX_HEADER_LENGTH = 16 * 1024
MAX_DECODED_BODY_BYTES = 10 * 1024 * 1024
MAX_CONCURRENT_UPLOADS = 4
PARSER_DEADLINE_SECONDS = 30

# Attachment content-type detection reads at most this many decoded bytes.
# It is a bounded observation, never a security verdict.
MAGIC_SNIFF_BYTES = 512

# Transfer encodings whose decoded bytes are considered established. An
# unrecognised encoding is a Q-2 failure: sha256 stays NULL and decode_ok false.
KNOWN_TRANSFER_ENCODINGS = frozenset({"base64", "quoted-printable", "7bit", "8bit", "binary"})

PARSER_VERSION = "phishguard-parser-2.3.3"


@dataclass(frozen=True, slots=True)
class ParserLimits:
    """Bounds applied by :func:`app.services.email.parser.parse_email`."""

    max_upload_bytes: int = MAX_UPLOAD_BYTES
    max_mime_depth: int = MAX_MIME_DEPTH
    max_mime_parts: int = MAX_MIME_PART_COUNT
    max_header_count: int = MAX_HEADER_COUNT
    max_header_length: int = MAX_HEADER_LENGTH
    max_decoded_body_bytes: int = MAX_DECODED_BODY_BYTES
    magic_sniff_bytes: int = MAGIC_SNIFF_BYTES
    deadline_seconds: int = PARSER_DEADLINE_SECONDS


DEFAULT_LIMITS = ParserLimits()
