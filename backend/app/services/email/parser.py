"""Parse one raw RFC822 message into structured, database-neutral data.

The parser is deliberately independent of the API, the database and the
filesystem. It never fetches a URL, opens an attachment, renders HTML, derives
an authentication verdict or raises to its caller for malformed input.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import logging
import re
import time
from datetime import UTC
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any

from app.services.email.limits import (
    DEFAULT_LIMITS,
    KNOWN_TRANSFER_ENCODINGS,
    PARSER_VERSION,
    ParserLimits,
)
from app.services.email.links import extract_links
from app.services.email.magic import detect_content_type
from app.services.email.models import (
    BODY_DECODE_MALFORMED,
    BODY_DECODE_OK,
    BODY_DECODE_UNDECODABLE,
    PERSISTED_CATEGORY_MAP,
    AttachmentMetadata,
    ParseResult,
)

logger = logging.getLogger(__name__)

# Failure reasons are fixed strings. Attacker-controlled exception messages
# and tracebacks are never returned to the caller or persisted.
_FAILURE_PARSE_ERROR = "parse_error"
_FAILURE_UNEXPECTED = "unexpected_error"
_FAILURE_NO_CONTENT = "no_usable_content"

_BASE64_WHITESPACE = re.compile(r"\s+")
_QP_BAD_ESCAPE = re.compile(r"=(?![0-9A-Fa-f]{2}|\r?\n)")


class _LimitExceededError(Exception):
    """Internal signal carrying the safe name of the exceeded limit."""

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


class _TraversalState:
    """Mutable counters shared by one traversal."""

    def __init__(self) -> None:
        self.part_count = 0
        self.attachment_index = 0
        self.defect_occurrences = 0


def _text_header(message: Any, name: str) -> str | None:
    """Return one decoded header value, or ``None`` when absent."""
    value = message.get(name)
    return None if value is None else str(value)


def _address_list(message: Any, name: str) -> list[str]:
    """Return the address portion of every occurrence of one header."""
    values = [str(value) for value in message.get_all(name, [])]
    if not values:
        return []
    return [address for _, address in getaddresses(values) if address]


def _collect_headers(message: Any, result: ParseResult, limits: ParserLimits) -> None:
    """Collect lowercase header names and preserve every repeated value."""
    for count, (name, value) in enumerate(message.items(), start=1):
        if count > limits.max_header_count:
            raise _LimitExceededError("max_header_count")
        text = str(value)
        # The limit is 16 KiB of data, not 16384 characters. Counting bytes
        # prevents a multi-byte header from bypassing the cap.
        if len(text.encode("utf-8", errors="replace")) > limits.max_header_length:
            raise _LimitExceededError("max_header_length")
        result.headers.setdefault(name.lower(), []).append(text)


def _collect_metadata(message: Any, result: ParseResult) -> None:
    """Extract sender-controlled metadata as untrusted data."""
    result.subject = _text_header(message, "Subject")

    from_pairs = getaddresses([str(v) for v in message.get_all("From", [])])
    if from_pairs:
        result.from_display_name = from_pairs[0][0] or None
        result.from_address = from_pairs[0][1] or None

    result.to_addresses = _address_list(message, "To")
    result.cc_addresses = _address_list(message, "Cc")
    result.reply_to_addresses = _address_list(message, "Reply-To")
    result.date_header = _text_header(message, "Date")
    result.message_id = _text_header(message, "Message-ID")

    if result.date_header is not None:
        try:
            parsed = parsedate_to_datetime(result.date_header)
        except (TypeError, ValueError, OverflowError):
            parsed = None
        if parsed is not None:
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
                result.date_assumed_utc = True
            result.date_parsed = parsed


def _collect_defects(part: Any, result: ParseResult, state: _TraversalState) -> set[str]:
    """Record defect class names only. Defect values can contain attacker text.

    ``defect_count`` is the total number of defect occurrences; ``defect_types``
    is the deduplicated list of their class names. A repeated instance of one
    defect class therefore raises the count but not the type list.
    """
    names: set[str] = set()
    for defect in getattr(part, "defects", ()) or ():
        name = defect.__class__.__name__
        names.add(name)
        state.defect_occurrences += 1
        if name not in result.defect_types:
            result.defect_types.append(name)
    result.defect_count = state.defect_occurrences
    return names


def _content_type(part: Any) -> str | None:
    """Return the declared type, or ``None`` when the header is absent."""
    if part.get("Content-Type") is None:
        return None
    try:
        return part.get_content_type()
    except Exception:
        return None


def _decode_payload(part: Any) -> bytes | None:
    """Return decoded bytes, or ``None`` when they cannot be established."""
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        return None
    return payload if isinstance(payload, bytes) else None


def _base64_is_valid(part: Any) -> bool:
    """Reject malformed or incomplete base64 before accepting its bytes."""
    encoded = part.get_payload()
    if not isinstance(encoded, str):
        return False
    compact = _BASE64_WHITESPACE.sub("", encoded)
    if not compact:
        return True
    try:
        base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return False
    return True


def _quoted_printable_is_valid(part: Any) -> bool:
    """Reject malformed quoted-printable escapes."""
    encoded = part.get_payload()
    if not isinstance(encoded, str):
        return False
    return _QP_BAD_ESCAPE.search(encoded) is None


def _decode_attachment(part: Any) -> tuple[bytes | None, bool]:
    """Apply Q-2: uncertain bytes produce ``(None, False)``, never a digest."""
    # An attached message/rfc822 is opaque. The email package has already
    # turned its payload into parsed Message objects; serialising one of those
    # objects back to bytes can normalise line endings and otherwise differ
    # from the original attachment payload. Those bytes are not byte-identical
    # evidence, so Q-2 requires the failure state instead of a digest. The
    # embedded message is never traversed or analysed.
    if part.get_content_type() == "message/rfc822":
        return None, False

    raw_encoding = part.get("Content-Transfer-Encoding")
    encoding = str(raw_encoding).strip().lower() if raw_encoding is not None else "7bit"
    if encoding not in KNOWN_TRANSFER_ENCODINGS:
        return None, False

    if encoding == "base64" and not _base64_is_valid(part):
        return None, False
    if encoding == "quoted-printable" and not _quoted_printable_is_valid(part):
        return None, False

    decoded = _decode_payload(part)
    if decoded is None:
        return None, False
    return decoded, True


def _decode_charset(part: Any, decoded: bytes) -> tuple[str, str]:
    """Decode body bytes with a recognised charset, else UTF-8, with replace."""
    declared = part.get_content_charset()
    charset = declared if declared else "utf-8"
    try:
        codecs.lookup(charset)
    except LookupError:
        charset = "utf-8"
    return decoded.decode(charset, errors="replace"), charset


def _classify(part: Any, content_type: str | None, defects: set[str], is_root: bool) -> str:
    """Assign exactly one of the six parser categories.

    The container check happens in the caller, before this function, so a
    multipart node can never be classified as a file.
    """
    if content_type is None or defects:
        return "unknown"
    if content_type == "message/rfc822" and not is_root:
        return "attached_message"

    filename = part.get_filename()
    # get_content_disposition() returns the disposition type alone; the raw
    # header (with parameters) is kept separately as untrusted metadata.
    disposition_text = (part.get_content_disposition() or "").strip().lower()

    if (
        content_type in ("text/plain", "text/html")
        and not filename
        and disposition_text in ("", "inline")
    ):
        return "body"
    if disposition_text == "inline" and filename:
        return "inline"
    if disposition_text == "attachment" or filename:
        return "attachment"
    return "unknown"


def _record_attachment(
    part: Any,
    result: ParseResult,
    state: _TraversalState,
    content_type: str | None,
    category: str,
    limits: ParserLimits,
) -> None:
    """Record metadata for one persisted attachment row. Never store bytes."""
    decoded, decode_ok = _decode_attachment(part)
    digest = hashlib.sha256(decoded).hexdigest() if decode_ok and decoded is not None else None
    size = len(decoded) if decode_ok and decoded is not None else None
    detected = detect_content_type(decoded, limits.magic_sniff_bytes) if decode_ok else None

    disposition = part.get("Content-Disposition")
    encoding = part.get("Content-Transfer-Encoding")

    result.attachments.append(
        AttachmentMetadata(
            part_index=state.attachment_index,
            category=PERSISTED_CATEGORY_MAP[category],
            filename=part.get_filename(),
            declared_content_type=content_type,
            detected_content_type=detected,
            content_disposition=str(disposition) if disposition is not None else None,
            content_transfer_encoding=str(encoding) if encoding is not None else None,
            size_bytes=size,
            sha256=digest,
            decode_ok=decode_ok,
        )
    )
    state.attachment_index += 1


def _decode_body_payload(part: Any) -> tuple[str, bytes | None]:
    """Validate and decode one body part without ever raising.

    Malformed base64/quoted-printable and unknown encodings are reported as
    distinct states. Their bytes are not accepted as reliable body content.
    """
    raw_encoding = part.get("Content-Transfer-Encoding")
    encoding = str(raw_encoding).strip().lower() if raw_encoding is not None else "7bit"
    if encoding not in KNOWN_TRANSFER_ENCODINGS:
        return BODY_DECODE_UNDECODABLE, None
    if encoding == "base64" and not _base64_is_valid(part):
        return BODY_DECODE_MALFORMED, None
    if encoding == "quoted-printable" and not _quoted_printable_is_valid(part):
        return BODY_DECODE_MALFORMED, None

    decoded = _decode_payload(part)
    if decoded is None:
        return BODY_DECODE_UNDECODABLE, None
    return BODY_DECODE_OK, decoded


def _merge_body_status(current: str | None, new: str) -> str | None:
    """Keep the worst observed body decoding state across all body parts."""
    if current == BODY_DECODE_UNDECODABLE or new == BODY_DECODE_UNDECODABLE:
        return BODY_DECODE_UNDECODABLE
    if current == BODY_DECODE_MALFORMED or new == BODY_DECODE_MALFORMED:
        return BODY_DECODE_MALFORMED
    return BODY_DECODE_OK


def _record_body(part: Any, result: ParseResult, content_type: str, limits: ParserLimits) -> None:
    """Record the first plain and first HTML reliably decoded body.

    The aggregate status records the worst decoding outcome seen. A part whose
    bytes are malformed or undecodable is not stored as body text, so URLs
    derived from a partial decode cannot be presented as message content.
    """
    status, decoded = _decode_body_payload(part)
    result.body_decode_status = _merge_body_status(result.body_decode_status, status)
    if decoded is None:
        return
    if len(decoded) > limits.max_decoded_body_bytes:
        raise _LimitExceededError("max_decoded_body_bytes")

    text, charset = _decode_charset(part, decoded)
    if result.body_charset is None:
        result.body_charset = charset
    if content_type == "text/plain" and result.text_body is None:
        result.text_body = text
    elif content_type == "text/html" and result.html_body is None:
        result.html_body = text


def _traverse(
    part: Any,
    result: ParseResult,
    state: _TraversalState,
    limits: ParserLimits,
    depth: int = 0,
    is_root: bool = True,
) -> None:
    """Walk the MIME tree with bounded depth and part count.

    Attached ``message/rfc822`` parts stay opaque. The email package has
    already parsed them into Message objects, so their exact original decoded
    bytes cannot currently be established. Per SR-7/Q-2 no digest is computed:
    the attachment is recorded with ``decode_ok=False`` and ``sha256=None``.
    The embedded message is never traversed and its headers and URLs are never
    interpreted.
    """
    if depth > limits.max_mime_depth:
        raise _LimitExceededError("max_depth")
    state.part_count += 1
    if state.part_count > limits.max_mime_parts:
        raise _LimitExceededError("max_part_count")
    result.part_count = state.part_count
    result.max_depth = max(result.max_depth, depth)

    defects = _collect_defects(part, result, state)

    # Container first: a multipart node is a structure, never a file. Use the
    # declared main type, not is_multipart(): an attached message/rfc822 may
    # look multipart to the email package but must stay an opaque file.
    if part.get_content_maintype() == "multipart":
        for child in part.iter_parts():
            _traverse(child, result, state, limits, depth + 1, False)
        return

    content_type = _content_type(part)
    category = _classify(part, content_type, defects, is_root)

    # A completely empty root has no content to persist. It is not an
    # attachment and must not turn an empty upload into a parsed message.
    if is_root and category == "unknown" and content_type is None:
        return

    if category == "body":
        assert content_type is not None  # noqa: S101 - invariant from _classify
        _record_body(part, result, content_type, limits)
    else:
        _record_attachment(part, result, state, content_type, category, limits)


def _has_usable_content(result: ParseResult) -> bool:
    """Whether anything was extracted worth calling a successful parse."""
    return any(
        (
            result.subject,
            result.from_address,
            result.to_addresses,
            result.cc_addresses,
            result.reply_to_addresses,
            result.message_id,
            result.date_header,
            result.text_body,
            result.html_body,
            result.attachments,
        )
    )


def parse_email(raw: bytes, limits: ParserLimits = DEFAULT_LIMITS) -> ParseResult:
    """Parse raw message bytes into a structured result.

    This function never raises for malformed input. Failures are reported with
    fixed ``failure_reason`` or ``limit_exceeded`` strings; no attacker text or
    traceback is returned.
    """
    started = time.monotonic()
    result = ParseResult(status="parsed", parser_version=PARSER_VERSION)

    if not isinstance(raw, (bytes, bytearray)):
        result.status = "parse_failed"
        result.failure_reason = _FAILURE_PARSE_ERROR
        return result
    raw = bytes(raw)

    if len(raw) > limits.max_upload_bytes:
        result.status = "parse_failed"
        result.limit_exceeded = "max_upload_bytes"
        return result

    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception:
        result.status = "parse_failed"
        result.failure_reason = _FAILURE_PARSE_ERROR
        return result

    result.multipart = message.is_multipart()

    try:
        _collect_headers(message, result, limits)
        _collect_metadata(message, result)
        _traverse(message, result, _TraversalState(), limits)

        if result.limit_exceeded is None:
            links = extract_links(result.text_body, result.html_body)
            result.links = [link.as_dict() for link in links]
            if not _has_usable_content(result):
                result.status = "parse_failed"
                result.failure_reason = _FAILURE_NO_CONTENT
    except _LimitExceededError as exc:
        result.status = "parse_failed"
        result.limit_exceeded = exc.name
    except Exception:
        result.status = "parse_failed"
        result.failure_reason = _FAILURE_UNEXPECTED

    elapsed = time.monotonic() - started
    if elapsed > limits.deadline_seconds:
        # Observation only. A synchronous CPU-bound parse cannot be terminated
        # by an asyncio timeout; the real controls are the upload cap and the
        # process-local concurrency limit.
        logger.warning("email parse exceeded the %ss monitor", limits.deadline_seconds)

    return result
