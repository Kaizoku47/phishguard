"""Bounded magic-byte content-type detection.

Detected types are observations, not security verdicts. Detection reads at
most ``MAGIC_SNIFF_BYTES`` decoded bytes and never inspects the filename or
extension. No document parsing library is used.
"""

from __future__ import annotations

# Ordered longest-first so overlapping signatures do not shadow each other.
_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"%PDF-", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x1f\x8b", "application/gzip"),
    (b"\x7fELF", "application/x-elf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/msword"),
    (b"BM", "image/bmp"),
    (b"RIFF", "application/x-riff"),
    (b"<?xml", "application/xml"),
    (b"<!DOCTYPE html", "text/html"),
    (b"<html", "text/html"),
)


def detect_content_type(data: bytes | None, sniff_bytes: int = 512) -> str | None:
    """Return the observed content type from magic bytes, or ``None``.

    ``data`` is already decoded attachment bytes. Only the first
    ``sniff_bytes`` bytes are read. The result is advisory metadata.
    """
    if not data:
        return None

    head = data[:sniff_bytes]
    for signature, content_type in _SIGNATURES:
        if head.startswith(signature):
            return content_type
    return None
