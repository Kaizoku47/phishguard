"""Focused tests for Milestone 2.3.3 — email parser.

Every fixture is synthetic. The parser is pure with respect to the filesystem
and the network: these tests assert that no URL is fetched, no attachment is
written or executed and no authentication verdict is produced.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import http.client
import logging
import socket
import subprocess
import urllib.request
from email.message import Message
from pathlib import Path

import pytest
from app.core.config import Settings
from app.services.email.limits import MAGIC_SNIFF_BYTES, ParserLimits
from app.services.email.models import (
    BODY_DECODE_MALFORMED,
    BODY_DECODE_OK,
    BODY_DECODE_UNDECODABLE,
)
from app.services.email.parser import parse_email
from pydantic import ValidationError

FIXTURES = Path(__file__).parent / "fixtures" / "eml"


def parser_settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "PHISHGUARD_SECRET_KEY": "test-secret-key-value",
        "PHISHGUARD_CORS_ORIGINS": [],
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


def load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def parse(name: str, limits: ParserLimits | None = None) -> object:
    return parse_email(load(name)) if limits is None else parse_email(load(name), limits)


# ---------------------------------------------------------------------------
# T-14 to T-24 — metadata and bodies
# ---------------------------------------------------------------------------


def test_a_plain_text_email_yields_metadata_and_body() -> None:
    result = parse("simple_plain.eml")

    assert result.status == "parsed"
    assert result.subject == "Plain message"
    assert result.from_address == "alice@example.com"
    assert result.from_display_name == "Alice"
    assert result.to_addresses == ["bob@example.com"]
    assert result.text_body is not None and "Hello Bob" in result.text_body
    assert result.html_body is None
    assert result.message_id == "<plain-1@example.com>"
    assert result.headers["subject"] == ["Plain message"]


def test_header_names_are_lowercase() -> None:
    result = parse("simple_plain.eml")

    assert all(name == name.lower() for name in result.headers)
    assert "content-type" in result.headers


def test_repeated_headers_are_preserved() -> None:
    result = parse("repeated_headers.eml")

    assert result.headers["x-custom"] == ["first", "second"]
    assert result.to_addresses == ["one@example.com", "two@example.com"]


def test_encoded_headers_are_decoded() -> None:
    result = parse("encoded_headers.eml")

    assert result.subject == "Invoice 2026"
    assert result.from_display_name == "José Péres"
    assert result.from_address == "jose@example.com"


def test_an_unparseable_date_is_null_without_an_exception() -> None:
    result = parse("malformed_date.eml")

    assert result.status == "parsed"
    assert result.date_header == "not a real date"
    assert result.date_parsed is None


def test_a_missing_date_and_message_id_are_null() -> None:
    raw = b"From: Alice <alice@example.com>\r\nSubject: No extras\r\n\r\nbody\r\n"
    result = parse_email(raw)

    assert result.status == "parsed"
    assert result.date_parsed is None
    assert result.message_id is None


def test_a_naive_date_is_assumed_utc_and_the_assumption_is_recorded() -> None:
    raw = (
        b"From: Alice <alice@example.com>\r\n"
        b"Date: Tue, 17 Nov 2026 10:00:00\r\n"
        b"Subject: Naive date\r\n\r\nbody\r\n"
    )
    result = parse_email(raw)

    assert result.date_parsed is not None
    assert result.date_parsed.tzinfo is not None
    assert result.date_assumed_utc is True


def test_html_body_is_extracted_as_text_never_rendered() -> None:
    result = parse("html.eml")

    assert result.html_body is not None
    assert "<a" in result.html_body
    assert result.text_body is None


def test_multipart_alternative_separates_both_bodies() -> None:
    result = parse("multipart_alternative.eml")

    assert result.status == "parsed"
    assert result.text_body is not None and "Plain alternative" in result.text_body
    assert result.html_body is not None and "<html>" in result.html_body
    assert result.multipart is True
    assert result.attachments == []


def test_an_invalid_charset_falls_back_to_utf8_with_replacement() -> None:
    result = parse("invalid_charset.eml")

    assert result.status == "parsed"
    assert result.body_charset == "utf-8"
    assert result.text_body is not None and "café" in result.text_body


def test_non_ascii_content_round_trips() -> None:
    result = parse("non_ascii.eml")

    assert result.subject == "Café — résumé"
    assert result.text_body is not None and "✓" in result.text_body


def test_a_valid_base64_body_is_decoded_and_marked_ok() -> None:
    encoded = base64.b64encode(b"hello from base64").decode("ascii")
    raw = (
        b"From: Alice <alice@example.com>\r\n"
        b"Subject: Base64 body\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n" + encoded.encode("ascii") + b"\r\n"
    )
    result = parse_email(raw)

    assert result.status == "parsed"
    assert result.text_body == "hello from base64"
    assert result.body_decode_status == BODY_DECODE_OK


def test_a_valid_quoted_printable_body_is_decoded_and_marked_ok() -> None:
    raw = (
        b"From: Alice <alice@example.com>\r\n"
        b"Subject: QP body\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
        b"one=3Dtwo\r\n"
    )
    result = parse_email(raw)

    assert result.text_body is not None and result.text_body.strip() == "one=two"
    assert result.body_decode_status == BODY_DECODE_OK


def test_a_malformed_base64_body_is_not_stored_as_content() -> None:
    raw = (
        b"From: Alice <alice@example.com>\r\n"
        b"Subject: Bad base64 body\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n"
        b"aHR0cDovL2dvb2QuZXhhbXBsZQ!!!\r\n"
    )
    result = parse_email(raw)

    assert result.status == "parsed"
    assert result.text_body is None
    assert result.body_decode_status == BODY_DECODE_MALFORMED
    assert result.links == []


def test_a_malformed_quoted_printable_body_is_not_stored_as_content() -> None:
    raw = (
        b"From: Alice <alice@example.com>\r\n"
        b"Subject: Bad QP body\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n\r\n"
        b"http://good.example =ZZ\r\n"
    )
    result = parse_email(raw)

    assert result.text_body is None
    assert result.body_decode_status == BODY_DECODE_MALFORMED
    assert result.links == []


def test_an_unknown_body_transfer_encoding_is_undecodable() -> None:
    raw = (
        b"From: Alice <alice@example.com>\r\n"
        b"Subject: Unknown body CTE\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: x-pg-unknown\r\n\r\n"
        b"body text\r\n"
    )
    result = parse_email(raw)

    assert result.text_body is None
    assert result.body_decode_status == BODY_DECODE_UNDECODABLE


# ---------------------------------------------------------------------------
# T-16 to T-20, T-31 — MIME categories and attachments
# ---------------------------------------------------------------------------


def test_a_multipart_container_never_becomes_an_attachment() -> None:
    result = parse("multipart_mixed_attachments.eml")

    assert result.multipart is True
    assert len(result.attachments) == 1
    assert all(item.filename != "container" for item in result.attachments)


def test_an_attachment_has_the_declared_type_and_the_correct_digest() -> None:
    result = parse("multipart_mixed_attachments.eml")
    attachment = result.attachments[0]

    decoded = base64.b64decode("JVBERi0xLjQK")
    assert attachment.category == "attachment"
    assert attachment.filename == "report.pdf"
    assert attachment.declared_content_type == "application/pdf"
    assert attachment.size_bytes == len(decoded)
    assert attachment.sha256 == hashlib.sha256(decoded).hexdigest()
    assert attachment.decode_ok is True


def test_an_inline_image_is_persisted_as_inline() -> None:
    result = parse("inline_image.eml")
    attachment = result.attachments[0]

    assert attachment.category == "inline"
    assert attachment.filename == "pic.png"
    assert attachment.detected_content_type == "image/png"
    assert attachment.decode_ok is True


def test_an_unknown_leaf_is_persisted_as_unknown() -> None:
    result = parse("unknown_part.eml")

    assert len(result.attachments) == 1
    assert result.attachments[0].category == "unknown"


def test_an_attached_message_is_an_attachment_and_is_never_opened() -> None:
    result = parse("attached_message.eml")

    assert result.status == "parsed"
    assert len(result.attachments) == 1
    attachment = result.attachments[0]
    assert attachment.category == "attachment"
    assert attachment.declared_content_type == "message/rfc822"
    assert attachment.filename == "original.eml"
    # SR-7: reserialised bytes are not byte-identical evidence. Q-2 applies.
    assert attachment.decode_ok is False
    assert attachment.sha256 is None
    assert attachment.size_bytes is None
    assert attachment.detected_content_type is None

    # The embedded message's URL and subject are never extracted as content.
    assert all(link["url"] != "http://inner.example.net/secret" for link in result.links)
    assert result.subject == "Forwarded"


def test_an_attached_message_with_crlf_line_endings_uses_the_q2_failure_state() -> None:
    """SR-7: original CRLF attachment bytes cannot be re-established safely.

    The parser must not present a reserialised parsed-message object as the
    digest of these bytes. The embedded message stays opaque: no URL, subject
    or header from it may appear in the outer result.
    """
    raw = (
        b"From: Alice <alice@example.com>\r\n"
        b"Subject: CRLF forward\r\n"
        b'Content-Type: multipart/mixed; boundary="CRLF"\r\n'
        b"\r\n"
        b"--CRLF\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"forwarded\r\n"
        b"--CRLF\r\n"
        b"Content-Type: message/rfc822\r\n"
        b'Content-Disposition: attachment; filename="inner.eml"\r\n'
        b"\r\n"
        b"From: Inner <inner@example.net>\r\n"
        b"Subject: Inner CRLF subject\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"inner body http://inner.example.net/secret\r\n"
        b"--CRLF--\r\n"
    )
    result = parse_email(raw)

    assert result.status == "parsed"
    assert result.subject == "CRLF forward"
    assert len(result.attachments) == 1
    attachment = result.attachments[0]
    assert attachment.category == "attachment"
    assert attachment.decode_ok is False
    assert attachment.sha256 is None
    assert attachment.size_bytes is None

    dumped = repr(result)
    assert "Inner CRLF subject" not in dumped
    assert "inner@example.net" not in dumped
    assert all(link["url"] != "http://inner.example.net/secret" for link in result.links)


def test_an_attached_message_is_never_reserialized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SR-7: no Message.as_bytes() result may be used as attachment evidence."""

    def forbidden(*args: object, **kwargs: object) -> bytes:
        raise AssertionError("attached message was reserialized")

    monkeypatch.setattr(Message, "as_bytes", forbidden)
    result = parse("attached_message.eml")

    assert result.attachments[0].decode_ok is False
    assert result.attachments[0].sha256 is None


def test_a_malicious_filename_is_preserved_verbatim_and_never_written(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = (
        b"From: Alice <alice@example.com>\r\n"
        b"Subject: Traversal\r\n"
        b'Content-Type: multipart/mixed; boundary="T"\r\n\r\n'
        b"--T\r\nContent-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="../../etc/passwd"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\nYWJj\r\n--T--\r\n"
    )
    monkeypatch.chdir(tmp_path)
    result = parse_email(raw)

    assert result.attachments[0].filename == "../../etc/passwd"
    assert list(tmp_path.iterdir()) == []


def test_a_zero_length_attachment_has_the_empty_string_digest() -> None:
    raw = (
        b"From: Alice <alice@example.com>\r\n"
        b"Subject: Empty attachment\r\n"
        b'Content-Type: multipart/mixed; boundary="Z"\r\n\r\n'
        b"--Z\r\nContent-Type: application/octet-stream\r\n"
        b'Content-Disposition: attachment; filename="empty.bin"\r\n'
        b"Content-Transfer-Encoding: base64\r\n\r\n\r\n--Z--\r\n"
    )
    result = parse_email(raw)
    attachment = result.attachments[0]

    assert attachment.decode_ok is True
    assert attachment.size_bytes == 0
    assert attachment.sha256 == hashlib.sha256(b"").hexdigest()


def test_q2_is_consistent_for_every_fixture_attachment() -> None:
    for fixture in sorted(FIXTURES.glob("*.eml")):
        result = parse_email(fixture.read_bytes())
        for attachment in result.attachments:
            if attachment.decode_ok:
                assert attachment.sha256 is not None
                assert attachment.size_bytes is not None
            else:
                assert attachment.sha256 is None
                assert attachment.size_bytes is None


# ---------------------------------------------------------------------------
# T-25 to T-29, T-28 — limits
# ---------------------------------------------------------------------------


def test_excessive_mime_depth_fails_cleanly() -> None:
    result = parse("deep_nested.eml")

    assert result.status == "parse_failed"
    assert result.limit_exceeded == "max_depth"


def test_excessive_part_count_fails_cleanly() -> None:
    result = parse("excessive_parts.eml")

    assert result.status == "parse_failed"
    assert result.limit_exceeded == "max_part_count"


def test_excessive_header_count_fails_cleanly() -> None:
    result = parse("excessive_headers.eml")

    assert result.status == "parse_failed"
    assert result.limit_exceeded == "max_header_count"


def test_an_oversized_single_header_fails_cleanly() -> None:
    result = parse("oversized_header.eml")

    assert result.status == "parse_failed"
    assert result.limit_exceeded == "max_header_length"


def test_a_multibyte_header_cannot_bypass_the_byte_limit() -> None:
    """9000 multi-byte characters exceed 16 KiB of data but not 16384 chars."""
    raw = (
        "From: Alice <alice@example.com>\r\n"
        "X-Multibyte: " + ("é" * 9000) + "\r\n"
        "Subject: Multibyte\r\n"
        "Content-Type: text/plain\r\n\r\nbody\r\n"
    ).encode("utf-8")
    result = parse_email(raw)

    assert result.status == "parse_failed"
    assert result.limit_exceeded == "max_header_length"


def test_the_raw_upload_cap_is_enforced() -> None:
    result = parse("simple_plain.eml", ParserLimits(max_upload_bytes=10))

    assert result.status == "parse_failed"
    assert result.limit_exceeded == "max_upload_bytes"


def test_the_decoded_body_limit_is_enforced() -> None:
    result = parse("simple_plain.eml", ParserLimits(max_decoded_body_bytes=5))

    assert result.status == "parse_failed"
    assert result.limit_exceeded == "max_decoded_body_bytes"


def test_a_custom_depth_limit_is_enforced() -> None:
    result = parse("multipart_alternative.eml", ParserLimits(max_mime_depth=0))

    assert result.status == "parse_failed"
    assert result.limit_exceeded == "max_depth"


def test_an_unknown_transfer_encoding_has_no_digest() -> None:
    result = parse("invalid_transfer_encoding.eml")
    attachment = result.attachments[0]

    assert attachment.decode_ok is False
    assert attachment.sha256 is None
    assert attachment.size_bytes is None


def test_malformed_base64_has_no_digest() -> None:
    result = parse("malformed_base64.eml")
    attachment = result.attachments[0]

    assert attachment.decode_ok is False
    assert attachment.sha256 is None


def test_malformed_quoted_printable_has_no_digest() -> None:
    result = parse("malformed_quoted_printable.eml")
    attachment = result.attachments[0]

    assert attachment.decode_ok is False
    assert attachment.sha256 is None


def test_an_empty_email_is_a_structured_failure() -> None:
    result = parse("empty.eml")

    assert result.status == "parse_failed"
    assert result.failure_reason == "no_usable_content"
    assert result.attachments == []


# ---------------------------------------------------------------------------
# T-41 — URL extraction without network access
# ---------------------------------------------------------------------------


def test_plain_text_links_and_hosts_are_extracted() -> None:
    result = parse("multiple_urls_plain.eml")
    urls = {link["url"] for link in result.links}

    assert "https://Example.COM:8443/path?q=1" in urls
    assert "www.Sample.NET/page" in urls
    hosts = {link["host"] for link in result.links}
    assert "example.com" in hosts
    assert "www.sample.net" in hosts
    assert all(":" not in host for host in hosts)


def test_html_href_and_src_values_are_extracted() -> None:
    result = parse("html_href_src.eml")
    urls = {link["url"] for link in result.links}

    assert "https://A.Example.com:443/x" in urls
    assert "https://b.example.net/y.png" in urls
    assert "http://c.example.org/z.js" in urls
    assert all(link["host"] == link["host"].lower() for link in result.links)


def test_no_socket_or_http_client_is_invoked_during_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access attempted during parsing")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(http.client.HTTPConnection, "request", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)

    for name in (
        "multiple_urls_plain.eml",
        "html_href_src.eml",
        "multipart_alternative.eml",
    ):
        result = parse(name)
        assert result.links

    # An attached message is opaque: its embedded URL is never extracted.
    assert parse("attached_message.eml").links == []


def test_parsing_does_not_import_an_http_client_into_the_email_package() -> None:
    import app.services.email as email_package

    package_dir = Path(email_package.__file__).parent
    for source_file in package_dir.glob("*.py"):
        source = source_file.read_text()
        assert "import httpx" not in source
        assert "import requests" not in source
        assert "urllib.request" not in source
        assert "import socket" not in source
        assert "import subprocess" not in source


# ---------------------------------------------------------------------------
# T-42 — header trust boundary
# ---------------------------------------------------------------------------


def test_forged_authentication_results_is_stored_verbatim_but_never_interpreted() -> None:
    result = parse("forged_auth.eml")

    header = result.headers["authentication-results"]
    assert header == [
        "mx.example.com; spf=pass smtp.mailfrom=paypal.com; "
        "dkim=pass header.d=paypal.com; dmarc=pass"
    ]

    field_names = {field.name for field in dataclasses.fields(result)}
    assert not any(
        "auth" in name or "spf" in name or "dkim" in name or "dmarc" in name for name in field_names
    )


def test_authentication_headers_are_never_treated_as_proof() -> None:
    forged = parse("forged_auth.eml")
    absent = parse_email(
        b"From: Alice <alice@example.com>\r\nSubject: Clean\r\n"
        b"Content-Type: text/plain\r\n\r\nbody\r\n"
    )

    assert forged.status == absent.status == "parsed"
    assert dataclasses.asdict(forged).keys() == dataclasses.asdict(absent).keys()
    assert "authentication-results" not in absent.headers


# ---------------------------------------------------------------------------
# Defects, malformed input and exception safety
# ---------------------------------------------------------------------------


def test_mime_defects_are_recorded_as_class_names_only() -> None:
    result = parse("malformed_mime.eml")

    assert result.status == "parsed"
    assert result.defect_count > 0
    assert "CloseBoundaryNotFoundDefect" in result.defect_types
    assert all(" " not in name and ":" not in name for name in result.defect_types)
    assert "missing closing boundary" not in repr(result.defect_types).lower()


def test_defect_count_counts_occurrences_and_defect_types_deduplicates_classes() -> None:
    """Two instances of one defect class count twice but appear once in types."""
    raw = (
        b"From: Alice <alice@example.com>\r\n"
        b"Subject: Repeated defect class\r\n"
        b'Content-Type: multipart/mixed; boundary="A"\r\n\r\n'
        b'--A\r\nContent-Type: multipart/mixed; boundary="B"\r\n\r\n'
        b"--B\r\nContent-Type: text/plain\r\n\r\nb1\r\n"
        b'--A\r\nContent-Type: multipart/mixed; boundary="C"\r\n\r\n'
        b"--C\r\nContent-Type: text/plain\r\n\r\nc1\r\n"
        b"--A--\r\n"
    )
    result = parse_email(raw)

    assert result.defect_count == 2
    assert result.defect_types == ["CloseBoundaryNotFoundDefect"]


def test_defect_count_counts_distinct_classes_separately() -> None:
    """Different defect classes contribute both to count and to the type list."""
    raw = (
        b"From: Alice <alice@example.com>\r\n"
        b"Subject: Different defect classes\r\n"
        b'Content-Type: multipart/mixed; boundary="X"\r\n\r\n'
        b"--Y\r\nContent-Type: text/plain\r\n\r\na\r\n"
    )
    result = parse_email(raw)

    assert result.defect_count == 2
    assert set(result.defect_types) == {
        "StartBoundaryNotFoundDefect",
        "MultipartInvariantViolationDefect",
    }


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\r\n",
        b"not an email at all",
        b"\xff\x00\x80",
        b"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n",
        b"From: \r\nSubject: \r\n\r\nbody",
    ],
)
def test_malformed_input_never_raises(raw: bytes) -> None:
    result = parse_email(raw)

    assert isinstance(result.status, str)
    assert result.status in ("parsed", "parse_failed")
    assert result.failure_reason is None or isinstance(result.failure_reason, str)
    assert "\nTraceback" not in repr(result)


def test_unexpected_exceptions_are_reported_with_a_safe_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.services.email.parser as parser_module

    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("attacker-controlled-secret-value must not leak")

    monkeypatch.setattr(parser_module, "_collect_metadata", boom)
    result = parse("simple_plain.eml")

    assert result.status == "parse_failed"
    assert result.failure_reason == "unexpected_error"
    assert "attacker-controlled-secret-value" not in repr(result)


def test_a_missing_content_type_is_accepted() -> None:
    result = parse("missing_content_type.eml")

    assert result.status == "parsed"
    assert result.subject == "No content type"


def test_a_malformed_mime_structure_is_still_accepted() -> None:
    result = parse("malformed_mime.eml")

    assert result.status == "parsed"
    assert result.defect_count >= 1


def test_no_attachment_is_written_to_disk(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    for name in (
        "multipart_mixed_attachments.eml",
        "inline_image.eml",
        "attached_message.eml",
        "misleading_extension.eml",
    ):
        parse(name)

    assert list(tmp_path.iterdir()) == []


def test_no_subprocess_is_invoked_during_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("subprocess invoked during parsing")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    result = parse("multipart_mixed_attachments.eml")

    assert result.attachments


def test_a_misleading_filename_does_not_influence_detection() -> None:
    result = parse("misleading_extension.eml")
    attachment = result.attachments[0]

    assert attachment.filename == "invoice.pdf"
    assert attachment.declared_content_type == "application/pdf"
    assert attachment.detected_content_type == "image/png"


# ---------------------------------------------------------------------------
# Categories, configuration and counters
# ---------------------------------------------------------------------------


def test_six_parser_categories_and_three_persisted_categories_are_exposed() -> None:
    from app.services.email import (
        PARSER_CATEGORIES,
        PERSISTED_CATEGORIES,
        PERSISTED_CATEGORY_MAP,
    )

    assert {
        "container",
        "body",
        "inline",
        "attachment",
        "attached_message",
        "unknown",
    } == PARSER_CATEGORIES
    assert {"attachment", "inline", "unknown"} == PERSISTED_CATEGORIES
    assert PERSISTED_CATEGORY_MAP["attached_message"] == "attachment"
    assert PERSISTED_CATEGORY_MAP["inline"] == "inline"
    assert PERSISTED_CATEGORY_MAP["unknown"] == "unknown"


def test_part_and_depth_counters_are_recorded() -> None:
    result = parse("multipart_alternative.eml")

    assert result.part_count == 3
    assert result.max_depth == 1
    assert result.multipart is True


def test_the_deadline_is_a_monitor_and_does_not_terminate_parsing(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import app.services.email.parser as parser_module

    times = iter([0.0, 31.0])
    monkeypatch.setattr(parser_module.time, "monotonic", lambda: next(times))

    with caplog.at_level(logging.WARNING):
        result = parse("simple_plain.eml")

    assert result.status == "parsed"
    assert "monitor" in caplog.text


def test_settings_expose_additive_parser_limits() -> None:
    settings = Settings(
        _env_file=None,
        PHISHGUARD_SECRET_KEY="test-secret-key-value",
        PHISHGUARD_CORS_ORIGINS=[],
    )

    assert settings.max_upload_bytes == 10 * 1024 * 1024
    assert settings.max_mime_depth == 10
    assert settings.max_mime_parts == 500
    assert settings.max_header_count == 200
    assert settings.max_header_length == 16 * 1024
    assert settings.max_decoded_body_bytes == 10 * 1024 * 1024
    assert settings.max_concurrent_uploads == 4
    assert settings.parser_deadline_seconds == 30


def test_default_settings_map_to_default_parser_limits() -> None:
    limits = parser_settings().to_parser_limits()

    assert limits == ParserLimits()
    assert limits.magic_sniff_bytes == MAGIC_SNIFF_BYTES


def test_non_default_settings_map_to_parser_limits() -> None:
    settings = parser_settings(
        PHISHGUARD_MAX_UPLOAD_BYTES=123456,
        PHISHGUARD_MAX_MIME_DEPTH=7,
        PHISHGUARD_MAX_MIME_PARTS=99,
        PHISHGUARD_MAX_HEADER_COUNT=33,
        PHISHGUARD_MAX_HEADER_LENGTH=4096,
        PHISHGUARD_MAX_DECODED_BODY_BYTES=234567,
        PHISHGUARD_PARSER_DEADLINE_SECONDS=45,
        PHISHGUARD_MAX_CONCURRENT_UPLOADS=9,
    )
    limits = settings.to_parser_limits()

    assert limits.max_upload_bytes == 123456
    assert limits.max_mime_depth == 7
    assert limits.max_mime_parts == 99
    assert limits.max_header_count == 33
    assert limits.max_header_length == 4096
    assert limits.max_decoded_body_bytes == 234567
    assert limits.deadline_seconds == 45
    assert limits.magic_sniff_bytes == MAGIC_SNIFF_BYTES
    assert not hasattr(limits, "max_concurrent_uploads")


def test_mapped_parser_limits_are_honoured_by_the_parser() -> None:
    limits = parser_settings(PHISHGUARD_MAX_UPLOAD_BYTES=10).to_parser_limits()

    result = parse_email(load("simple_plain.eml"), limits)

    assert result.status == "parse_failed"
    assert result.limit_exceeded == "max_upload_bytes"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("PHISHGUARD_MAX_UPLOAD_BYTES", 0),
        ("PHISHGUARD_MAX_MIME_DEPTH", 0),
        ("PHISHGUARD_MAX_MIME_PARTS", 0),
        ("PHISHGUARD_MAX_HEADER_COUNT", 0),
        ("PHISHGUARD_MAX_HEADER_LENGTH", 0),
        ("PHISHGUARD_MAX_DECODED_BODY_BYTES", 0),
        ("PHISHGUARD_PARSER_DEADLINE_SECONDS", 0),
    ],
)
def test_invalid_parser_settings_are_rejected(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        parser_settings(**{field: value})


def test_date_parsed_is_timezone_aware_for_aware_dates() -> None:
    result = parse("simple_plain.eml")

    assert result.date_parsed is not None
    assert result.date_parsed.tzinfo is not None
    assert result.date_assumed_utc is False
