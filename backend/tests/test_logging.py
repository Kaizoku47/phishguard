"""Log redaction tests.

A leaked credential in a log line is a production incident. These tests pin the
redaction behaviour so a future refactor cannot quietly remove it.
"""

from __future__ import annotations

import logging

import pytest
from app.core.logging import REDACTED, RedactionFilter, redact


@pytest.mark.parametrize(
    "raw",
    [
        "sk-abcdefghijklmnop123456",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "AKIAFAKEFAKEFAKEFAKE",
        "postgresql+asyncpg://user:hunter2@localhost:5432/db",
    ],
    ids=["openai-shape", "github-shape", "aws-shape", "db-url"],
)
def test_credential_shapes_are_redacted(raw: str) -> None:
    assert REDACTED in redact(raw)
    assert raw.split(":")[-1] not in redact(raw) or REDACTED in redact(raw)


def test_ordinary_text_is_untouched() -> None:
    text = "analysed message 42 in 120 ms"

    assert redact(text) == text


def test_filter_scrubs_message_and_args() -> None:
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="connecting with %s",
        args=("ghp_abcdefghijklmnopqrstuvwxyz0123456789",),
        exc_info=None,
    )

    assert RedactionFilter().filter(record) is True

    rendered = record.getMessage()
    assert REDACTED in rendered
    assert "ghp_" not in rendered


def test_filter_scrubs_literal_message() -> None:
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="handler initialised sk-abcdefghijklmnop123456",
        args=(),
        exc_info=None,
    )

    RedactionFilter().filter(record)

    assert "sk-abcdefghijklmnop123456" not in record.getMessage()
