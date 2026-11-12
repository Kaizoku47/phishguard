"""Logging configuration.

A redaction filter runs before records are emitted, so credentials that leak
into a message or an extra field are masked rather than written to disk or to
the console.
"""

from __future__ import annotations

import logging
import re

REDACTED = "***REDACTED***"

# Patterns that indicate a credential-bearing key or value.
_SENSITIVE_KEY = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|authorization|bearer|"
    r"access[_-]?key|private[_-]?key)\b"
)
_SECRET_SHAPES = re.compile(
    r"(?i)(sk-[a-z0-9]{10,}|ghp_[a-z0-9]{20,}|xox[baprs]-[a-z0-9-]{10,}|"
    r"akia[0-9a-z]{16}|postgres(?:ql)?(\+\w+)?://[^:\s]+:[^@\s]+@)"
)


def redact(value: str) -> str:
    """Mask credential-shaped substrings in a single string."""
    return _SECRET_SHAPES.sub(REDACTED, value)


class RedactionFilter(logging.Filter):
    """Scrub credential shapes from log messages and their arguments."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if record.args:
            record.args = tuple(redact(arg) if isinstance(arg, str) else arg for arg in record.args)
        return True


def configure_logging(level: str = "INFO") -> None:
    """Install a single stderr handler with redaction applied."""
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s %(levelname)-8s %(name)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )
    handler.addFilter(RedactionFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
