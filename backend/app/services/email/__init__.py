"""Email parsing service for Milestone 2.3.3.

The parsing path has no database, HTTP client, SMTP client, model client or
attachment extraction dependency. URLs are recorded as text and never fetched.
"""

from __future__ import annotations

from app.services.email.models import (
    PARSER_CATEGORIES,
    PERSISTED_CATEGORIES,
    PERSISTED_CATEGORY_MAP,
    AttachmentMetadata,
    Link,
    ParseResult,
)
from app.services.email.parser import parse_email

__all__ = [
    "PARSER_CATEGORIES",
    "PERSISTED_CATEGORIES",
    "PERSISTED_CATEGORY_MAP",
    "AttachmentMetadata",
    "Link",
    "ParseResult",
    "parse_email",
]
