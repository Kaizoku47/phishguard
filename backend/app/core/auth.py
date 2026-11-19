"""Static bearer-token authentication.

The token is never logged, returned or placed in a URL. Comparison is performed
over fixed-length SHA-256 digests with ``hmac.compare_digest`` so token length
does not leak through timing.
"""

from __future__ import annotations

import hashlib
import hmac
import re

from app.core.config import Settings

# D-1: exactly one scheme, one space and one credential. Case-insensitive
# scheme, as in the existing contract. Repeated whitespace, tabs, leading or
# trailing whitespace and multiple credentials are all rejected.
_BEARER_HEADER = re.compile(r"Bearer [^\s]+", re.IGNORECASE | re.ASCII)


def token_digest(token: str) -> str:
    """Return the fixed-length digest used for the constant-time comparison."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def bearer_token(header: str | None) -> str | None:
    """Extract the credential from an ``Authorization: Bearer …`` header.

    A missing header, a wrong scheme, an empty credential or extra whitespace
    all produce ``None`` so the caller can return one identical failure.
    """
    if not header:
        return None
    match = _BEARER_HEADER.fullmatch(header)
    if match is None:
        return None
    return header.split(" ", 1)[1]


def token_is_valid(presented: str | None, settings: Settings) -> bool:
    """Compare digests without ever logging or returning the token."""
    if not presented:
        return False
    expected = settings.api_token.get_secret_value()
    return hmac.compare_digest(token_digest(presented), token_digest(expected))
