"""Strict bearer-token parsing (PG-237-05)."""

from __future__ import annotations

from app.core.auth import bearer_token, token_is_valid
from app.core.config import SYNTHETIC_TEST_TOKEN, Settings


def _settings() -> Settings:
    return Settings(
        _env_file=None,
        PHISHGUARD_SECRET_KEY="test-secret-key-value",
        PHISHGUARD_ENVIRONMENT="test",
        PHISHGUARD_API_TOKEN=SYNTHETIC_TEST_TOKEN,
    )


def test_correct_bearer_header_is_accepted() -> None:
    assert bearer_token(f"Bearer {SYNTHETIC_TEST_TOKEN}") == SYNTHETIC_TEST_TOKEN
    assert token_is_valid(SYNTHETIC_TEST_TOKEN, _settings()) is True


def test_lowercase_scheme_is_accepted() -> None:
    assert bearer_token(f"bearer {SYNTHETIC_TEST_TOKEN}") == SYNTHETIC_TEST_TOKEN


def test_repeated_whitespace_is_rejected() -> None:
    assert bearer_token("Bearer  token") is None
    assert bearer_token("Bearer   token") is None


def test_leading_and_trailing_whitespace_is_rejected() -> None:
    assert bearer_token(" Bearer token") is None
    assert bearer_token("Bearer token ") is None
    assert bearer_token("Bearer token\n") is None


def test_tab_separator_is_rejected() -> None:
    assert bearer_token("Bearer\ttoken") is None
    assert bearer_token("Bearer \ttoken") is None


def test_malformed_headers_are_rejected() -> None:
    assert bearer_token(None) is None
    assert bearer_token("") is None
    assert bearer_token("Bearer") is None
    assert bearer_token("Bearer token token2") is None
    assert bearer_token("Basic token") is None
    assert bearer_token("Token token") is None


def test_incorrect_token_is_rejected() -> None:
    assert token_is_valid("wrong-token", _settings()) is False
    assert token_is_valid(None, _settings()) is False
