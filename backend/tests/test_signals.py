"""Unit tests for deterministic phishing signals (T-42 to T-46)."""

from __future__ import annotations

import socket
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from app.services.analysis.signals import (
    Signal,
    archive_attachment_signal,
    attachment_type_mismatch_signal,
    auth_results_unverifiable_signal,
    evaluate_signals,
    free_mail_sender_signal,
    html_form_count_signal,
    link_host_count_signal,
    lookalike_sender_domain_signal,
    missing_date_signal,
    missing_evidence,
    normalize_domain,
    punycode_host_signal,
    reply_to_mismatch_signal,
    suspicious_tld_signal,
    url_credential_scheme_signal,
)


def parsed(**overrides: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "from_address": "Alice <alice@example.test>",
        "reply_to_addresses": [],
        "links": [],
        "html_body": None,
        "date_header": "Tue, 17 Nov 2026 10:00:00 +0000",
        "date_parsed": datetime(2026, 11, 17, 10, 0, tzinfo=UTC),
        "headers": {},
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def attachment(**overrides: Any) -> SimpleNamespace:
    values: dict[str, Any] = {
        "filename": None,
        "declared_content_type": None,
        "detected_content_type": None,
        "category": "attachment",
        "decode_ok": True,
        "sha256": "0" * 64,
        "size_bytes": 1,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_signal_requires_a_non_empty_reason() -> None:
    with pytest.raises(ValueError, match="reason"):
        Signal(id="x", severity="low", contribution=1, reason="", evaluated=True)
    with pytest.raises(ValueError, match="reason"):
        Signal(id="x", severity="low", contribution=1, reason="   ", evaluated=True)


def test_unevaluated_signal_must_contribute_zero() -> None:
    signal = auth_results_unverifiable_signal()
    assert signal.evaluated is False
    assert signal.contribution == 0

    with pytest.raises(ValueError, match="zero"):
        Signal(id="x", severity="none", contribution=5, reason="unevaluated", evaluated=False)


def test_t42_forged_authentication_results_never_becomes_a_verdict() -> None:
    record = parsed(
        headers={"authentication-results": ["mx.example.test; spf=pass; dkim=pass; dmarc=pass"]}
    )

    signals = evaluate_signals(record, [])
    auth = [signal for signal in signals if signal.id == "auth_results_unverifiable"]

    assert len(auth) == 1
    assert auth[0].evaluated is False
    assert auth[0].contribution == 0
    assert "not an authentication verdict" in auth[0].reason
    assert not any(
        signal.id in {"spf_pass", "dkim_pass", "dmarc_pass", "auth_pass"} for signal in signals
    )
    assert missing_evidence(signals) == [
        {"target": "auth:spf_dkim_dmarc", "reason": auth[0].reason}
    ]


def test_t43_header_derived_reasons_state_claim_not_fact() -> None:
    record = parsed(
        from_address="Alice <alice@gmail.com>",
        reply_to_addresses=["Bob <bob@example.test>"],
        links=[{"url": "https://x.top", "host": "x.top"}],
    )

    signals = [
        reply_to_mismatch_signal(record),
        lookalike_sender_domain_signal(parsed(from_address="a@paypa1.com")),
        free_mail_sender_signal(record),
        suspicious_tld_signal(record),
    ]

    assert all(signal is not None for signal in signals)
    for signal in signals:
        assert signal is not None
        lowered = signal.reason.lower()
        assert "claimed" in lowered or "sender-controlled" in lowered


def test_domain_normalization_is_deterministic() -> None:
    assert normalize_domain(" Example.COM. ") == "example.com"
    assert normalize_domain("BÜCHER.example.") == "xn--bcher-kva.example"
    assert normalize_domain("") == ""
    assert normalize_domain(None) == ""
    assert normalize_domain("bad\u0000host") == "bad\u0000host"


def test_lookalike_requires_exactly_one_edit_and_excludes_exact_match() -> None:
    assert lookalike_sender_domain_signal(parsed(from_address="a@paypal.com")) is None
    assert lookalike_sender_domain_signal(parsed(from_address="a@paypa1.com")) is not None
    assert lookalike_sender_domain_signal(parsed(from_address="a@paypalxx.com")) is None


def test_free_mail_uses_exact_membership() -> None:
    assert free_mail_sender_signal(parsed(from_address="a@gmail.com")) is not None
    assert free_mail_sender_signal(parsed(from_address="a@mail.gmail.com")) is None
    assert free_mail_sender_signal(parsed(from_address="a@example.test")) is None


def test_suspicious_tld_checks_sender_and_link_hosts() -> None:
    assert suspicious_tld_signal(parsed(from_address="a@evil.top")) is not None
    assert (
        suspicious_tld_signal(parsed(links=[{"url": "https://x.xyz", "host": "x.xyz"}])) is not None
    )
    assert suspicious_tld_signal(parsed(from_address="a@example.test")) is None


def test_link_host_threshold_deduplicates_hosts() -> None:
    hosts = [f"h{i}.example.test" for i in range(5)]
    links = [{"url": f"https://{host}", "host": host} for host in hosts + hosts[:2]]
    assert link_host_count_signal(parsed(links=links)) is not None

    few = [{"url": "https://a.example.test", "host": "a.example.test"}] * 6
    assert link_host_count_signal(parsed(links=few)) is None


def test_credential_url_requires_http_scheme_and_both_parts() -> None:
    good = [{"url": "https://user:pass@example.test", "host": "example.test"}]
    assert url_credential_scheme_signal(parsed(links=good)) is not None

    cases = [
        [{"url": "ftp://user:pass@example.test", "host": "example.test"}],
        [{"url": "https://user@example.test", "host": "example.test"}],
        [{"url": "https://:pass@example.test", "host": "example.test"}],
        [{"url": "http://[::1", "host": ""}],
    ]
    for links in cases:
        assert url_credential_scheme_signal(parsed(links=links)) is None


def test_punycode_host_detection() -> None:
    links = [{"url": "https://xn--bcher-kva.example", "host": "xn--bcher-kva.example"}]
    assert punycode_host_signal(parsed(links=links)) is not None


def test_attachment_mismatch_ignores_missing_metadata() -> None:
    assert (
        attachment_type_mismatch_signal(
            parsed(), [attachment(declared_content_type=None, detected_content_type="image/png")]
        )
        is None
    )
    assert (
        attachment_type_mismatch_signal(
            parsed(),
            [
                attachment(
                    declared_content_type="application/pdf",
                    detected_content_type="image/png",
                )
            ],
        )
        is not None
    )


def test_zip_and_rar_classification_from_metadata_only() -> None:
    zip_item = attachment(filename="archive.zip")
    rar_item = attachment(detected_content_type="application/vnd.rar")
    assert archive_attachment_signal(parsed(), [zip_item]) is not None
    assert archive_attachment_signal(parsed(), [rar_item]) is not None
    assert archive_attachment_signal(parsed(), [attachment(filename="doc.txt")]) is None


def test_html_form_detection_does_not_execute_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("network or process access attempted")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    record = parsed(html_body="<html><form><script>alert(1)</script></form></html>")
    assert html_form_count_signal(record) is not None
    assert html_form_count_signal(parsed(html_body="<p>no form</p>")) is None


def test_missing_date_uses_parser_fields() -> None:
    assert missing_date_signal(parsed(date_header=None, date_parsed=None)) is not None
    assert missing_date_signal(parsed(date_header="bad", date_parsed=None)) is not None
    assert missing_date_signal(parsed()) is None


def test_reply_to_mismatch_uses_normalized_domains() -> None:
    assert (
        reply_to_mismatch_signal(
            parsed(
                from_address="A <Alice@Example.COM.>",
                reply_to_addresses=["B <bob@example.com>"],
            )
        )
        is None
    )
    assert (
        reply_to_mismatch_signal(
            parsed(from_address="a@example.test", reply_to_addresses=["b@other.test"])
        )
        is not None
    )


def test_evaluate_signals_is_deterministic() -> None:
    record = parsed(
        from_address="a@gmail.com",
        reply_to_addresses=["b@other.test"],
        links=[{"url": "https://u:p@x.top", "host": "x.top"}],
        html_body="<form></form>",
        headers={"authentication-results": ["spf=pass"]},
    )
    first = [signal.as_dict() for signal in evaluate_signals(record, [])]
    second = [signal.as_dict() for signal in evaluate_signals(record, [])]
    assert first == second
