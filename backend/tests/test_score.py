"""Unit tests for deterministic scoring (T-44 and T-45)."""

from __future__ import annotations

from types import SimpleNamespace

from app.services.analysis.score import (
    BAND_CRITICAL,
    BAND_HIGH,
    BAND_LOW,
    BAND_MEDIUM,
    ENGINE_VERSION,
    SIGNAL_WEIGHTS,
    build_score_result,
    clamp_score,
    risk_band,
    score_signals,
)
from app.services.analysis.signals import Signal, auth_results_unverifiable_signal

EXPECTED_WEIGHTS = {
    "reply_to_mismatch": 20,
    "lookalike_sender_domain": 18,
    "auth_results_unverifiable": 0,
    "link_host_count": 10,
    "url_credential_scheme": 15,
    "punycode_host": 15,
    "free_mail_sender": 8,
    "attachment_type_mismatch": 12,
    "archive_attachment": 10,
    "html_form_count": 20,
    "suspicious_tld": 8,
    "missing_date": 5,
}


def evaluated(signal_id: str, contribution: int | None = None) -> Signal:
    return Signal(
        id=signal_id,
        severity="medium",
        contribution=SIGNAL_WEIGHTS[signal_id] if contribution is None else contribution,
        reason=f"reason for {signal_id}",
        evaluated=True,
    )


def test_t45_all_signal_contributions_are_centrally_defined() -> None:
    assert SIGNAL_WEIGHTS == EXPECTED_WEIGHTS
    for signal_id, contribution in EXPECTED_WEIGHTS.items():
        assert evaluated(signal_id).contribution == contribution


def test_t44_unevaluated_signal_does_not_affect_score() -> None:
    base = [evaluated("reply_to_mismatch")]
    with_auth = [*base, auth_results_unverifiable_signal()]

    assert score_signals(base) == 20
    assert score_signals(with_auth) == 20

    defensive = SimpleNamespace(evaluated=False, contribution=50)
    assert score_signals([evaluated("missing_date"), defensive]) == 5  # type: ignore[arg-type]


def test_t45_aggregation_and_clamping() -> None:
    signals = [
        evaluated("reply_to_mismatch"),
        evaluated("lookalike_sender_domain"),
        evaluated("html_form_count"),
        evaluated("url_credential_scheme"),
        evaluated("punycode_host"),
        evaluated("link_host_count"),
        evaluated("archive_attachment"),
    ]
    assert score_signals(signals) == 100
    assert clamp_score(150) == 100
    assert clamp_score(-5) == 0


def test_t45_all_risk_boundaries() -> None:
    assert risk_band(0) == BAND_LOW
    assert risk_band(24) == BAND_LOW
    assert risk_band(25) == BAND_MEDIUM
    assert risk_band(49) == BAND_MEDIUM
    assert risk_band(50) == BAND_HIGH
    assert risk_band(79) == BAND_HIGH
    assert risk_band(80) == BAND_CRITICAL
    assert risk_band(100) == BAND_CRITICAL


def test_score_result_is_deterministic() -> None:
    signals = [
        evaluated("reply_to_mismatch"),
        evaluated("missing_date"),
        auth_results_unverifiable_signal(),
    ]

    first = build_score_result(signals)
    second = build_score_result(signals)

    assert first == second
    assert first.score == 25
    assert first.risk_band == BAND_MEDIUM
    assert first.engine_version == ENGINE_VERSION
    assert [entry["id"] for entry in first.signals] == [
        "reply_to_mismatch",
        "missing_date",
        "auth_results_unverifiable",
    ]
