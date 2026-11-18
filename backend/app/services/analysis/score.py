"""Deterministic scoring for Milestone 2.3.5.

All signal weights live in :data:`SIGNAL_WEIGHTS`. The scoring functions are
pure: they read signal objects and return values, with no database, network,
filesystem or model access.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from app.services.analysis.signals import Signal

ENGINE_VERSION = "1.0.0"

# The single authoritative weight table. Signal construction reads from here.
SIGNAL_WEIGHTS: dict[str, int] = {
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

BAND_LOW = "low"
BAND_MEDIUM = "medium"
BAND_HIGH = "high"
BAND_CRITICAL = "critical"

# Owner-approved v1 ranges, inclusive at both ends.
BAND_RANGES: tuple[tuple[int, int, str], ...] = (
    (0, 24, BAND_LOW),
    (25, 49, BAND_MEDIUM),
    (50, 79, BAND_HIGH),
    (80, 100, BAND_CRITICAL),
)


@dataclass(frozen=True, slots=True)
class ScoreResult:
    """The authoritative deterministic result for one parsed record."""

    score: int
    risk_band: str
    signals: list[dict[str, object]]
    engine_version: str = ENGINE_VERSION


def clamp_score(value: int) -> int:
    """Clamp a score to the approved 0-100 range."""
    return max(0, min(100, int(value)))


def score_signals(signals: Iterable[Signal]) -> int:
    """Sum contributions from evaluated signals only.

    An unevaluated signal is ignored even if its contribution field is
    defensive-nonzero, so a caller cannot accidentally award points.
    """
    total = 0
    for signal in signals:
        if signal.evaluated:
            total += signal.contribution
    return clamp_score(total)


def risk_band(score: int) -> str:
    """Derive the risk band from the clamped score using the approved ranges."""
    value = clamp_score(score)
    for lower, upper, band in BAND_RANGES:
        if lower <= value <= upper:
            return band
    raise AssertionError("BAND_RANGES must cover 0-100")  # pragma: no cover


def build_score_result(signals: Iterable[Signal]) -> ScoreResult:
    """Build a deterministic score result from evaluated signals."""
    materialized = list(signals)
    score = score_signals(materialized)
    return ScoreResult(
        score=score,
        risk_band=risk_band(score),
        signals=[signal.as_dict() for signal in materialized],
        engine_version=ENGINE_VERSION,
    )
