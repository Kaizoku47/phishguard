"""Deterministic phishing analysis services."""

from __future__ import annotations

from app.services.analysis.score import (
    ENGINE_VERSION,
    SIGNAL_WEIGHTS,
    ScoreResult,
    build_score_result,
    clamp_score,
    risk_band,
    score_signals,
)
from app.services.analysis.service import analyse_and_persist
from app.services.analysis.signals import (
    BRAND_DOMAINS,
    FREE_MAIL_DOMAINS,
    SUSPICIOUS_TLDS,
    Signal,
    evaluate_signals,
    missing_evidence,
    normalize_domain,
)

__all__ = [
    "BRAND_DOMAINS",
    "ENGINE_VERSION",
    "FREE_MAIL_DOMAINS",
    "SIGNAL_WEIGHTS",
    "SUSPICIOUS_TLDS",
    "ScoreResult",
    "Signal",
    "analyse_and_persist",
    "build_score_result",
    "clamp_score",
    "evaluate_signals",
    "missing_evidence",
    "normalize_domain",
    "risk_band",
    "score_signals",
]
