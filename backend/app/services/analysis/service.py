"""Deterministic analysis persistence.

Signal evaluation and scoring are pure; this module only loads the already
parsed record and stores one authoritative ``analysis_results`` row. It does
no network, filesystem or model work.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.exceptions import NotFoundError
from app.models import AnalysisResult, EmailAttachment, ParsedEmail
from app.models.analysis_result import NARRATIVE_UNAVAILABLE
from app.services.analysis.score import ScoreResult, build_score_result
from app.services.analysis.signals import evaluate_signals

SessionFactory = async_sessionmaker[Any]


async def analyse_and_persist(evidence_id: UUID, session_factory: SessionFactory) -> ScoreResult:
    """Calculate the deterministic result and persist at most one row.

    The database unique constraint remains the final guard. A repeated
    analysis simply leaves the existing authoritative row untouched.
    """
    async with session_factory() as session, session.begin():
        parsed = await session.scalar(
            select(ParsedEmail).where(ParsedEmail.email_evidence_id == evidence_id)
        )
        if parsed is None:
            raise NotFoundError

        attachments = list(
            (
                await session.execute(
                    select(EmailAttachment).where(EmailAttachment.parsed_email_id == parsed.id)
                )
            ).scalars()
        )

        signals = evaluate_signals(parsed, attachments)
        result = build_score_result(signals)

        existing = await session.scalar(
            select(AnalysisResult).where(AnalysisResult.email_evidence_id == evidence_id)
        )
        if existing is None:
            session.add(
                AnalysisResult(
                    email_evidence_id=evidence_id,
                    score=result.score,
                    risk_band=result.risk_band,
                    signals=result.signals,
                    intelligence_results={},
                    narrative=None,
                    narrative_status=NARRATIVE_UNAVAILABLE,
                    narrative_reason="investigation pending",
                    engine_version=result.engine_version,
                )
            )
        return result
