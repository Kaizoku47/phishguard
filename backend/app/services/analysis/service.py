"""Deterministic analysis persistence.

Signal evaluation and scoring are pure. This module loads minimal immutable
snapshots, computes the deterministic result, collects supplementary
intelligence off the event loop, then writes one authoritative
``analysis_results`` row. It performs no filesystem or model work.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.config import Settings, get_settings
from app.core.exceptions import NotFoundError
from app.models import AnalysisResult, EmailAttachment, ParsedEmail
from app.models.analysis_result import NARRATIVE_UNAVAILABLE
from app.services.analysis.intel import collect_intelligence
from app.services.analysis.score import ScoreResult, build_score_result
from app.services.analysis.signals import evaluate_signals

SessionFactory = async_sessionmaker[Any]


@dataclass(frozen=True, slots=True)
class _ParsedSnapshot:
    """Minimal immutable parsed-field view used by deterministic signals."""

    from_address: str | None
    reply_to_addresses: list[str] | None
    links: list[dict[str, Any]] | None
    html_body: str | None
    date_header: str | None
    date_parsed: Any
    headers: dict[str, list[str]] | None


@dataclass(frozen=True, slots=True)
class _AttachmentSnapshot:
    """Minimal immutable attachment metadata used by signals and intel."""

    filename: str | None
    declared_content_type: str | None
    detected_content_type: str | None
    sha256: str | None


def _snapshot(
    parsed: ParsedEmail, attachments: list[EmailAttachment]
) -> tuple[_ParsedSnapshot, list[_AttachmentSnapshot]]:
    return (
        _ParsedSnapshot(
            from_address=parsed.from_address,
            reply_to_addresses=list(parsed.reply_to_addresses or []),
            links=[dict(link) for link in (parsed.links or []) if isinstance(link, dict)],
            html_body=parsed.html_body,
            date_header=parsed.date_header,
            date_parsed=parsed.date_parsed,
            headers={key: list(value) for key, value in (parsed.headers or {}).items()},
        ),
        [
            _AttachmentSnapshot(
                filename=item.filename,
                declared_content_type=item.declared_content_type,
                detected_content_type=item.detected_content_type,
                sha256=item.sha256,
            )
            for item in attachments
        ],
    )


async def analyse_and_persist(
    evidence_id: UUID,
    session_factory: SessionFactory,
    settings: Settings | None = None,
) -> ScoreResult:
    """Calculate and persist at most one result for one evidence record.

    External intelligence runs in a worker thread and outside the database
    transaction. A second check for an existing result guards concurrent
    analysis attempts; the database unique constraint remains the final guard.
    """
    async with session_factory() as session:
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
        parsed_snapshot, attachment_snapshots = _snapshot(parsed, attachments)

    signals = evaluate_signals(parsed_snapshot, attachment_snapshots)
    result = build_score_result(signals)
    intelligence = await asyncio.to_thread(
        collect_intelligence,
        parsed_snapshot,
        attachment_snapshots,
        settings or get_settings(),
    )

    try:
        async with session_factory() as session, session.begin():
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
                        intelligence_results=intelligence.as_dict(),
                        narrative=None,
                        narrative_status=NARRATIVE_UNAVAILABLE,
                        narrative_reason="investigation pending",
                        engine_version=result.engine_version,
                    )
                )
            return result
    except IntegrityError:
        # A concurrent analysis may insert the same row after both writers
        # observe no existing result. Confirm a winner before treating it as
        # idempotent; any other integrity failure still propagates.
        async with session_factory() as check:
            winner = await check.scalar(
                select(AnalysisResult).where(AnalysisResult.email_evidence_id == evidence_id)
            )
        if winner is None:
            raise
        return result
