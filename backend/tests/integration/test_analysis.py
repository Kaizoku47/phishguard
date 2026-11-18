"""Integration tests for deterministic analysis persistence (T-51 and T-52)."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

import pytest
from app.core.config import get_settings
from app.db.target import validate_test_target
from app.models import AnalysisResult, EmailAttachment, EmailEvidence, ParsedEmail
from app.services.analysis import analyse_and_persist
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

pytestmark = pytest.mark.integration


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.mark.asyncio
async def test_t51_analysis_persists_one_authoritative_result() -> None:
    settings = get_settings()
    url = settings.database_url_test
    validate_test_target(url)
    engine = create_async_engine(url, pool_pre_ping=True)
    factory: async_sessionmaker[Any] = async_sessionmaker(
        engine, expire_on_commit=False, autoflush=False
    )

    try:
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "TRUNCATE email_attachments, parsed_emails, analysis_results, "
                    "audit_events, email_evidence CASCADE"
                )
            )

        async with factory() as session, session.begin():
            evidence = EmailEvidence(
                sha256=_digest("evidence"),
                size_bytes=64,
                storage_id="aa/bb/" + "a" * 32 + ".eml",
                status="parsed",
            )
            session.add(evidence)
            await session.flush()
            evidence_id = evidence.id

            parsed = ParsedEmail(
                email_evidence_id=evidence_id,
                parser_version="phishguard-parser-2.3.3",
                from_address="Alice <alice@gmail.com>",
                reply_to_addresses=["Bob <bob@example.test>"],
                date_header="Tue, 17 Nov 2026 10:00:00 +0000",
                date_parsed=datetime(2026, 11, 17, 10, 0, tzinfo=UTC),
                links=[{"url": "https://u:p@x.top", "host": "x.top"}],
                html_body="<form></form>",
                headers={},
                multipart=False,
                part_count=1,
                max_depth=0,
                defect_count=0,
                defect_types=[],
            )
            session.add(parsed)
            await session.flush()

            session.add(
                EmailAttachment(
                    parsed_email_id=parsed.id,
                    part_index=0,
                    category="attachment",
                    filename="report.pdf",
                    declared_content_type="application/pdf",
                    detected_content_type="image/png",
                    decode_ok=True,
                    sha256=_digest("attachment"),
                    size_bytes=8,
                )
            )

        result = await analyse_and_persist(evidence_id, factory)

        async with factory() as session:
            rows = list((await session.execute(select(AnalysisResult))).scalars())
            count = await session.scalar(select(func.count()).select_from(AnalysisResult))

        assert count == 1
        stored = rows[0]
        assert stored.email_evidence_id == evidence_id
        assert stored.score == result.score
        assert stored.risk_band == result.risk_band
        assert stored.signals == result.signals
        assert stored.intelligence_results == {}
        assert stored.engine_version == result.engine_version
        assert stored.narrative is None
        assert stored.narrative_status == "unavailable"
        assert stored.narrative_reason == "investigation pending"
        assert any(item["id"] == "auth_results_unverifiable" for item in stored.signals)

        # T-52: repeat analysis leaves exactly one authoritative row.
        second = await analyse_and_persist(evidence_id, factory)
        assert second == result
        async with factory() as session:
            count_again = await session.scalar(select(func.count()).select_from(AnalysisResult))
        assert count_again == 1
    finally:
        await engine.dispose()
