"""Integration tests for deterministic analysis persistence (T-51 and T-52)."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import threading
import time
from datetime import UTC, datetime
from typing import Any

import pytest
from app.core.config import get_settings
from app.db.target import validate_test_target
from app.models import AnalysisResult, EmailAttachment, EmailEvidence, ParsedEmail
from app.services.analysis import IntelligenceResult, analyse_and_persist
from app.services.analysis import service as analysis_service
from app.services.analysis.score import build_score_result
from app.services.analysis.signals import evaluate_signals
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

pytestmark = pytest.mark.integration


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _test_settings():
    """Deterministic settings: the agent must not depend on ambient .env state."""
    return get_settings().model_copy(update={"agent_enabled": False, "agent_api_key": None})


@pytest.mark.asyncio
async def test_t51_analysis_persists_one_authoritative_result() -> None:
    settings = _test_settings()
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

        result = await analyse_and_persist(evidence_id, factory, settings)

        async with factory() as session:
            rows = list((await session.execute(select(AnalysisResult))).scalars())
            count = await session.scalar(select(func.count()).select_from(AnalysisResult))

        assert count == 1
        stored = rows[0]
        assert stored.email_evidence_id == evidence_id
        assert stored.score == result.score
        assert stored.risk_band == result.risk_band
        assert stored.signals == result.signals
        intelligence = stored.intelligence_results
        assert intelligence["domains"] == {}
        assert intelligence["hashes"] == {}
        assert intelligence["missing"]
        assert all(item["reason"] == "api_key_not_configured" for item in intelligence["missing"])
        assert stored.engine_version == result.engine_version
        assert stored.narrative is None
        assert stored.narrative_status == "disabled"
        assert stored.narrative_reason == "no AI agent configured"
        assert any(item["id"] == "auth_results_unverifiable" for item in stored.signals)

        # T-52: repeat analysis leaves exactly one authoritative row.
        second = await analyse_and_persist(evidence_id, factory, settings)
        assert second == result
        async with factory() as session:
            count_again = await session.scalar(select(func.count()).select_from(AnalysisResult))
        assert count_again == 1
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_t50_provider_failure_does_not_change_deterministic_score(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _test_settings()
    url = settings.database_url_test
    validate_test_target(url)
    engine = create_async_engine(url, pool_pre_ping=True)
    factory: async_sessionmaker[Any] = async_sessionmaker(
        engine, expire_on_commit=False, autoflush=False
    )
    missing = IntelligenceResult(
        missing=[{"target": "otx:domains:example.test", "reason": "provider_timeout"}]
    )

    def failed_intelligence(*args: object, **kwargs: object) -> IntelligenceResult:
        return missing

    monkeypatch.setattr(analysis_service, "collect_intelligence", failed_intelligence)

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
                sha256=_digest("timeout-evidence"),
                size_bytes=4,
                storage_id="bb/cc/" + "b" * 32 + ".eml",
                status="parsed",
            )
            session.add(evidence)
            await session.flush()
            parsed = ParsedEmail(
                email_evidence_id=evidence.id,
                parser_version="phishguard-parser-2.3.3",
                from_address="a@example.test",
                reply_to_addresses=[],
                date_header="Tue, 17 Nov 2026 10:00:00 +0000",
                date_parsed=datetime(2026, 11, 17, 10, 0, tzinfo=UTC),
                links=[],
                html_body=None,
                headers={},
                multipart=False,
                part_count=1,
                max_depth=0,
                defect_count=0,
                defect_types=[],
            )
            session.add(parsed)
            await session.flush()
            evidence_id = evidence.id

        async with factory() as session:
            parsed_row = await session.scalar(
                select(ParsedEmail).where(ParsedEmail.email_evidence_id == evidence_id)
            )
            expected = build_score_result(evaluate_signals(parsed_row, []))

        result = await analyse_and_persist(evidence_id, factory, settings)

        assert result.score == expected.score
        assert result.risk_band == expected.risk_band
        assert result.signals == expected.signals
        async with factory() as session:
            stored = await session.scalar(
                select(AnalysisResult).where(AnalysisResult.email_evidence_id == evidence_id)
            )
        assert stored is not None
        assert stored.intelligence_results == missing.as_dict()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_analysis_does_not_block_event_loop_during_slow_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _test_settings()
    url = settings.database_url_test
    validate_test_target(url)
    engine = create_async_engine(url, pool_pre_ping=True)
    factory: async_sessionmaker[Any] = async_sessionmaker(
        engine, expire_on_commit=False, autoflush=False
    )

    slow_seconds = 0.15
    main_thread = threading.get_ident()
    worker_threads: list[int] = []

    def slow_intelligence(*args: object, **kwargs: object) -> IntelligenceResult:
        worker_threads.append(threading.get_ident())
        time.sleep(slow_seconds)
        return IntelligenceResult()

    monkeypatch.setattr(analysis_service, "collect_intelligence", slow_intelligence)

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
                sha256=_digest("nonblocking-evidence"),
                size_bytes=4,
                storage_id="cc/dd/" + "c" * 32 + ".eml",
                status="parsed",
            )
            session.add(evidence)
            await session.flush()
            session.add(
                ParsedEmail(
                    email_evidence_id=evidence.id,
                    parser_version="phishguard-parser-2.3.3",
                    from_address="a@example.test",
                    reply_to_addresses=[],
                    date_header="Tue, 17 Nov 2026 10:00:00 +0000",
                    date_parsed=datetime(2026, 11, 17, 10, 0, tzinfo=UTC),
                    links=[],
                    html_body=None,
                    headers={},
                    multipart=False,
                    part_count=1,
                    max_depth=0,
                    defect_count=0,
                    defect_types=[],
                )
            )
            await session.flush()
            evidence_id = evidence.id

        ticks = 0

        async def heartbeat() -> None:
            nonlocal ticks
            while True:
                ticks += 1
                await asyncio.sleep(0.005)

        task = asyncio.create_task(heartbeat())
        try:
            await analyse_and_persist(evidence_id, factory, settings)
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

        assert worker_threads
        assert worker_threads[0] != main_thread
        assert ticks >= 5
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_concurrent_analysis_is_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _test_settings()
    url = settings.database_url_test
    validate_test_target(url)
    engine = create_async_engine(url, pool_pre_ping=True)
    factory: async_sessionmaker[Any] = async_sessionmaker(
        engine, expire_on_commit=False, autoflush=False
    )

    barrier = threading.Barrier(2)

    def quick_intelligence(*args: object, **kwargs: object) -> IntelligenceResult:
        barrier.wait(timeout=5)
        return IntelligenceResult()

    monkeypatch.setattr(analysis_service, "collect_intelligence", quick_intelligence)

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
                sha256=_digest("concurrent-evidence"),
                size_bytes=4,
                storage_id="dd/ee/" + "d" * 32 + ".eml",
                status="parsed",
            )
            session.add(evidence)
            await session.flush()
            session.add(
                ParsedEmail(
                    email_evidence_id=evidence.id,
                    parser_version="phishguard-parser-2.3.3",
                    from_address="a@example.test",
                    reply_to_addresses=[],
                    date_header="Tue, 17 Nov 2026 10:00:00 +0000",
                    date_parsed=datetime(2026, 11, 17, 10, 0, tzinfo=UTC),
                    links=[],
                    html_body=None,
                    headers={},
                    multipart=False,
                    part_count=1,
                    max_depth=0,
                    defect_count=0,
                    defect_types=[],
                )
            )
            await session.flush()
            evidence_id = evidence.id

        first, second = await asyncio.gather(
            analyse_and_persist(evidence_id, factory, settings),
            analyse_and_persist(evidence_id, factory, settings),
        )
        assert first == second

        async with factory() as session:
            count = await session.scalar(
                select(func.count())
                .select_from(AnalysisResult)
                .where(AnalysisResult.email_evidence_id == evidence_id)
            )
        assert count == 1
    finally:
        await engine.dispose()
