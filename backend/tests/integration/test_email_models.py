"""Database tests for the Milestone 2.3.1 ingestion schema.

These run against the real PHISHGUARD PostgreSQL service on
127.0.0.1:5434 and against the ``phishguard_test`` database only. The
fixture chain validates the target before anything is written, so a
misconfiguration refuses to run rather than touching the wrong database.

The unit tests in ``tests/test_models.py`` check the *declared* schema. These
tests check that PostgreSQL actually enforces it.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from app.models import (
    AnalysisResult,
    AuditEvent,
    EmailAttachment,
    EmailEvidence,
    ParsedEmail,
)
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, async_sessionmaker

pytestmark = pytest.mark.integration

TABLES = (
    "email_evidence",
    "parsed_emails",
    "email_attachments",
    "audit_events",
    "analysis_results",
)


def _digest(seed: str = "a") -> str:
    return (seed * 64)[:64]


@asynccontextmanager
async def engine_begin(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    """A transaction that rolls back when the block raises."""
    async with engine.begin() as connection:
        yield connection


@pytest_asyncio.fixture
async def db(integration_engine: AsyncEngine, clean_tables: None) -> AsyncIterator[AsyncEngine]:
    """A validated, empty schema for one test."""
    yield integration_engine


async def _new_evidence(db: AsyncEngine, **overrides: object) -> uuid.UUID:
    """Insert one evidence row and return its identifier."""
    values: dict[str, object] = {
        "sha256": _digest("a"),
        "size_bytes": 1024,
        "storage_id": "ab/cd/0123.bin",
        "status": "parsing",
    }
    values.update(overrides)
    async with db.begin() as connection:
        result = await connection.execute(
            EmailEvidence.__table__.insert()
            .values(**values)
            .returning(EmailEvidence.__table__.c.id)
        )
        return result.scalar_one()


async def _new_parsed(db: AsyncEngine, evidence_id: uuid.UUID) -> uuid.UUID:
    async with db.begin() as connection:
        return (
            await connection.execute(
                ParsedEmail.__table__.insert()
                .values(
                    email_evidence_id=evidence_id,
                    parser_version="1.0.0",
                    multipart=False,
                    part_count=1,
                    max_depth=1,
                    defect_count=0,
                )
                .returning(ParsedEmail.__table__.c.id)
            )
        ).scalar_one()


async def test_all_five_tables_exist(db: AsyncEngine) -> None:
    async with db.connect() as connection:
        rows = await connection.execute(
            text("select table_name from information_schema.tables where table_schema = 'public'")
        )
        present = {row[0] for row in rows}
    for table in TABLES:
        assert table in present, table


async def test_a_row_round_trips(db: AsyncEngine) -> None:
    evidence_id = await _new_evidence(
        db,
        original_filename="invoice.eml",
        declared_content_type="message/rfc822",
        parser_version="1.0.0",
    )
    async with async_sessionmaker(db, expire_on_commit=False)() as session:
        row = await session.get(EmailEvidence, evidence_id)
    assert row is not None
    assert row.sha256 == _digest("a")
    assert row.size_bytes == 1024
    assert row.storage_id == "ab/cd/0123.bin"
    assert row.status == "parsing"
    assert row.original_filename == "invoice.eml"
    assert row.received_at is not None
    assert row.updated_at is not None


async def test_identifiers_are_generated_by_the_database(db: AsyncEngine) -> None:
    async with db.begin() as connection:
        result = await connection.execute(
            EmailEvidence.__table__.insert()
            .values(
                sha256=_digest("b"),
                size_bytes=10,
                storage_id="ab/cd/4567.bin",
                status="parsing",
            )
            .returning(EmailEvidence.__table__.c.id)
        )
        generated = result.scalar_one()
    assert isinstance(generated, uuid.UUID)


async def test_status_is_constrained(db: AsyncEngine) -> None:
    with pytest.raises(DBAPIError):
        await _new_evidence(db, status="not-a-status")


async def test_a_tombstone_must_carry_its_timestamp(db: AsyncEngine) -> None:
    """A tombstone must carry the timestamp that explains it.

    The rule is one-directional: ``deleted`` requires a timestamp, and a
    non-deleted row must not have one. A live row with no timestamp is
    perfectly valid.
    """
    with pytest.raises(DBAPIError):
        await _new_evidence(db, status="deleted", deleted_at=None)

    with pytest.raises(DBAPIError):
        await _new_evidence(db, status="parsed", deleted_at=datetime.now(UTC))

    # A tombstone with its timestamp is accepted.
    tombstoned = await _new_evidence(db, status="deleted", deleted_at=datetime.now(UTC))
    assert tombstoned is not None


async def test_the_attachment_size_column_is_a_bigint(db: AsyncEngine) -> None:
    """Revision 5.2.1 §6.4 requires ``size_bytes BIGINT``.

    The model declares it, but only PostgreSQL can confirm what was really
    created.
    """
    async with db.connect() as connection:
        data_type = await connection.scalar(
            text(
                "select data_type from information_schema.columns "
                "where table_schema = 'public' "
                "and table_name = 'email_attachments' "
                "and column_name = 'size_bytes'"
            )
        )
        is_nullable = await connection.scalar(
            text(
                "select is_nullable from information_schema.columns "
                "where table_schema = 'public' "
                "and table_name = 'email_attachments' "
                "and column_name = 'size_bytes'"
            )
        )
    assert data_type == "bigint"
    assert is_nullable == "YES"


async def test_the_digest_must_be_present(db: AsyncEngine) -> None:
    with pytest.raises(DBAPIError):
        await _new_evidence(db, sha256=None)


async def test_only_one_parsed_view_per_evidence_object(db: AsyncEngine) -> None:
    evidence_id = await _new_evidence(db, sha256=_digest("c"))
    values = {
        "email_evidence_id": evidence_id,
        "parser_version": "1.0.0",
        "multipart": False,
        "part_count": 1,
        "max_depth": 1,
        "defect_count": 0,
    }
    async with db.begin() as connection:
        await connection.execute(ParsedEmail.__table__.insert().values(**values))
    with pytest.raises(IntegrityError):
        async with engine_begin(db) as connection:
            await connection.execute(ParsedEmail.__table__.insert().values(**values))


async def test_only_one_analysis_result_per_evidence_object(db: AsyncEngine) -> None:
    evidence_id = await _new_evidence(db, sha256=_digest("d"))
    values = {
        "email_evidence_id": evidence_id,
        "score": 42,
        "risk_band": "medium",
        "signals": [],
        "narrative_status": "unavailable",
        "narrative_reason": "investigation pending",
        "engine_version": "1.0.0",
    }
    async with db.begin() as connection:
        await connection.execute(AnalysisResult.__table__.insert().values(**values))
    with pytest.raises(IntegrityError):
        async with engine_begin(db) as connection:
            await connection.execute(AnalysisResult.__table__.insert().values(**values))


async def test_attachment_digest_and_decode_flag_must_agree(db: AsyncEngine) -> None:
    """Q-2, enforced by the database and not only by convention."""
    evidence_id = await _new_evidence(db, sha256=_digest("e"))
    parsed_id = await _new_parsed(db, evidence_id)

    def attachment(**overrides: object) -> dict[str, object]:
        values: dict[str, object] = {
            "parsed_email_id": parsed_id,
            "part_index": 0,
            "category": "attachment",
            "decode_ok": True,
            "sha256": _digest("f"),
        }
        values.update(overrides)
        return values

    # A decoded attachment must carry a digest. This is the valid case.
    async with db.begin() as connection:
        await connection.execute(
            EmailAttachment.__table__.insert().values(**attachment(part_index=0))
        )
    # A failed decode with no digest is also valid: that is the Q-2 state.
    async with db.begin() as connection:
        await connection.execute(
            EmailAttachment.__table__.insert().values(
                **attachment(part_index=1, decode_ok=False, sha256=None)
            )
        )
    # A failed decode that claims a digest is refused.
    with pytest.raises(DBAPIError):
        async with engine_begin(db) as connection:
            await connection.execute(
                EmailAttachment.__table__.insert().values(
                    **attachment(part_index=2, decode_ok=False)
                )
            )
    # A decoded attachment with no digest is refused too.
    with pytest.raises(DBAPIError):
        async with engine_begin(db) as connection:
            await connection.execute(
                EmailAttachment.__table__.insert().values(
                    **attachment(part_index=3, decode_ok=True, sha256=None)
                )
            )


async def test_attachment_category_is_constrained(db: AsyncEngine) -> None:
    evidence_id = await _new_evidence(db, sha256=_digest("g"))
    parsed_id = await _new_parsed(db, evidence_id)
    with pytest.raises(DBAPIError):
        async with engine_begin(db) as connection:
            await connection.execute(
                EmailAttachment.__table__.insert().values(
                    parsed_email_id=parsed_id,
                    part_index=0,
                    category="body",
                    decode_ok=False,
                    sha256=None,
                )
            )


async def test_score_and_band_are_constrained(db: AsyncEngine) -> None:
    evidence_id = await _new_evidence(db, sha256=_digest("h"))

    def result(**overrides: object) -> dict[str, object]:
        values: dict[str, object] = {
            "email_evidence_id": evidence_id,
            "score": 10,
            "risk_band": "low",
            "signals": [],
            "narrative_status": "unavailable",
            "engine_version": "1.0.0",
        }
        values.update(overrides)
        return values

    with pytest.raises(DBAPIError):
        async with engine_begin(db) as connection:
            await connection.execute(AnalysisResult.__table__.insert().values(**result(score=101)))
    with pytest.raises(DBAPIError):
        async with engine_begin(db) as connection:
            await connection.execute(
                AnalysisResult.__table__.insert().values(**result(risk_band="extreme"))
            )


async def test_narrative_must_match_its_status(db: AsyncEngine) -> None:
    evidence_id = await _new_evidence(db, sha256=_digest("i"))

    def result(**overrides: object) -> dict[str, object]:
        values: dict[str, object] = {
            "email_evidence_id": evidence_id,
            "score": 10,
            "risk_band": "low",
            "signals": [],
            "narrative_status": "unavailable",
            "narrative_reason": "investigation pending",
            "engine_version": "1.0.0",
        }
        values.update(overrides)
        return values

    # "available" without a narrative is refused.
    with pytest.raises(DBAPIError):
        async with engine_begin(db) as connection:
            await connection.execute(
                AnalysisResult.__table__.insert().values(
                    **result(narrative_status="available", narrative_reason=None)
                )
            )
    # A narrative without "available" is refused.
    with pytest.raises(DBAPIError):
        async with engine_begin(db) as connection:
            await connection.execute(
                AnalysisResult.__table__.insert().values(
                    **result(narrative_status="unavailable", narrative="some prose")
                )
            )


async def test_deleting_the_evidence_cascades(db: AsyncEngine) -> None:
    """The parsed view, the attachments and the analysis result all go."""
    evidence_id = await _new_evidence(db, sha256=_digest("j"))
    parsed_id = await _new_parsed(db, evidence_id)
    async with db.begin() as connection:
        await connection.execute(
            EmailAttachment.__table__.insert().values(
                parsed_email_id=parsed_id,
                part_index=0,
                category="attachment",
                decode_ok=False,
                sha256=None,
            )
        )
        await connection.execute(
            AnalysisResult.__table__.insert().values(
                email_evidence_id=evidence_id,
                score=5,
                risk_band="low",
                signals=[],
                narrative_status="disabled",
                narrative_reason="no AI agent configured",
                engine_version="1.0.0",
            )
        )

    async with db.begin() as connection:
        await connection.execute(
            EmailEvidence.__table__.delete().where(EmailEvidence.__table__.c.id == evidence_id)
        )

    async with db.connect() as connection:
        parsed_count = await connection.scalar(
            text("select count(*) from parsed_emails where email_evidence_id = :eid"),
            {"eid": evidence_id},
        )
        attachment_count = await connection.scalar(text("select count(*) from email_attachments"))
        analysis_count = await connection.scalar(
            text("select count(*) from analysis_results where email_evidence_id = :eid"),
            {"eid": evidence_id},
        )
    assert parsed_count == 0
    assert attachment_count == 0
    assert analysis_count == 0


async def test_an_audit_event_survives_the_deletion_of_its_subject(db: AsyncEngine) -> None:
    """A tombstone keeps the audit link intact."""
    evidence_id = await _new_evidence(db, sha256=_digest("k"))
    async with db.begin() as connection:
        await connection.execute(
            AuditEvent.__table__.insert().values(
                event_type="uploaded",
                email_evidence_id=evidence_id,
                detail={"size_bytes": 1024},
                actor="local",
            )
        )
    async with db.begin() as connection:
        await connection.execute(
            EmailEvidence.__table__.update()
            .where(EmailEvidence.__table__.c.id == evidence_id)
            .values(status="deleted", deleted_at=datetime.now(UTC))
        )
    async with db.connect() as connection:
        linked = await connection.scalar(
            text("select email_evidence_id from audit_events where event_type = 'uploaded'")
        )
    assert linked == evidence_id


async def test_a_physical_deletion_nulls_the_audit_link(db: AsyncEngine) -> None:
    """The real ``ON DELETE SET NULL`` action, exercised by PostgreSQL.

    The tombstone test above only sets ``status='deleted'``; the row stays.
    This test deletes the evidence row for real, so the database must apply
    the foreign key's ``ON DELETE SET NULL`` and keep the audit event with a
    null link.
    """
    evidence_id = await _new_evidence(db, sha256=_digest("m"))
    async with db.begin() as connection:
        await connection.execute(
            AuditEvent.__table__.insert().values(
                event_type="uploaded",
                email_evidence_id=evidence_id,
                detail={"size_bytes": 1024},
                actor="local",
            )
        )

    # The evidence row is physically removed. The audit event must survive.
    async with db.begin() as connection:
        await connection.execute(
            EmailEvidence.__table__.delete().where(EmailEvidence.__table__.c.id == evidence_id)
        )

    async with db.connect() as connection:
        row = (
            await connection.execute(
                text(
                    "select event_type, email_evidence_id from audit_events "
                    "where event_type = 'uploaded'"
                )
            )
        ).one()

    # The audit event still exists ...
    assert row.event_type == "uploaded"
    # ... and its link to the deleted evidence is null, not dangling.
    assert row.email_evidence_id is None


async def test_an_audit_event_may_exist_without_an_evidence_row(db: AsyncEngine) -> None:
    """The link is nullable, so a record can outlive a physical deletion."""
    async with db.begin() as connection:
        await connection.execute(
            AuditEvent.__table__.insert().values(
                event_type="reparse_completed",
                email_evidence_id=None,
                detail={"ok": True},
            )
        )
    async with db.connect() as connection:
        count = await connection.scalar(text("select count(*) from audit_events"))
    assert count >= 1
