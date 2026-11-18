"""Authenticated ingestion, retrieval, deletion and startup recovery.

This module owns the authoritative two-transaction sequence from Architecture
Revision 5.2.2 §9.1. It is framework-neutral: the API layer passes async byte
chunks in and receives plain dictionaries out.

The ingestion path **never** deletes a published evidence file. Only the
explicit delete operation and the startup cleanup's tombstone-driven unlink do
that, and both act on rows the database already marks as deleted.
"""

from __future__ import annotations

import asyncio
import logging
import stat
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import delete as sql_delete
from sqlalchemy import func, select, update
from sqlalchemy.exc import DBAPIError, InterfaceError, SQLAlchemyError
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.config import Settings
from app.core.exceptions import (
    EmptyPayloadError,
    EvidenceStorageError,
    NotFoundError,
    ParsingNotCompleteError,
    PayloadTooLargeError,
)
from app.models import AnalysisResult, AuditEvent, EmailAttachment, EmailEvidence, ParsedEmail
from app.models.audit_event import EVENT_DELETED, EVENT_INTEGRITY_FAILURE, EVENT_UPLOADED
from app.models.email_evidence import (
    STATUS_DELETED,
    STATUS_PARSE_FAILED,
    STATUS_PARSED,
    STATUS_PARSING,
)
from app.services.email import parse_email
from app.services.email.models import ParseResult
from app.services.evidence.store import (
    EvidenceError,
    EvidenceNotFoundError,
    EvidenceStore,
    EvidenceTooLargeError,
    StoredObject,
)

logger = logging.getLogger(__name__)

STALE_AFTER = timedelta(hours=1)

SessionFactory = async_sessionmaker[Any]


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_status(result: ParseResult) -> str:
    if result.limit_exceeded:
        return "limit_exceeded"
    if result.failure_reason:
        return "parse_failed"
    if result.defect_count:
        return "ok_with_defects"
    return "ok"


# ---------------------------------------------------------------------------
# Phase A — receive and publish. No database involvement.
# ---------------------------------------------------------------------------


async def receive_and_publish(chunks: AsyncIterator[bytes], store: EvidenceStore) -> StoredObject:
    """Stream bytes into the evidence store and return the published object."""
    writer = store.open()
    try:
        async for chunk in chunks:
            writer.write(chunk)
    except EvidenceTooLargeError:
        raise PayloadTooLargeError from None
    except EvidenceError:
        raise EvidenceStorageError from None

    if writer.size_bytes == 0:
        writer.abort()
        raise EmptyPayloadError

    try:
        return writer.publish()
    except EvidenceError:
        raise EvidenceStorageError from None


# ---------------------------------------------------------------------------
# TX-1 — evidence row plus uploaded audit event, committed together.
# ---------------------------------------------------------------------------


async def create_evidence_record(
    session_factory: SessionFactory,
    stored: StoredObject,
    declared_content_type: str | None,
) -> tuple[UUID, datetime]:
    """Insert the evidence row and the ``uploaded`` audit event in TX-1."""
    try:
        async with session_factory() as session:
            async with session.begin():
                evidence = EmailEvidence(
                    sha256=stored.sha256,
                    size_bytes=stored.size_bytes,
                    storage_id=stored.storage_id,
                    original_filename=None,
                    declared_content_type=declared_content_type,
                    status=STATUS_PARSING,
                )
                session.add(evidence)
                await session.flush()

                session.add(
                    AuditEvent(
                        event_type=EVENT_UPLOADED,
                        email_evidence_id=evidence.id,
                        detail={"size_bytes": stored.size_bytes, "sha256": stored.sha256},
                    )
                )
            return evidence.id, evidence.received_at
    except (DBAPIError, InterfaceError) as exc:
        uncertain = bool(getattr(exc, "connection_invalidated", False)) or isinstance(
            exc, InterfaceError
        )
        # The published file is deliberately retained in both definite and
        # uncertain cases. Never unlink it on this path.
        logger.error(
            "TX-1 failure (uncertain=%s): storage_id=%s sha256=%s",
            uncertain,
            stored.storage_id,
            stored.sha256,
        )
        raise EvidenceStorageError from None
    except SQLAlchemyError:
        logger.error("TX-1 failure: storage_id=%s sha256=%s", stored.storage_id, stored.sha256)
        raise EvidenceStorageError from None


# ---------------------------------------------------------------------------
# Phase C — parse bytes read back from the published evidence file.
# ---------------------------------------------------------------------------


def parse_published_evidence(
    store: EvidenceStore, storage_id: str, settings: Settings
) -> ParseResult:
    """Read the published file through the store and parse exactly those bytes."""
    try:
        raw = store.read(storage_id)
    except EvidenceError:
        raise EvidenceStorageError from None
    return parse_email(raw, settings.to_parser_limits())


# ---------------------------------------------------------------------------
# TX-2 — lock, insert parsed data, set terminal status, commit together.
# ---------------------------------------------------------------------------


async def persist_parse(
    session_factory: SessionFactory,
    evidence_id: UUID,
    result: ParseResult,
) -> str:
    """Persist the parse result. Returns the terminal evidence status."""
    async with session_factory() as session, session.begin():
        row = await session.execute(
            select(EmailEvidence).where(EmailEvidence.id == evidence_id).with_for_update()
        )
        evidence = row.scalar_one_or_none()
        if evidence is None:
            raise NotFoundError

        if evidence.status == STATUS_DELETED:
            return STATUS_DELETED

        parsed = ParsedEmail(
            email_evidence_id=evidence_id,
            parser_version=result.parser_version,
            subject=result.subject,
            from_address=result.from_address,
            from_display_name=result.from_display_name,
            to_addresses=result.to_addresses,
            cc_addresses=result.cc_addresses,
            reply_to_addresses=result.reply_to_addresses,
            date_header=result.date_header,
            date_parsed=result.date_parsed,
            message_id=result.message_id,
            headers=result.headers,
            text_body=result.text_body,
            html_body=result.html_body,
            body_charset=result.body_charset,
            links=result.links,
            multipart=result.multipart,
            part_count=result.part_count,
            max_depth=result.max_depth,
            defect_count=result.defect_count,
            defect_types=result.defect_types,
        )
        session.add(parsed)
        await session.flush()

        for item in result.attachments:
            session.add(
                EmailAttachment(
                    parsed_email_id=parsed.id,
                    part_index=item.part_index,
                    category=item.category,
                    filename=item.filename,
                    declared_content_type=item.declared_content_type,
                    detected_content_type=item.detected_content_type,
                    content_disposition=item.content_disposition,
                    content_transfer_encoding=item.content_transfer_encoding,
                    size_bytes=item.size_bytes,
                    sha256=item.sha256,
                    decode_ok=item.decode_ok,
                )
            )

        evidence.status = STATUS_PARSED if result.status == "parsed" else STATUS_PARSE_FAILED
        evidence.parser_version = result.parser_version
        evidence.defect_count = result.defect_count
        evidence.limit_exceeded = result.limit_exceeded
        evidence.failure_reason = result.failure_reason
        return evidence.status


async def ingest_message(
    chunks: AsyncIterator[bytes],
    declared_content_type: str | None,
    settings: Settings,
    store: EvidenceStore,
    session_factory: SessionFactory,
    semaphore: asyncio.Semaphore | None = None,
) -> dict[str, Any]:
    """Run the full authoritative ingestion sequence and build the 201 body.

    The semaphore is process-local, as specified by the single-worker MVP.
    """

    async def _run() -> dict[str, Any]:
        stored = await receive_and_publish(chunks, store)
        evidence_id, received_at = await create_evidence_record(
            session_factory, stored, declared_content_type
        )
        result = parse_published_evidence(store, stored.storage_id, settings)
        status = await persist_parse(session_factory, evidence_id, result)
        return {
            "id": evidence_id,
            "status": status,
            "parse_status": _parse_status(result),
            "size_bytes": stored.size_bytes,
            "sha256": stored.sha256,
            "received_at": _iso(received_at),
        }

    if semaphore is None:
        return await _run()
    async with semaphore:
        return await _run()


# ---------------------------------------------------------------------------
# Retrieval helpers — never return bodies, paths or storage ids.
# ---------------------------------------------------------------------------


async def get_evidence(evidence_id: UUID, session_factory: SessionFactory) -> EmailEvidence:
    async with session_factory() as session:
        row = await session.execute(select(EmailEvidence).where(EmailEvidence.id == evidence_id))
        evidence = row.scalar_one_or_none()
    if evidence is None:
        raise NotFoundError
    return evidence


async def get_status(evidence_id: UUID, session_factory: SessionFactory) -> dict[str, Any]:
    evidence = await get_evidence(evidence_id, session_factory)
    return {
        "id": evidence.id,
        "status": evidence.status,
        "size_bytes": evidence.size_bytes,
        "sha256": evidence.sha256,
        "received_at": _iso(evidence.received_at),
        "parser_version": evidence.parser_version,
        "defect_count": evidence.defect_count,
        "limit_exceeded": evidence.limit_exceeded,
        "failure_reason": evidence.failure_reason,
        "deleted_at": _iso(evidence.deleted_at),
    }


async def get_metadata(evidence_id: UUID, session_factory: SessionFactory) -> dict[str, Any]:
    await get_evidence(evidence_id, session_factory)
    async with session_factory() as session:
        row = await session.execute(
            select(ParsedEmail).where(ParsedEmail.email_evidence_id == evidence_id)
        )
        parsed = row.scalar_one_or_none()
    if parsed is None:
        raise ParsingNotCompleteError
    return {
        "subject": parsed.subject,
        "from_address": parsed.from_address,
        "from_display_name": parsed.from_display_name,
        "to_addresses": parsed.to_addresses,
        "cc_addresses": parsed.cc_addresses,
        "reply_to_addresses": parsed.reply_to_addresses,
        "date_header": parsed.date_header,
        "date_parsed": _iso(parsed.date_parsed),
        "message_id": parsed.message_id,
        "headers": parsed.headers,
        "body_charset": parsed.body_charset,
        "links": parsed.links,
        "multipart": parsed.multipart,
        "part_count": parsed.part_count,
        "max_depth": parsed.max_depth,
        "defect_count": parsed.defect_count,
        "defect_types": parsed.defect_types,
        "parser_version": parsed.parser_version,
    }


async def get_attachments(
    evidence_id: UUID, session_factory: SessionFactory
) -> list[dict[str, Any]]:
    await get_evidence(evidence_id, session_factory)
    async with session_factory() as session:
        rows = await session.execute(
            select(EmailAttachment)
            .join(ParsedEmail, EmailAttachment.parsed_email_id == ParsedEmail.id)
            .where(ParsedEmail.email_evidence_id == evidence_id)
            .order_by(EmailAttachment.part_index)
        )
        items = rows.scalars().all()
    return [
        {
            "part_index": item.part_index,
            "category": item.category,
            "filename": item.filename,
            "declared_content_type": item.declared_content_type,
            "detected_content_type": item.detected_content_type,
            "content_disposition": item.content_disposition,
            "content_transfer_encoding": item.content_transfer_encoding,
            "size_bytes": item.size_bytes,
            "sha256": item.sha256,
            "decode_ok": item.decode_ok,
        }
        for item in items
    ]


async def verify_integrity(
    evidence_id: UUID, store: EvidenceStore, session_factory: SessionFactory
) -> dict[str, Any]:
    evidence = await get_evidence(evidence_id, session_factory)
    try:
        verified = store.verify(evidence.storage_id, evidence.sha256)
        present = True
    except EvidenceNotFoundError:
        verified = None
        present = False
    except EvidenceError:
        raise EvidenceStorageError from None

    if verified is False and evidence.status != STATUS_DELETED:
        async with session_factory() as session, session.begin():
            session.add(
                AuditEvent(
                    event_type=EVENT_INTEGRITY_FAILURE,
                    email_evidence_id=evidence_id,
                    detail={"reason": "integrity_mismatch", "sha256": evidence.sha256},
                )
            )
            await session.execute(
                update(EmailEvidence)
                .where(EmailEvidence.id == evidence_id)
                .values(status=STATUS_PARSE_FAILED, failure_reason="integrity_mismatch")
            )
    return {"evidence_present": present, "verified": verified}


# ---------------------------------------------------------------------------
# Deletion — one lock, one order, tombstone first, unlink after commit.
# ---------------------------------------------------------------------------


async def delete_evidence(
    evidence_id: UUID, store: EvidenceStore, session_factory: SessionFactory
) -> dict[str, Any]:
    async with session_factory() as session:
        async with session.begin():
            row = await session.execute(
                select(EmailEvidence).where(EmailEvidence.id == evidence_id).with_for_update()
            )
            evidence = row.scalar_one_or_none()
            if evidence is None:
                raise NotFoundError

            # Count attachments before deleting their parent: the FK cascade
            # removes them, so a delete statement afterwards would count zero.
            attachment_removed = int(
                (
                    await session.execute(
                        select(func.count())
                        .select_from(EmailAttachment)
                        .join(ParsedEmail, EmailAttachment.parsed_email_id == ParsedEmail.id)
                        .where(ParsedEmail.email_evidence_id == evidence_id)
                    )
                ).scalar()
                or 0
            )
            parsed_removed = (
                await session.execute(
                    sql_delete(ParsedEmail).where(ParsedEmail.email_evidence_id == evidence_id)
                )
            ).rowcount
            analysis_removed = (
                await session.execute(
                    sql_delete(AnalysisResult).where(
                        AnalysisResult.email_evidence_id == evidence_id
                    )
                )
            ).rowcount

            evidence.status = STATUS_DELETED
            evidence.deleted_at = func.now()
            evidence.original_filename = None
            evidence.declared_content_type = None

            session.add(
                AuditEvent(
                    event_type=EVENT_DELETED,
                    email_evidence_id=evidence_id,
                    detail={
                        "parsed_rows_removed": parsed_removed,
                        "attachment_rows_removed": attachment_removed,
                        "analysis_results_removed": analysis_removed,
                        "bytes_removed": evidence.size_bytes,
                        "sha256": evidence.sha256,
                    },
                )
            )
        storage_id = evidence.storage_id

    file_removed = True
    try:
        store.delete(storage_id)
    except EvidenceError:
        file_removed = False
        logger.warning("pending cleanup for evidence id=%s", evidence_id)

    return {
        "id": evidence_id,
        "status": STATUS_DELETED,
        "parsed_rows_removed": parsed_removed,
        "attachment_rows_removed": attachment_removed,
        "analysis_results_removed": analysis_removed,
        "file_removed": file_removed,
        "pending_cleanup": not file_removed,
    }


# ---------------------------------------------------------------------------
# Startup recovery — idempotent, before the server accepts requests.
# ---------------------------------------------------------------------------


def _remove_stale_temps(pending: Path, cutoff_ts: float) -> None:
    """Remove old regular files in ``.pending`` without following symlinks."""
    if not pending.is_dir():
        return
    for entry in pending.iterdir():
        try:
            info = entry.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_mtime < cutoff_ts:
                entry.unlink()
        except OSError:
            logger.warning("could not remove stale temporary file")


async def run_startup_recovery(
    settings: Settings, store: EvidenceStore, session_factory: SessionFactory
) -> None:
    """Finish interrupted deletions, repair stale parses, remove stale temps."""
    cutoff = _now() - STALE_AFTER

    async with session_factory() as session, session.begin():
        rows = await session.execute(
            select(EmailEvidence).where(EmailEvidence.status == STATUS_DELETED)
        )
        for evidence in rows.scalars():
            try:
                store.delete(evidence.storage_id)
            except EvidenceError:
                logger.warning("startup cleanup could not unlink %s", evidence.storage_id)

        await session.execute(
            update(EmailEvidence)
            .where(
                EmailEvidence.status == STATUS_PARSING,
                EmailEvidence.updated_at < cutoff,
            )
            .values(
                status=STATUS_PARSE_FAILED,
                failure_reason="process_interrupted",
                updated_at=func.now(),
            )
        )

    pending: Path = store.root / ".pending"
    await asyncio.to_thread(_remove_stale_temps, pending, cutoff.timestamp())
