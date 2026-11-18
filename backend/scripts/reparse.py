#!/usr/bin/env python
"""Reparse an existing registered evidence record from its stored file.

Run from ``backend/``:

    .venv/bin/python scripts/reparse.py <storage-id>

The storage id is the opaque relative path recorded in ``email_evidence``.
This script never registers an orphan file and never prints message content.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import Settings, get_settings  # noqa: E402
from app.db.session import create_engine, create_session_factory, dispose_engine  # noqa: E402
from app.models import AuditEvent, EmailEvidence  # noqa: E402
from app.models.audit_event import EVENT_REPARSE_COMPLETED  # noqa: E402
from app.services.evidence import EvidenceStore  # noqa: E402
from app.services.ingestion import parse_published_evidence, persist_parse  # noqa: E402
from sqlalchemy import select  # noqa: E402


async def _reparse(settings: Settings, storage_id: str) -> int:
    engine = create_engine(settings)
    factory = create_session_factory(engine)
    store = EvidenceStore(settings.evidence_root, settings.max_upload_bytes)
    try:
        async with factory() as session:
            row = await session.execute(
                select(EmailEvidence).where(EmailEvidence.storage_id == storage_id)
            )
            evidence = row.scalar_one_or_none()
        if evidence is None:
            print("no registered evidence for that storage id; orphans are never re-registered")
            return 1

        result = parse_published_evidence(store, storage_id, settings)
        status = await persist_parse(factory, evidence.id, result)

        async with factory() as session, session.begin():
            session.add(
                AuditEvent(
                    event_type=EVENT_REPARSE_COMPLETED,
                    email_evidence_id=evidence.id,
                    detail={
                        "status": status,
                        "parser_version": result.parser_version,
                        "defect_count": result.defect_count,
                    },
                )
            )
        print(f"reparse complete: id={evidence.id} status={status}")
        return 0
    finally:
        await dispose_engine(engine)


async def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("storage_id", help="opaque storage id from email_evidence")
    args = parser.parse_args(argv)
    try:
        settings = get_settings()
    except Exception as exc:
        print(f"configuration error: {type(exc).__name__}")
        return 1
    return await _reparse(settings, args.storage_id)


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
