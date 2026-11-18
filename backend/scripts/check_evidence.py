#!/usr/bin/env python
"""Report evidence/database consistency; optionally perform offline repair.

Run from ``backend/``:

    .venv/bin/python scripts/check_evidence.py
    .venv/bin/python scripts/check_evidence.py --repair --confirm-stopped

The default mode is read-only. ``--repair`` may only finish tombstoned-file
cleanup, remove stale temporary files and repair stale ``parsing`` rows. It
never deletes or re-registers orphan files.

``--repair`` requires the PHISHGUARD application to be stopped first, because
the repair assumes no upload or parse is in flight.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import Settings, get_settings  # noqa: E402
from app.db.session import create_engine, create_session_factory, dispose_engine  # noqa: E402
from app.models import EmailEvidence  # noqa: E402
from app.models.email_evidence import STATUS_DELETED, STATUS_PARSING  # noqa: E402
from app.services.evidence import EvidenceStore  # noqa: E402
from app.services.ingestion import run_startup_recovery  # noqa: E402
from sqlalchemy import select  # noqa: E402


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def _evidence_files(root: Path) -> list[tuple[str, Path]]:
    """Return regular evidence files as (storage_id, path)."""
    if not root.is_dir():
        return []
    results: list[tuple[str, Path]] = []
    for path in root.rglob("*"):
        try:
            info = path.lstat()
        except OSError:
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == ".pending":
            continue
        results.append((relative.as_posix(), path))
    return results


async def _report(settings: Settings, store: EvidenceStore) -> int:
    engine = create_engine(settings)
    factory = create_session_factory(engine)
    try:
        async with factory() as session:
            rows = await session.execute(select(EmailEvidence))
            evidence = rows.scalars().all()
    finally:
        await dispose_engine(engine)

    registered = {item.storage_id: item for item in evidence}
    files = _evidence_files(store.root)
    present = dict(files)

    orphans = sorted(set(present) - set(registered))
    missing = sorted(set(registered) - set(present))
    pending = sorted(item.storage_id for item in evidence if item.status == STATUS_DELETED)
    stuck = sorted(item.storage_id for item in evidence if item.status == STATUS_PARSING)

    print(f"evidence root : {store.root}")
    print(f"registered evidence : {len(registered)}")
    print(f"files present       : {len(present)}")
    print(f"orphan files        : {len(orphans)}")
    for storage_id in orphans:
        path = present[storage_id]
        print(f"  {storage_id}  {path.stat().st_size} bytes  sha256 {_digest(path)}")
        print("    -> no registered row; NEVER removed automatically")

    print(f"missing files       : {len(missing)}")
    for storage_id in missing:
        item = registered[storage_id]
        print(f"  {storage_id}  sha256 {item.sha256}")

    print(f"pending deletions   : {len(pending)}")
    for storage_id in pending:
        print(f"  {storage_id}")

    print(f"stuck parses        : {len(stuck)}")
    for storage_id in stuck:
        print(f"  {storage_id}")
    return 0


async def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repair", action="store_true", help="perform offline repair")
    parser.add_argument(
        "--confirm-stopped",
        action="store_true",
        help="confirm the application is stopped before --repair",
    )
    args = parser.parse_args(argv)

    if args.repair and not args.confirm_stopped:
        print("--repair requires --confirm-stopped; stop the application first")
        return 2

    try:
        settings = get_settings()
    except Exception as exc:  # configuration errors are reported without details
        print(f"configuration error: {type(exc).__name__}")
        return 1

    store = EvidenceStore(settings.evidence_root, settings.max_upload_bytes)
    code = await _report(settings, store)
    if code != 0:
        return code

    if args.repair:
        print("repair requires the application to be stopped")
        engine = create_engine(settings)
        factory = create_session_factory(engine)
        try:
            await run_startup_recovery(settings, store, factory)
        finally:
            await dispose_engine(engine)
        print("offline repair complete")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
