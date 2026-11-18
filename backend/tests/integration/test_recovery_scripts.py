"""T-62, T-63 and T-67: operational recovery-script tests.

All tests use the isolated PHISHGUARD test database and a temporary evidence
directory. No real or shared evidence store is repaired.
"""

from __future__ import annotations

import importlib.util
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from app.core.config import SYNTHETIC_TEST_TOKEN, Settings, get_settings
from app.db.session import create_engine, create_session_factory, dispose_engine
from app.models import EmailEvidence
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine

pytestmark = pytest.mark.integration

SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "check_evidence.py"
_spec = importlib.util.spec_from_file_location("check_evidence_under_test", SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
script = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(script)

TOMBSTONE_STORAGE = "aa/bb/" + "a" * 32 + ".eml"
STALE_STORAGE = "cc/dd/" + "c" * 32 + ".eml"
ORPHAN_STORAGE = "ee/ff/" + "e" * 32 + ".eml"
STALE_TEMP_NAME = "stale.tmp"


def _settings(tmp_path: Path) -> Settings:
    base = get_settings()
    return base.model_copy(
        update={
            "api_token": SYNTHETIC_TEST_TOKEN,
            "evidence_root": tmp_path / "evidence",
            "database_url": base.database_url_test,
            "postgres_db": base.postgres_test_db,
        }
    )


@pytest.fixture
def script_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    settings = _settings(tmp_path)
    monkeypatch.setattr(script, "get_settings", lambda: settings)
    return settings


async def _truncate(url: str) -> None:
    engine = create_async_engine(url, pool_pre_ping=True)
    try:
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "TRUNCATE email_attachments, parsed_emails, analysis_results, "
                    "audit_events, email_evidence CASCADE"
                )
            )
    finally:
        await engine.dispose()


@pytest.fixture
def clean_script_db(script_settings: Settings) -> None:
    asyncio_run(_truncate(script_settings.database_url_test))


def asyncio_run(coro: Any) -> Any:
    import asyncio

    return asyncio.run(coro)


async def _seed(settings: Settings) -> dict[str, Path]:
    root = settings.evidence_root
    files: dict[str, Path] = {}
    for name, storage_id in (
        ("tombstone", TOMBSTONE_STORAGE),
        ("orphan", ORPHAN_STORAGE),
    ):
        path = root / storage_id
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"{name} evidence".encode())
        files[name] = path

    pending = root / ".pending"
    pending.mkdir(parents=True, exist_ok=True)
    stale_temp = pending / STALE_TEMP_NAME
    stale_temp.write_bytes(b"stale temp")
    old_ts = (datetime.now(UTC) - timedelta(hours=2)).timestamp()
    os.utime(stale_temp, (old_ts, old_ts))
    files["stale_temp"] = stale_temp

    engine = create_engine(settings)
    factory = create_session_factory(engine)
    try:
        async with factory() as session, session.begin():
            session.add(
                EmailEvidence(
                    sha256="a" * 64,
                    size_bytes=12,
                    storage_id=TOMBSTONE_STORAGE,
                    status="deleted",
                    deleted_at=datetime.now(UTC),
                )
            )
            session.add(
                EmailEvidence(
                    sha256="c" * 64,
                    size_bytes=12,
                    storage_id=STALE_STORAGE,
                    status="parsing",
                    updated_at=datetime.now(UTC) - timedelta(hours=2),
                )
            )
    finally:
        await dispose_engine(engine)
    return files


async def _statuses(settings: Settings, storage_id: str) -> list[Any]:
    engine = create_async_engine(settings.database_url_test, pool_pre_ping=True)
    try:
        async with engine.connect() as connection:
            result = await connection.execute(
                select(EmailEvidence.status, EmailEvidence.failure_reason).where(
                    EmailEvidence.storage_id == storage_id
                )
            )
            return list(result)
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_default_report_is_read_only(
    script_settings: Settings, clean_script_db: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-62: default execution changes nothing."""
    files = await _seed(script_settings)

    assert await script.main([]) == 0
    output = capsys.readouterr().out

    assert "orphan files" in output
    assert files["tombstone"].exists()
    assert files["orphan"].exists()
    assert files["stale_temp"].exists()
    statuses = await _statuses(script_settings, STALE_STORAGE)
    assert statuses and statuses[0][0] == "parsing"


@pytest.mark.asyncio
async def test_repair_requires_explicit_confirmation(
    script_settings: Settings, clean_script_db: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """T-63/T-67: --repair is refused without --confirm-stopped."""
    files = await _seed(script_settings)

    assert await script.main(["--repair"]) == 2
    assert "stopped" in capsys.readouterr().out
    assert files["tombstone"].exists()
    assert files["orphan"].exists()


@pytest.mark.asyncio
async def test_repair_cleans_only_eligible_items_and_is_idempotent(
    script_settings: Settings, clean_script_db: None
) -> None:
    """T-63: tombstoned files, stale parses and stale temps are repaired; orphans stay."""
    files = await _seed(script_settings)

    assert await script.main(["--repair", "--confirm-stopped"]) == 0

    assert not files["tombstone"].exists()
    assert files["orphan"].exists()
    assert not files["stale_temp"].exists()
    statuses = await _statuses(script_settings, STALE_STORAGE)
    assert statuses and statuses[0][0] == "parse_failed"
    assert statuses[0][1] == "process_interrupted"

    assert await script.main(["--repair", "--confirm-stopped"]) == 0
    assert files["orphan"].exists()


@pytest.mark.asyncio
async def test_help_and_documentation_state_offline_repair_and_read_only_default() -> None:
    """T-67: help text and docs state the offline requirement and safe report mode."""
    doc = (script.__doc__ or "").lower()
    assert "read-only" in doc and "default mode" in doc
    assert "stopped" in doc
    assert "orphan" in doc

    with pytest.raises(SystemExit) as exc:
        await script.main(["--help"])
    assert exc.value.code == 0


@pytest.mark.asyncio
async def test_repair_uses_same_row_lock_free_recovery_path(
    script_settings: Settings, clean_script_db: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Repair delegates to the documented idempotent startup recovery operation."""
    called: list[bool] = []
    original = script.run_startup_recovery

    async def spy(*args: object, **kwargs: object) -> None:
        called.append(True)
        await original(*args, **kwargs)

    monkeypatch.setattr(script, "run_startup_recovery", spy)
    await _seed(script_settings)

    assert await script.main(["--repair", "--confirm-stopped"]) == 0
    assert called
