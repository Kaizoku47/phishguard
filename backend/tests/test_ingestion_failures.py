"""Failure-injection tests for ingestion evidence-retention guarantees.

These are unit tests: no database is contacted. They prove that the ingestion
path never unlinks a published evidence file, and that pre-publication failures
leave no temporary or published file behind.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from app.core.config import SYNTHETIC_TEST_TOKEN, Settings
from app.core.exceptions import EvidenceStorageError
from app.services import ingestion as ingestion_module
from app.services.evidence import EvidenceStore, EvidenceWriter
from app.services.evidence.store import EvidenceError


def _settings(root: Path) -> Settings:
    return Settings(
        _env_file=None,
        PHISHGUARD_SECRET_KEY="test-secret-key-value",
        PHISHGUARD_API_TOKEN=SYNTHETIC_TEST_TOKEN,
        PHISHGUARD_EVIDENCE_ROOT=str(root),
    )


async def _chunks(*values: bytes) -> AsyncIterator[bytes]:
    for value in values:
        yield value


def _published_files(store: EvidenceStore) -> list[Path]:
    if not store.root.exists():
        return []
    return [
        path for path in store.root.rglob("*") if path.is_file() and ".pending" not in path.parts
    ]


def _pending_files(store: EvidenceStore) -> list[Path]:
    pending = store.root / ".pending"
    if not pending.exists():
        return []
    return list(pending.iterdir())


@pytest.mark.asyncio
async def test_storage_failure_before_publication_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-65: a failed publish leaves no temporary or published evidence."""
    settings = _settings(tmp_path / "evidence")
    store = EvidenceStore(settings.evidence_root, settings.max_upload_bytes)

    def fail_write(self: EvidenceWriter, chunk: bytes) -> None:
        self.abort()
        raise EvidenceError("simulated storage failure")

    monkeypatch.setattr(EvidenceWriter, "write", fail_write)

    with pytest.raises(EvidenceStorageError):
        await ingestion_module.receive_and_publish(_chunks(b"subject: x\r\n\r\nbody"), store)

    assert _pending_files(store) == []
    assert _published_files(store) == []


@pytest.mark.asyncio
async def test_post_publication_parse_failure_never_unlinks_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-68: a parse failure cannot trigger evidence unlink."""
    settings = _settings(tmp_path / "evidence")
    store = EvidenceStore(settings.evidence_root, settings.max_upload_bytes)

    async def fake_evidence(*args: object, **kwargs: object) -> tuple[object, datetime]:
        return uuid4(), datetime.now(UTC)

    def fail_parse(*args: object, **kwargs: object) -> None:
        raise EvidenceStorageError

    def forbidden_delete(*args: object, **kwargs: object) -> None:
        raise AssertionError("ingestion path attempted to unlink published evidence")

    monkeypatch.setattr(ingestion_module, "create_evidence_record", fake_evidence)
    monkeypatch.setattr(ingestion_module, "parse_published_evidence", fail_parse)
    monkeypatch.setattr(EvidenceStore, "delete", forbidden_delete)

    with pytest.raises(EvidenceStorageError):
        await ingestion_module.ingest_message(
            _chunks(b"From: a@example.test\r\nSubject: x\r\n\r\nbody"),
            "message/rfc822",
            settings,
            store,
            object(),
        )

    assert len(_published_files(store)) == 1


@pytest.mark.asyncio
async def test_post_publication_tx2_failure_never_unlinks_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """T-68: a TX-2 failure cannot trigger evidence unlink."""
    settings = _settings(tmp_path / "evidence")
    store = EvidenceStore(settings.evidence_root, settings.max_upload_bytes)

    async def fake_evidence(*args: object, **kwargs: object) -> tuple[object, datetime]:
        return uuid4(), datetime.now(UTC)

    async def fail_persist(*args: object, **kwargs: object) -> None:
        raise RuntimeError("simulated TX-2 failure")

    def forbidden_delete(*args: object, **kwargs: object) -> None:
        raise AssertionError("ingestion path attempted to unlink published evidence")

    monkeypatch.setattr(ingestion_module, "create_evidence_record", fake_evidence)
    monkeypatch.setattr(ingestion_module, "persist_parse", fail_persist)
    monkeypatch.setattr(EvidenceStore, "delete", forbidden_delete)

    with pytest.raises(RuntimeError, match="simulated TX-2 failure"):
        await ingestion_module.ingest_message(
            _chunks(b"From: a@example.test\r\nSubject: x\r\n\r\nbody"),
            "message/rfc822",
            settings,
            store,
            object(),
        )

    assert len(_published_files(store)) == 1
