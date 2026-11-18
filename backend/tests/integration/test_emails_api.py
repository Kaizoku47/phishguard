"""Integration tests for Milestone 2.3.4 authenticated ingestion and deletion.

These tests use only the isolated PHISHGUARD test database on 127.0.0.1:5434.
They never touch native PostgreSQL 5432, the other container on 5433, Redis,
Docker resources, or any other project's data.
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from app.core.config import SYNTHETIC_TEST_TOKEN, Settings, get_settings
from app.db.session import create_engine, create_session_factory, dispose_engine
from app.db.target import validate_test_target
from app.main import create_app
from app.models import AuditEvent, EmailAttachment, EmailEvidence, ParsedEmail
from app.models.email_evidence import STATUS_PARSE_FAILED
from app.services.evidence import EvidenceStore
from app.services.ingestion import run_startup_recovery
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import create_async_engine

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).parent.parent / "fixtures" / "eml"


def _settings(tmp_path: Path) -> Settings:
    base = get_settings()
    root = tmp_path / "evidence"
    return base.model_copy(
        update={
            "api_token": SecretStr(SYNTHETIC_TEST_TOKEN),
            "evidence_root": root,
            "database_url": base.database_url_test,
            "postgres_db": base.postgres_test_db,
            "max_upload_bytes": 10 * 1024 * 1024,
        }
    )


@pytest.fixture
def api_settings(tmp_path: Path) -> Settings:
    return _settings(tmp_path)


async def _truncate(url: str) -> None:
    validate_test_target(url)
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
def clean_api_db(api_settings: Settings) -> None:
    asyncio.run(_truncate(api_settings.database_url_test))


@pytest.fixture
def api_client(api_settings: Settings, monkeypatch: pytest.MonkeyPatch):
    async def _noop_recovery(*args: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr("app.main.run_startup_recovery", _noop_recovery)
    with TestClient(create_app(api_settings)) as client:
        yield client


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {SYNTHETIC_TEST_TOKEN}",
        "Content-Type": "message/rfc822",
    }


async def _scalar(api_settings: Settings, statement: Any) -> Any:
    engine = create_async_engine(api_settings.database_url_test, pool_pre_ping=True)
    try:
        async with engine.connect() as connection:
            result = await connection.execute(statement)
            return result.scalar()
    finally:
        await engine.dispose()


async def _rows(api_settings: Settings, statement: Any) -> list[Any]:
    engine = create_async_engine(api_settings.database_url_test, pool_pre_ping=True)
    factory = create_session_factory(engine)
    try:
        async with factory() as session:
            result = await session.execute(statement)
            return list(result.scalars())
    finally:
        await engine.dispose()


def _count(api_settings: Settings, model: Any) -> int:
    return int(asyncio.run(_scalar(api_settings, select(func.count()).select_from(model))))


def _latest_evidence(api_settings: Settings) -> EmailEvidence:
    rows = asyncio.run(
        _rows(
            api_settings,
            select(EmailEvidence).order_by(EmailEvidence.received_at.desc()).limit(1),
        )
    )
    assert rows
    return rows[0]


def _upload(client: TestClient, name: str) -> dict[str, Any]:
    response = client.post(
        "/api/v1/emails", content=(FIXTURES / name).read_bytes(), headers=_headers()
    )
    assert response.status_code == 201
    return response.json()


def test_successful_ingestion_persists_evidence_and_parsed_rows(
    api_client: TestClient, api_settings: Settings, clean_api_db: None
) -> None:
    raw = (FIXTURES / "simple_plain.eml").read_bytes()
    body = _upload(api_client, "simple_plain.eml")

    assert body["status"] == "parsed"
    assert body["sha256"] == hashlib.sha256(raw).hexdigest()
    assert body["size_bytes"] == len(raw)
    assert "storage_id" not in body
    assert _count(api_settings, EmailEvidence) == 1
    assert _count(api_settings, ParsedEmail) == 1
    assert _count(api_settings, AuditEvent) >= 1

    evidence = _latest_evidence(api_settings)
    assert evidence.sha256 == body["sha256"]
    store = EvidenceStore(api_settings.evidence_root, api_settings.max_upload_bytes)
    assert store.read(evidence.storage_id) == raw


def test_metadata_and_attachment_endpoints_return_untrusted_values_as_data(
    api_client: TestClient, api_settings: Settings, clean_api_db: None
) -> None:
    body = _upload(api_client, "simple_plain.eml")
    metadata = api_client.get(f"/api/v1/emails/{body['id']}/metadata", headers=_headers())
    attachments = api_client.get(f"/api/v1/emails/{body['id']}/attachments", headers=_headers())

    assert metadata.status_code == 200
    assert metadata.json()["subject"] == "Plain message"
    assert metadata.json()["from_address"] == "alice@example.com"
    assert "text_body" not in metadata.json()
    assert attachments.status_code == 200
    assert attachments.json() == {"items": []}


def test_attachment_metadata_is_returned_without_bytes(
    api_client: TestClient, api_settings: Settings, clean_api_db: None
) -> None:
    body = _upload(api_client, "multipart_mixed_attachments.eml")
    response = api_client.get(f"/api/v1/emails/{body['id']}/attachments", headers=_headers())

    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["category"] == "attachment"
    assert items[0]["filename"] == "report.pdf"
    assert items[0]["sha256"] == hashlib.sha256(b"%PDF-1.4\n").hexdigest()


def test_integrity_endpoint_reports_verified_and_detects_modification(
    api_client: TestClient, api_settings: Settings, clean_api_db: None
) -> None:
    body = _upload(api_client, "simple_plain.eml")
    endpoint = f"/api/v1/emails/{body['id']}/integrity"

    first = api_client.get(endpoint, headers=_headers())
    assert first.status_code == 200
    assert first.json() == {"evidence_present": True, "verified": True}

    evidence = _latest_evidence(api_settings)
    store = EvidenceStore(api_settings.evidence_root, api_settings.max_upload_bytes)
    path = store.root / evidence.storage_id
    data = bytearray(path.read_bytes())
    data[0] ^= 0xFF
    path.write_bytes(data)

    second = api_client.get(endpoint, headers=_headers())
    assert second.status_code == 200
    assert second.json() == {"evidence_present": True, "verified": False}
    assert _count(api_settings, AuditEvent) >= 2


def test_deletion_tombstones_and_removes_file(
    api_client: TestClient, api_settings: Settings, clean_api_db: None
) -> None:
    body = _upload(api_client, "multipart_mixed_attachments.eml")
    evidence = _latest_evidence(api_settings)
    store = EvidenceStore(api_settings.evidence_root, api_settings.max_upload_bytes)
    path = store.root / evidence.storage_id
    assert path.exists()

    response = api_client.delete(f"/api/v1/emails/{body['id']}", headers=_headers())

    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "deleted"
    assert result["parsed_rows_removed"] == 1
    assert result["attachment_rows_removed"] == 1
    assert result["file_removed"] is True
    assert result["pending_cleanup"] is False
    assert not path.exists()
    assert _count(api_settings, ParsedEmail) == 0
    assert _count(api_settings, EmailAttachment) == 0

    tombstone = _latest_evidence(api_settings)
    assert tombstone.status == "deleted"
    assert tombstone.deleted_at is not None
    assert tombstone.original_filename is None
    assert tombstone.sha256 == body["sha256"]
    assert _count(api_settings, AuditEvent) >= 2

    status = api_client.get(f"/api/v1/emails/{body['id']}", headers=_headers())
    assert status.status_code == 200
    assert status.json()["status"] == "deleted"


def test_malformed_email_is_accepted_and_marked_parse_failed(
    api_client: TestClient, api_settings: Settings, clean_api_db: None
) -> None:
    response = api_client.post("/api/v1/emails", content=b"not an email at all", headers=_headers())

    assert response.status_code == 201
    assert response.json()["status"] == "parse_failed"
    assert _count(api_settings, EmailEvidence) == 1
    assert _latest_evidence(api_settings).status == STATUS_PARSE_FAILED


def test_parser_reads_the_published_evidence_file(
    api_client: TestClient,
    api_settings: Settings,
    clean_api_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import ingestion as ingestion_module

    original = ingestion_module.parse_published_evidence
    captured: dict[str, bytes] = {}

    def spy(store, storage_id, settings):
        result = original(store, storage_id, settings)
        captured["raw"] = store.read(storage_id)
        return result

    monkeypatch.setattr(ingestion_module, "parse_published_evidence", spy)
    raw = (FIXTURES / "simple_plain.eml").read_bytes()

    body = _upload(api_client, "simple_plain.eml")

    assert body["status"] == "parsed"
    assert captured["raw"] == raw


def test_tx1_failure_retains_published_file(
    api_client: TestClient,
    api_settings: Settings,
    clean_api_db: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.exceptions import EvidenceStorageError
    from app.services import ingestion as ingestion_module

    async def fail(*args: object, **kwargs: object) -> None:
        raise EvidenceStorageError

    monkeypatch.setattr(ingestion_module, "create_evidence_record", fail)

    response = api_client.post(
        "/api/v1/emails",
        content=b"From: a@example.test\r\nSubject: x\r\n\r\nbody",
        headers=_headers(),
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable."}
    store = EvidenceStore(api_settings.evidence_root, api_settings.max_upload_bytes)
    assert list(store.root.rglob("*.eml"))
    assert _count(api_settings, EmailEvidence) == 0


def test_tx1_definite_commit_failure_is_logged_distinctly_and_retains_file(
    api_client: TestClient,
    api_settings: Settings,
    clean_api_db: None,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """T-64 definite failure: commit was rejected before an uncertain outcome."""
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm.session import SessionTransaction

    error = IntegrityError("INSERT", None, Exception("simulated definite failure"))

    def fail_commit(self: SessionTransaction) -> None:
        raise error

    def forbidden_delete(*args: object, **kwargs: object) -> None:
        raise AssertionError("ingestion path attempted to unlink published evidence")

    monkeypatch.setattr(SessionTransaction, "commit", fail_commit)
    monkeypatch.setattr(EvidenceStore, "delete", forbidden_delete)

    response = api_client.post(
        "/api/v1/emails",
        content=b"From: a@example.test\r\nSubject: x\r\n\r\nbody",
        headers=_headers(),
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable."}
    assert "TX-1 failure (uncertain=False)" in caplog.text
    assert "uncertain=True" not in caplog.text

    store = EvidenceStore(api_settings.evidence_root, api_settings.max_upload_bytes)
    assert list(store.root.rglob("*.eml"))


def test_tx1_uncertain_commit_outcome_retains_file_and_is_logged_distinctly(
    api_client: TestClient,
    api_settings: Settings,
    clean_api_db: None,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """T-64 uncertain outcome: connection lost after COMMIT was sent.

    The test deliberately does not assert whether the row exists. Only the
    response, the retained file, and the distinct uncertain log are asserted.
    """
    from sqlalchemy.exc import InterfaceError
    from sqlalchemy.orm.session import SessionTransaction

    error = InterfaceError("COMMIT", None, Exception("connection lost after COMMIT"))
    error.connection_invalidated = True
    commit_attempted: list[bool] = []

    def fail_commit(self: SessionTransaction) -> None:
        commit_attempted.append(True)
        raise error

    def forbidden_delete(*args: object, **kwargs: object) -> None:
        raise AssertionError("ingestion path attempted to unlink published evidence")

    monkeypatch.setattr(SessionTransaction, "commit", fail_commit)
    monkeypatch.setattr(EvidenceStore, "delete", forbidden_delete)

    response = api_client.post(
        "/api/v1/emails",
        content=b"From: a@example.test\r\nSubject: uncertain\r\n\r\nbody",
        headers=_headers(),
    )

    assert commit_attempted
    assert response.status_code == 503
    assert response.json() == {"detail": "Service temporarily unavailable."}
    assert "uncertain=True" in caplog.text
    assert "sha256=" in caplog.text

    store = EvidenceStore(api_settings.evidence_root, api_settings.max_upload_bytes)
    assert list(store.root.rglob("*.eml"))


def test_missing_resource_returns_generic_404(api_client: TestClient, clean_api_db: None) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    response = api_client.get(f"/api/v1/emails/{missing}", headers=_headers())

    assert response.status_code == 404
    assert response.json() == {"detail": "Not found."}


def test_parse_and_delete_race_never_leaves_parsed_content(
    api_settings: Settings, clean_api_db: None
) -> None:
    from app.services.email import parse_email
    from app.services.ingestion import delete_evidence, persist_parse

    engine = create_engine(api_settings)
    factory = create_session_factory(engine)
    result = parse_email((FIXTURES / "simple_plain.eml").read_bytes())

    async def seed() -> Any:
        async with factory() as session, session.begin():
            evidence = EmailEvidence(
                sha256="b" * 64,
                size_bytes=4,
                storage_id="dd/ee/" + "d" * 32 + ".eml",
                status="parsing",
            )
            session.add(evidence)
            await session.flush()
            return evidence.id

    async def race(evidence_id: Any) -> None:
        await asyncio.gather(
            persist_parse(factory, evidence_id, result),
            delete_evidence(
                evidence_id,
                EvidenceStore(api_settings.evidence_root, api_settings.max_upload_bytes),
                factory,
            ),
        )

    async def run() -> Any:
        evidence_id = await seed()
        await race(evidence_id)
        await dispose_engine(engine)
        return evidence_id

    evidence_id = asyncio.run(run())

    assert _count(api_settings, ParsedEmail) == 0
    assert _count(api_settings, EmailAttachment) == 0
    deleted = asyncio.run(
        _scalar(
            api_settings,
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.email_evidence_id == evidence_id, AuditEvent.event_type == "deleted"),
        )
    )
    assert int(deleted or 0) == 1


def test_startup_recovery_repairs_stale_parse_and_preserves_orphans(
    api_settings: Settings, clean_api_db: None
) -> None:
    cutoff = datetime.now(UTC) - timedelta(hours=2)
    store = EvidenceStore(api_settings.evidence_root, api_settings.max_upload_bytes)
    engine = create_engine(api_settings)
    factory = create_session_factory(engine)

    async def seed() -> None:
        async with factory() as session, session.begin():
            session.add(
                EmailEvidence(
                    sha256="a" * 64,
                    size_bytes=4,
                    storage_id="aa/bb/" + "a" * 32 + ".eml",
                    status="parsing",
                    updated_at=cutoff,
                )
            )

    orphan = store.root / "cc" / "dd" / ("c" * 32 + ".eml")
    orphan.parent.mkdir(parents=True, exist_ok=True)
    orphan.write_bytes(b"orphan")

    async def seed_and_recover() -> None:
        await seed()
        await run_startup_recovery(api_settings, store, factory)
        await dispose_engine(engine)

    asyncio.run(seed_and_recover())

    rows = asyncio.run(
        _rows(
            api_settings, select(EmailEvidence).where(EmailEvidence.status == STATUS_PARSE_FAILED)
        )
    )
    assert len(rows) == 1
    assert rows[0].failure_reason == "process_interrupted"
    assert orphan.exists()

    orphan.unlink()
