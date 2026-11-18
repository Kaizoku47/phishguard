"""Authenticated email endpoints A4-A9.

No raw body, attachment bytes, filesystem path or storage id is ever returned.
The report endpoint A10 belongs to Milestone 2.3.7 and is deliberately absent.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Request
from pydantic import BaseModel

from app.api.dependencies import AuthDep, SessionFactoryDep, SettingsDep
from app.core.exceptions import UnsupportedMediaTypeError
from app.services.evidence import EvidenceStore
from app.services.ingestion import (
    delete_evidence,
    get_attachments,
    get_metadata,
    get_status,
    ingest_message,
    verify_integrity,
)

router = APIRouter()


class UploadResponse(BaseModel):
    id: UUID
    status: str
    parse_status: str
    size_bytes: int
    sha256: str
    received_at: str | None = None


class EmailStatusResponse(BaseModel):
    id: UUID
    status: str
    size_bytes: int
    sha256: str
    received_at: str | None = None
    parser_version: str | None = None
    defect_count: int | None = None
    limit_exceeded: str | None = None
    failure_reason: str | None = None
    deleted_at: str | None = None


class ParsedMetadataResponse(BaseModel):
    subject: str | None = None
    from_address: str | None = None
    from_display_name: str | None = None
    to_addresses: list[str] | None = None
    cc_addresses: list[str] | None = None
    reply_to_addresses: list[str] | None = None
    date_header: str | None = None
    date_parsed: str | None = None
    message_id: str | None = None
    headers: dict[str, list[str]] | None = None
    body_charset: str | None = None
    links: list[dict[str, Any]] | None = None
    multipart: bool = False
    part_count: int = 0
    max_depth: int = 0
    defect_count: int = 0
    defect_types: list[str] | None = None
    parser_version: str | None = None


class AttachmentItem(BaseModel):
    part_index: int
    category: str
    filename: str | None = None
    declared_content_type: str | None = None
    detected_content_type: str | None = None
    content_disposition: str | None = None
    content_transfer_encoding: str | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    decode_ok: bool


class AttachmentListResponse(BaseModel):
    items: list[AttachmentItem]


class IntegrityResponse(BaseModel):
    evidence_present: bool
    verified: bool | None = None


class DeleteResponse(BaseModel):
    id: UUID
    status: str
    parsed_rows_removed: int
    attachment_rows_removed: int
    analysis_results_removed: int
    file_removed: bool
    pending_cleanup: bool


def _content_type_is_valid(value: str | None) -> bool:
    """Accept a missing Content-Type or exactly message/rfc822 with parameters."""
    if value is None:
        return True
    return value.split(";", 1)[0].strip().lower() == "message/rfc822"


def _store(settings: Any) -> EvidenceStore:
    return EvidenceStore(settings.evidence_root, settings.max_upload_bytes)


@router.post("/emails", response_model=UploadResponse, status_code=201)
async def upload_email(
    request: Request,
    _: AuthDep,
    settings: SettingsDep,
    session_factory: SessionFactoryDep,
) -> UploadResponse:
    if not _content_type_is_valid(request.headers.get("content-type")):
        raise UnsupportedMediaTypeError
    result = await ingest_message(
        request.stream(),
        request.headers.get("content-type"),
        settings,
        _store(settings),
        session_factory,
        request.app.state.upload_semaphore,
    )
    return UploadResponse(**result)


@router.get("/emails/{email_id}", response_model=EmailStatusResponse)
async def email_status(
    email_id: UUID,
    _: AuthDep,
    session_factory: SessionFactoryDep,
) -> EmailStatusResponse:
    return EmailStatusResponse(**await get_status(email_id, session_factory))


@router.get("/emails/{email_id}/metadata", response_model=ParsedMetadataResponse)
async def email_metadata(
    email_id: UUID,
    _: AuthDep,
    session_factory: SessionFactoryDep,
) -> ParsedMetadataResponse:
    return ParsedMetadataResponse(**await get_metadata(email_id, session_factory))


@router.get("/emails/{email_id}/attachments", response_model=AttachmentListResponse)
async def email_attachments(
    email_id: UUID,
    _: AuthDep,
    session_factory: SessionFactoryDep,
) -> AttachmentListResponse:
    items = await get_attachments(email_id, session_factory)
    return AttachmentListResponse(items=[AttachmentItem(**item) for item in items])


@router.get("/emails/{email_id}/integrity", response_model=IntegrityResponse)
async def email_integrity(
    email_id: UUID,
    _: AuthDep,
    settings: SettingsDep,
    session_factory: SessionFactoryDep,
) -> IntegrityResponse:
    return IntegrityResponse(**await verify_integrity(email_id, _store(settings), session_factory))


@router.delete("/emails/{email_id}", response_model=DeleteResponse)
async def delete_email(
    email_id: UUID,
    _: AuthDep,
    settings: SettingsDep,
    session_factory: SessionFactoryDep,
) -> DeleteResponse:
    result = await delete_evidence(email_id, _store(settings), session_factory)
    return DeleteResponse(**result)
