"""Report endpoint A10.

The report exposes only stored deterministic results and supplementary
narrative state. No raw body, attachment bytes, path or storage id is returned.
"""

from __future__ import annotations

from datetime import UTC
from typing import Any
from uuid import UUID

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import select

from app.api.dependencies import AuthDep, SessionFactoryDep
from app.core.exceptions import AnalysisNotPerformedError, NotFoundError
from app.models import AnalysisResult
from app.models.email_evidence import STATUS_DELETED
from app.services.analysis.signals import missing_evidence as build_missing_evidence
from app.services.ingestion import get_evidence

router = APIRouter()


class SignalSchema(BaseModel):
    id: str
    severity: str
    contribution: int
    reason: str
    evaluated: bool


class MissingEvidenceSchema(BaseModel):
    target: str
    reason: str


class ReputationEntrySchema(BaseModel):
    """One validated OTX-derived reputation entry.

    Only the three fields produced by ``intel._extract_minimal_fields`` are
    accepted. Unknown fields are refused so a stale or tampered JSONB value
    cannot be serialized into the report unchecked.
    """

    model_config = ConfigDict(extra="forbid")

    provider: str | None = None
    reputation: int | float | None = None
    pulse_count: int | None = None


class IntelligenceSchema(BaseModel):
    domains: dict[str, ReputationEntrySchema] = {}
    hashes: dict[str, ReputationEntrySchema] = {}
    missing: list[MissingEvidenceSchema] = []


class ReportResponse(BaseModel):
    email_id: UUID
    score: int
    risk_band: str
    signals: list[SignalSchema]
    missing_evidence: list[MissingEvidenceSchema]
    intelligence: IntelligenceSchema
    narrative: str | None
    narrative_status: str
    narrative_reason: str | None
    engine_version: str
    created_at: str


def _reputation_entries(value: Any) -> dict[str, ReputationEntrySchema]:
    """Validate nested reputation values before they reach the response model."""
    if not isinstance(value, dict):
        return {}
    entries: dict[str, ReputationEntrySchema] = {}
    for key, item in value.items():
        try:
            entries[str(key)] = ReputationEntrySchema.model_validate(item)
        except ValidationError:
            continue
    return entries


def _missing_entries(value: Any) -> list[MissingEvidenceSchema]:
    """Keep only well-formed missing-evidence records; never coerce arbitrary values."""
    if not isinstance(value, list):
        return []
    result: list[MissingEvidenceSchema] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        target, reason = item.get("target"), item.get("reason")
        if isinstance(target, str) and isinstance(reason, str):
            result.append(MissingEvidenceSchema(target=target, reason=reason[:200]))
    return result


def _iso(value: Any) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@router.get("/emails/{email_id}/report", response_model=ReportResponse)
async def email_report(
    email_id: UUID,
    _: AuthDep,
    session_factory: SessionFactoryDep,
) -> ReportResponse:
    evidence = await get_evidence(email_id, session_factory)
    if evidence.status == STATUS_DELETED:
        raise NotFoundError

    async with session_factory() as session:
        analysis = await session.scalar(
            select(AnalysisResult).where(AnalysisResult.email_evidence_id == email_id)
        )
    if analysis is None:
        raise AnalysisNotPerformedError

    signals = [SignalSchema(**item) for item in (analysis.signals or [])]
    intel = analysis.intelligence_results or {}
    # Reuse the deterministic signal layer's contract: the authentication
    # target and its reason are defined there, not duplicated in the API.
    missing_evidence = [MissingEvidenceSchema(**item) for item in build_missing_evidence(signals)]
    return ReportResponse(
        email_id=email_id,
        score=analysis.score,
        risk_band=analysis.risk_band,
        signals=signals,
        missing_evidence=missing_evidence,
        intelligence=IntelligenceSchema(
            domains=_reputation_entries(intel.get("domains")),
            hashes=_reputation_entries(intel.get("hashes")),
            missing=_missing_entries(intel.get("missing")),
        ),
        narrative=analysis.narrative,
        narrative_status=analysis.narrative_status,
        narrative_reason=analysis.narrative_reason,
        engine_version=analysis.engine_version,
        created_at=_iso(analysis.created_at),
    )
