"""Schema tests for the Milestone 2.3.1 domain models.

These are unit tests: they import the models and inspect the SQLAlchemy
metadata. No database is involved, so they run everywhere and they fail
immediately if a column, a constraint or an index drifts away from the
approved architecture.

The database-level behaviour - that the constraints are actually enforced by
PostgreSQL - is covered by the integration tests.
"""

from __future__ import annotations

import uuid

from app.models import (
    AnalysisResult,
    AuditEvent,
    Base,
    EmailAttachment,
    EmailEvidence,
    ParsedEmail,
)

EXPECTED_TABLES = {
    "analysis_results",
    "audit_events",
    "email_attachments",
    "email_evidence",
    "parsed_emails",
}

EXPECTED_MODELS = {
    "analysis_results": AnalysisResult,
    "audit_events": AuditEvent,
    "email_attachments": EmailAttachment,
    "email_evidence": EmailEvidence,
    "parsed_emails": ParsedEmail,
}


def _table(model: type) -> object:
    return model.__table__


def test_every_model_is_registered_on_the_shared_metadata() -> None:
    """Importing the package must register all five tables.

    Alembic imports the package rather than the base module. If a model is
    not registered, --autogenerate silently produces an empty migration.
    """
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_every_table_has_the_expected_model_class() -> None:
    for name, model in EXPECTED_MODELS.items():
        assert model.__tablename__ == name
        assert _table(model) is Base.metadata.tables[name]


def test_every_table_has_an_uuid_primary_key() -> None:
    """The primary key is a UUID, and it renders as UUID on PostgreSQL."""
    from sqlalchemy import Uuid
    from sqlalchemy.dialects import postgresql
    from sqlalchemy.schema import CreateTable

    for name, model in EXPECTED_MODELS.items():
        primary_key = list(_table(model).primary_key.columns)
        assert len(primary_key) == 1, name
        assert primary_key[0].name == "id", name
        assert isinstance(primary_key[0].type, Uuid), name
        ddl = str(CreateTable(_table(model)).compile(dialect=postgresql.dialect()))
        assert "id UUID" in ddl, name


def test_email_evidence_columns() -> None:
    columns = EmailEvidence.__table__.columns
    assert set(columns.keys()) == {
        "id",
        "received_at",
        "updated_at",
        "sha256",
        "size_bytes",
        "storage_id",
        "original_filename",
        "declared_content_type",
        "status",
        "parser_version",
        "defect_count",
        "limit_exceeded",
        "failure_reason",
        "deleted_at",
    }
    assert columns["sha256"].nullable is False
    assert columns["size_bytes"].nullable is False
    assert columns["storage_id"].nullable is False
    assert columns["status"].nullable is False
    assert columns["original_filename"].nullable is True
    assert columns["declared_content_type"].nullable is True
    assert columns["parser_version"].nullable is True
    assert columns["defect_count"].nullable is True
    assert columns["limit_exceeded"].nullable is True
    assert columns["failure_reason"].nullable is True
    assert columns["deleted_at"].nullable is True
    assert "CHAR" in str(columns["sha256"].type).upper()


def test_email_evidence_timestamp_defaults() -> None:
    columns = EmailEvidence.__table__.columns
    for name in ("received_at", "updated_at"):
        default = columns[name].server_default
        assert default is not None, name
        assert "now()" in str(default.arg), name


def test_parsed_emails_columns() -> None:
    columns = ParsedEmail.__table__.columns
    assert set(columns.keys()) == {
        "id",
        "email_evidence_id",
        "created_at",
        "parser_version",
        "subject",
        "from_address",
        "from_display_name",
        "to_addresses",
        "cc_addresses",
        "reply_to_addresses",
        "date_header",
        "date_parsed",
        "message_id",
        "headers",
        "text_body",
        "html_body",
        "body_charset",
        "links",
        "multipart",
        "part_count",
        "max_depth",
        "defect_count",
        "defect_types",
    }
    assert columns["email_evidence_id"].nullable is False
    assert columns["parser_version"].nullable is False
    assert columns["multipart"].nullable is False
    assert columns["part_count"].nullable is False
    assert columns["max_depth"].nullable is False
    assert columns["defect_count"].nullable is False
    assert columns["subject"].nullable is True
    assert columns["text_body"].nullable is True
    assert columns["html_body"].nullable is True
    assert columns["links"].nullable is True


def test_email_attachments_columns() -> None:
    columns = EmailAttachment.__table__.columns
    assert set(columns.keys()) == {
        "id",
        "parsed_email_id",
        "created_at",
        "part_index",
        "category",
        "filename",
        "declared_content_type",
        "detected_content_type",
        "content_disposition",
        "content_transfer_encoding",
        "size_bytes",
        "sha256",
        "decode_ok",
    }
    assert columns["parsed_email_id"].nullable is False
    assert columns["part_index"].nullable is False
    assert columns["category"].nullable is False
    assert columns["decode_ok"].nullable is False
    # Q-2: the digest is nullable, because it is unknown when the decoded
    # bytes could not be established.
    assert columns["sha256"].nullable is True
    assert "CHAR" in str(columns["sha256"].type).upper()


def test_audit_events_columns() -> None:
    columns = AuditEvent.__table__.columns
    assert set(columns.keys()) == {
        "id",
        "occurred_at",
        "event_type",
        "email_evidence_id",
        "detail",
        "actor",
    }
    assert columns["event_type"].nullable is False
    # The link to the evidence is nullable: an audit record outlives a
    # physical deletion of its subject.
    assert columns["email_evidence_id"].nullable is True
    assert columns["detail"].nullable is True
    assert columns["actor"].nullable is True


def test_analysis_results_columns() -> None:
    columns = AnalysisResult.__table__.columns
    assert set(columns.keys()) == {
        "id",
        "email_evidence_id",
        "score",
        "risk_band",
        "signals",
        "intelligence_results",
        "narrative",
        "narrative_status",
        "narrative_reason",
        "engine_version",
        "created_at",
    }
    assert columns["email_evidence_id"].nullable is False
    assert columns["score"].nullable is False
    assert columns["risk_band"].nullable is False
    assert columns["signals"].nullable is False
    assert columns["intelligence_results"].nullable is False
    assert columns["narrative_status"].nullable is False
    assert columns["engine_version"].nullable is False
    assert columns["narrative"].nullable is True
    assert columns["narrative_reason"].nullable is True


def test_foreign_keys_and_their_deletion_behaviour() -> None:
    """The cascade rules are part of the approved design, not a detail."""
    expected = {
        ParsedEmail: ("email_evidence_id", "email_evidence.id", "CASCADE"),
        EmailAttachment: ("parsed_email_id", "parsed_emails.id", "CASCADE"),
        AuditEvent: ("email_evidence_id", "email_evidence.id", "SET NULL"),
        AnalysisResult: ("email_evidence_id", "email_evidence.id", "CASCADE"),
    }
    for model, (column, target, ondelete) in expected.items():
        foreign_keys = list(_table(model).foreign_keys)
        assert len(foreign_keys) == 1, model.__name__
        foreign_key = foreign_keys[0]
        assert foreign_key.parent.name == column, model.__name__
        assert foreign_key.target_fullname == target, model.__name__
        assert foreign_key.ondelete == ondelete, model.__name__


def test_unique_constraints() -> None:
    """One parsed view and one analysis result per evidence object."""
    parsed_uniques = {
        tuple(column.name for column in constraint.columns)
        for constraint in ParsedEmail.__table__.constraints
        if constraint.__class__.__name__ == "UniqueConstraint"
    }
    assert parsed_uniques == {("email_evidence_id",)}

    analysis_uniques = {
        tuple(column.name for column in constraint.columns)
        for constraint in AnalysisResult.__table__.constraints
        if constraint.__class__.__name__ == "UniqueConstraint"
    }
    assert analysis_uniques == {("email_evidence_id",)}

    attachment_uniques = {
        tuple(column.name for column in constraint.columns)
        for constraint in EmailAttachment.__table__.constraints
        if constraint.__class__.__name__ == "UniqueConstraint"
    }
    assert attachment_uniques == {("parsed_email_id", "part_index")}


def test_check_constraints_exist_with_the_approved_names() -> None:
    expected = {
        EmailEvidence: {"ck_email_evidence_status", "ck_email_evidence_deleted_state"},
        EmailAttachment: {
            "ck_email_attachments_digest_state",
            "ck_email_attachments_category",
        },
        AnalysisResult: {
            "ck_analysis_results_score",
            "ck_analysis_results_band",
            "ck_analysis_results_narrative_state",
        },
    }
    for model, names in expected.items():
        actual = {
            constraint.name
            for constraint in _table(model).constraints
            if constraint.__class__.__name__ == "CheckConstraint"
        }
        assert actual == names, model.__name__


def test_check_constraint_text() -> None:
    """The constraint *content* matters as much as its name."""

    def texts(model: type) -> dict[str, str]:
        return {
            constraint.name: str(constraint.sqltext)
            for constraint in _table(model).constraints
            if constraint.__class__.__name__ == "CheckConstraint"
        }

    evidence = texts(EmailEvidence)
    assert "parsing" in evidence["ck_email_evidence_status"]
    assert "parse_failed" in evidence["ck_email_evidence_status"]
    assert "deleted" in evidence["ck_email_evidence_status"]
    assert "deleted_at IS NOT NULL" in evidence["ck_email_evidence_deleted_state"]

    attachments = texts(EmailAttachment)
    # Q-2: the digest and the decode flag can never disagree.
    assert "decode_ok = true" in attachments["ck_email_attachments_digest_state"]
    assert "sha256 IS NOT NULL" in attachments["ck_email_attachments_digest_state"]
    assert "decode_ok = false" in attachments["ck_email_attachments_digest_state"]
    assert "sha256 IS NULL" in attachments["ck_email_attachments_digest_state"]
    assert "attachment" in attachments["ck_email_attachments_category"]
    assert "inline" in attachments["ck_email_attachments_category"]
    assert "unknown" in attachments["ck_email_attachments_category"]

    analysis = texts(AnalysisResult)
    assert "0 AND 100" in analysis["ck_analysis_results_score"]
    assert "low" in analysis["ck_analysis_results_band"]
    assert "critical" in analysis["ck_analysis_results_band"]
    assert "available" in analysis["ck_analysis_results_narrative_state"]
    assert "narrative IS NOT NULL" in analysis["ck_analysis_results_narrative_state"]
    assert "narrative IS NULL" in analysis["ck_analysis_results_narrative_state"]


def test_indexes_exist_with_the_approved_names() -> None:
    expected = {
        EmailEvidence: {
            "ix_email_evidence_sha256",
            "ix_email_evidence_received_at",
            "ix_email_evidence_status",
            "ix_email_evidence_deleted_at",
        },
        ParsedEmail: {"ix_parsed_emails_created_at"},
        EmailAttachment: {
            "ix_email_attachments_parsed_email_id",
            "ix_email_attachments_sha256",
        },
        AuditEvent: {
            "ix_audit_events_occurred_at",
            "ix_audit_events_email_evidence_id",
        },
        AnalysisResult: {"ix_analysis_results_email_evidence_id"},
    }
    for model, names in expected.items():
        actual = {index.name for index in _table(model).indexes}
        assert actual == names, model.__name__


def test_server_defaults_for_generated_identifiers_and_timestamps() -> None:
    for model in EXPECTED_MODELS.values():
        columns = _table(model).columns
        id_default = columns["id"].server_default
        assert id_default is not None, model.__name__
        assert "gen_random_uuid()" in str(id_default.arg), model.__name__


def test_intelligence_results_has_an_empty_object_default() -> None:
    default = AnalysisResult.__table__.columns["intelligence_results"].server_default
    assert default is not None
    assert "{}" in str(default.arg)


def test_relationships_are_configured() -> None:
    """One evidence row has at most one parsed view and one analysis result."""
    from sqlalchemy import inspect

    evidence_mapper = inspect(EmailEvidence)
    parsed_mapper = inspect(ParsedEmail)

    assert evidence_mapper.relationships["parsed_email"].uselist is False
    assert evidence_mapper.relationships["analysis_result"].uselist is False
    assert evidence_mapper.relationships["audit_events"].uselist is True

    assert parsed_mapper.relationships["attachments"].uselist is True


def test_evidence_row_can_be_built_without_a_database() -> None:
    """A model instance needs no database and no server-side default."""
    evidence = EmailEvidence(
        sha256="a" * 64,
        size_bytes=1024,
        storage_id="ab/cd/0123.bin",
        status="parsing",
    )
    assert isinstance(evidence.id, (uuid.UUID, type(None)))
    assert evidence.status == "parsing"
    assert evidence.original_filename is None
