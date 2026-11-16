"""Create the email ingestion schema.

Adds the five Milestone 2.3.1 tables:

* ``email_evidence``   - one accepted upload: its bytes, digest and parse state
* ``parsed_emails``    - the normalised, parsed view of one evidence object
* ``email_attachments`` - metadata for each leaf MIME part, and its digest
* ``audit_events``     - the append-only, security-relevant audit trail
* ``analysis_results`` - one current result per evidence record

Revision ID: 0002_email_ingestion
Revises: 0001_baseline
Create Date: 2026-11-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0002_email_ingestion"
down_revision: str | Sequence[str] | None = "0001_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the five ingestion tables, parents before children."""
    op.create_table(
        "email_evidence",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("sha256", sa.CHAR(length=64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("storage_id", sa.String(length=128), nullable=False),
        sa.Column("original_filename", sa.String(length=512), nullable=True),
        sa.Column("declared_content_type", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("parser_version", sa.String(length=32), nullable=True),
        sa.Column("defect_count", sa.Integer(), nullable=True),
        sa.Column("limit_exceeded", sa.String(length=64), nullable=True),
        sa.Column("failure_reason", sa.String(length=64), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('parsing','parsed','parse_failed','deleted')",
            name=op.f("ck_email_evidence_status"),
        ),
        sa.CheckConstraint(
            "(status = 'deleted' AND deleted_at IS NOT NULL) "
            "OR (status <> 'deleted' AND deleted_at IS NULL)",
            name=op.f("ck_email_evidence_deleted_state"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_email_evidence")),
    )
    op.create_index("ix_email_evidence_sha256", "email_evidence", ["sha256"], unique=False)
    op.create_index(
        "ix_email_evidence_received_at", "email_evidence", ["received_at"], unique=False
    )
    op.create_index("ix_email_evidence_status", "email_evidence", ["status"], unique=False)
    op.create_index("ix_email_evidence_deleted_at", "email_evidence", ["deleted_at"], unique=False)

    op.create_table(
        "parsed_emails",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("email_evidence_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("parser_version", sa.String(length=32), nullable=False),
        sa.Column("subject", sa.Text(), nullable=True),
        sa.Column("from_address", sa.Text(), nullable=True),
        sa.Column("from_display_name", sa.Text(), nullable=True),
        sa.Column("to_addresses", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("cc_addresses", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("reply_to_addresses", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("date_header", sa.Text(), nullable=True),
        sa.Column("date_parsed", sa.DateTime(timezone=True), nullable=True),
        sa.Column("message_id", sa.Text(), nullable=True),
        sa.Column("headers", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("text_body", sa.Text(), nullable=True),
        sa.Column("html_body", sa.Text(), nullable=True),
        sa.Column("body_charset", sa.String(length=64), nullable=True),
        sa.Column("links", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("multipart", sa.Boolean(), nullable=False),
        sa.Column("part_count", sa.Integer(), nullable=False),
        sa.Column("max_depth", sa.Integer(), nullable=False),
        sa.Column("defect_count", sa.Integer(), nullable=False),
        sa.Column("defect_types", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(
            ["email_evidence_id"],
            ["email_evidence.id"],
            name=op.f("fk_parsed_emails_email_evidence_id_email_evidence"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_parsed_emails")),
        sa.UniqueConstraint("email_evidence_id", name="uq_parsed_emails_email_evidence_id"),
    )
    op.create_index("ix_parsed_emails_created_at", "parsed_emails", ["created_at"], unique=False)

    op.create_table(
        "email_attachments",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("parsed_email_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("part_index", sa.Integer(), nullable=False),
        sa.Column("category", sa.String(length=16), nullable=False),
        sa.Column("filename", sa.Text(), nullable=True),
        sa.Column("declared_content_type", sa.Text(), nullable=True),
        sa.Column("detected_content_type", sa.Text(), nullable=True),
        sa.Column("content_disposition", sa.Text(), nullable=True),
        sa.Column("content_transfer_encoding", sa.Text(), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("sha256", sa.CHAR(length=64), nullable=True),
        sa.Column("decode_ok", sa.Boolean(), nullable=False),
        sa.CheckConstraint(
            "(decode_ok = true AND sha256 IS NOT NULL) OR (decode_ok = false AND sha256 IS NULL)",
            name=op.f("ck_email_attachments_digest_state"),
        ),
        sa.CheckConstraint(
            "category IN ('attachment','inline','unknown')",
            name=op.f("ck_email_attachments_category"),
        ),
        sa.ForeignKeyConstraint(
            ["parsed_email_id"],
            ["parsed_emails.id"],
            name=op.f("fk_email_attachments_parsed_email_id_parsed_emails"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_email_attachments")),
        sa.UniqueConstraint(
            "parsed_email_id",
            "part_index",
            name="uq_email_attachments_parsed_email_id_part_index",
        ),
    )
    op.create_index(
        "ix_email_attachments_parsed_email_id",
        "email_attachments",
        ["parsed_email_id"],
        unique=False,
    )
    op.create_index("ix_email_attachments_sha256", "email_attachments", ["sha256"], unique=False)

    op.create_table(
        "audit_events",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("email_evidence_id", sa.Uuid(), nullable=True),
        sa.Column("detail", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("actor", sa.String(length=128), nullable=True),
        sa.ForeignKeyConstraint(
            ["email_evidence_id"],
            ["email_evidence.id"],
            name=op.f("fk_audit_events_email_evidence_id_email_evidence"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
    )
    op.create_index("ix_audit_events_occurred_at", "audit_events", ["occurred_at"], unique=False)
    op.create_index(
        "ix_audit_events_email_evidence_id",
        "audit_events",
        ["email_evidence_id"],
        unique=False,
    )

    op.create_table(
        "analysis_results",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("email_evidence_id", sa.Uuid(), nullable=False),
        sa.Column("score", sa.SmallInteger(), nullable=False),
        sa.Column("risk_band", sa.String(length=16), nullable=False),
        sa.Column("signals", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "intelligence_results",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("narrative", sa.Text(), nullable=True),
        sa.Column("narrative_status", sa.String(length=24), nullable=False),
        sa.Column("narrative_reason", sa.Text(), nullable=True),
        sa.Column("engine_version", sa.String(length=32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("score BETWEEN 0 AND 100", name=op.f("ck_analysis_results_score")),
        sa.CheckConstraint(
            "risk_band IN ('low','medium','high','critical')",
            name=op.f("ck_analysis_results_band"),
        ),
        sa.CheckConstraint(
            "(narrative_status = 'available' AND narrative IS NOT NULL) "
            "OR (narrative_status <> 'available' AND narrative IS NULL)",
            name=op.f("ck_analysis_results_narrative_state"),
        ),
        sa.ForeignKeyConstraint(
            ["email_evidence_id"],
            ["email_evidence.id"],
            name=op.f("fk_analysis_results_email_evidence_id_email_evidence"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_analysis_results")),
        sa.UniqueConstraint("email_evidence_id", name="uq_analysis_results_email_evidence_id"),
    )
    op.create_index(
        "ix_analysis_results_email_evidence_id",
        "analysis_results",
        ["email_evidence_id"],
        unique=False,
    )


def downgrade() -> None:
    """Drop the five ingestion tables, children before parents."""
    op.drop_index("ix_analysis_results_email_evidence_id", table_name="analysis_results")
    op.drop_table("analysis_results")
    op.drop_index("ix_audit_events_email_evidence_id", table_name="audit_events")
    op.drop_index("ix_audit_events_occurred_at", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index("ix_email_attachments_sha256", table_name="email_attachments")
    op.drop_index("ix_email_attachments_parsed_email_id", table_name="email_attachments")
    op.drop_table("email_attachments")
    op.drop_index("ix_parsed_emails_created_at", table_name="parsed_emails")
    op.drop_table("parsed_emails")
    op.drop_index("ix_email_evidence_deleted_at", table_name="email_evidence")
    op.drop_index("ix_email_evidence_sha256", table_name="email_evidence")
    op.drop_index("ix_email_evidence_received_at", table_name="email_evidence")
    op.drop_index("ix_email_evidence_status", table_name="email_evidence")
    op.drop_table("email_evidence")
