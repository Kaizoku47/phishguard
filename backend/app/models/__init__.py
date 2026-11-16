"""PHISHGUARD domain models.

Importing this package registers every model on ``Base.metadata``. Alembic
imports the package rather than the base module, so that ``--autogenerate``
sees the whole schema instead of an empty one.

The five tables are:

| Table | Purpose |
|---|---|
| ``email_evidence`` | One accepted upload: its bytes, its digest, its parse state |
| ``parsed_emails`` | The normalised, parsed view of one evidence object |
| ``email_attachments`` | Metadata for each leaf MIME part, and its digest |
| ``audit_events`` | The append-only, security-relevant audit trail |
| ``analysis_results`` | One current result per evidence record |
"""

from app.models.analysis_result import AnalysisResult
from app.models.audit_event import AuditEvent
from app.models.base import Base
from app.models.email_attachment import EmailAttachment
from app.models.email_evidence import EmailEvidence
from app.models.parsed_email import ParsedEmail

__all__ = [
    "AnalysisResult",
    "AuditEvent",
    "Base",
    "EmailAttachment",
    "EmailEvidence",
    "ParsedEmail",
]
