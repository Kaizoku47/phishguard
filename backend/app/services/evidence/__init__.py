"""Evidence storage services.

The evidence store is the only component that writes uploaded messages to
disk. See :mod:`app.services.evidence.store` for the layout and the
path-safety rules.
"""

from __future__ import annotations

from app.services.evidence.store import EvidenceStore, EvidenceWriter, StoredObject

__all__ = ["EvidenceStore", "EvidenceWriter", "StoredObject"]
