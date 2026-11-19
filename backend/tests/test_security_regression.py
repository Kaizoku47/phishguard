"""Milestone 2.3.7 security-boundary regression checks."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from app.api.v1.analysis import ReportResponse
from app.main import create_app
from app.models import Base
from app.services.analysis import agent as agent_module
from app.services.analysis.agent import TOOL_NAMES


class _RedirectResponse:
    status = 302

    def getheader(self, name: str) -> str | None:
        return None

    def read1(self, size: int) -> bytes:
        return b""


class _RedirectConnection:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.closed = False

    def request(self, *args: Any, **kwargs: Any) -> None:
        return None

    def getresponse(self) -> _RedirectResponse:
        return _RedirectResponse()

    def close(self) -> None:
        self.closed = True


def test_no_raw_body_or_attachment_download_endpoint() -> None:
    paths = create_app().openapi()["paths"]
    for path in paths:
        lowered = path.lower()
        assert "/body" not in lowered
        assert "download" not in lowered
    assert "/api/v1/emails/{email_id}/report" in paths


def test_report_schema_exposes_no_storage_details() -> None:
    fields = set(ReportResponse.model_fields)
    assert fields.isdisjoint({"body", "raw_body", "storage_id", "path", "evidence_root"})


def test_exactly_five_domain_tables_in_metadata() -> None:
    assert set(Base.metadata.tables) == {
        "email_evidence",
        "parsed_emails",
        "email_attachments",
        "audit_events",
        "analysis_results",
    }


def test_no_new_migration_was_added() -> None:
    versions = Path(__file__).parents[1] / "alembic" / "versions"
    names = sorted(path.name for path in versions.glob("*.py") if not path.name.startswith("__"))
    assert names == ["0001_baseline.py", "0002_email_ingestion.py"]


def test_seven_tool_allowlist_is_unchanged() -> None:
    assert (
        frozenset(
            {
                "get_headers",
                "get_signals",
                "get_links",
                "get_attachments",
                "lookup_domain",
                "lookup_hash",
                "record_finding",
            }
        )
        == TOOL_NAMES
    )


def test_redirect_response_is_not_followed(monkeypatch: pytest.MonkeyPatch) -> None:
    from app.services.analysis.agent import AgentProviderError, _post_chat_completion

    from tests.test_agent import make_settings

    monkeypatch.setattr(agent_module, "_PinnedHTTPSConnection", _RedirectConnection)
    monkeypatch.setattr(
        agent_module, "_resolve_and_validate", lambda host, deadline=None: ("93.184.216.34",)
    )
    with pytest.raises(AgentProviderError, match="provider error"):
        _post_chat_completion(make_settings(), [])
