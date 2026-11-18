"""Deterministic phishing signals for Milestone 2.3.5.

Every function here is pure over the parsed record and attachment metadata.
No function fetches URLs, resolves DNS, opens sockets, renders HTML, executes
attachments, writes files, calls a model, or interprets sender-controlled
authentication headers.
"""

from __future__ import annotations

from dataclasses import dataclass
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

from app.services.analysis.score import SIGNAL_WEIGHTS

SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"
SEVERITY_NONE = "none"

# Deliberately small, fixed v1 heuristic lists. They are never downloaded or
# dynamically updated.
BRAND_DOMAINS: frozenset[str] = frozenset(
    {
        "microsoft.com",
        "google.com",
        "apple.com",
        "amazon.com",
        "paypal.com",
        "netflix.com",
    }
)
FREE_MAIL_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "yahoo.com",
        "icloud.com",
        "proton.me",
        "protonmail.com",
        "aol.com",
    }
)
SUSPICIOUS_TLDS: frozenset[str] = frozenset({"top", "xyz", "click", "work", "country", "gq", "tk"})

ZIP_EXTENSIONS: frozenset[str] = frozenset({".zip"})
RAR_EXTENSIONS: frozenset[str] = frozenset({".rar"})
ZIP_MIME_TYPES: frozenset[str] = frozenset(
    {
        "application/zip",
        "application/x-zip-compressed",
        "application/zip-compressed",
        "application/x-zip",
    }
)
RAR_MIME_TYPES: frozenset[str] = frozenset(
    {
        "application/vnd.rar",
        "application/x-rar-compressed",
        "application/rar",
        "application/x-rar",
    }
)

AUTH_UNVERIFIABLE_TARGET = "auth:spf_dkim_dmarc"
AUTH_UNVERIFIABLE_REASON = (
    "Uploaded Authentication-Results headers are sender-controlled/untrusted; "
    "PHISHGUARD has no trusted receiving infrastructure, so no SPF, DKIM or "
    "DMARC outcome can be established. This is not an authentication verdict."
)


@dataclass(frozen=True, slots=True)
class Signal:
    """One deterministic signal observation.

    ``reason`` is mandatory and non-empty. An unevaluated signal must carry a
    zero contribution, so it can never affect the score.
    """

    id: str
    severity: str
    contribution: int
    reason: str
    evaluated: bool

    def __post_init__(self) -> None:
        if not self.reason or not self.reason.strip():
            raise ValueError("a signal reason is mandatory")
        if not self.evaluated and self.contribution != 0:
            raise ValueError("an unevaluated signal must contribute zero")

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "severity": self.severity,
            "contribution": self.contribution,
            "reason": self.reason,
            "evaluated": self.evaluated,
        }


def _get(value: Any, name: str, default: Any = None) -> Any:
    return getattr(value, name, default)


def normalize_domain(value: str | None) -> str:
    """Normalize a hostname consistently: lowercase, trim, dot and IDNA."""
    if not value:
        return ""
    host = value.strip().lower()
    if host.endswith("."):
        host = host[:-1]
    if not host:
        return ""
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def domain_from_address(value: str | None) -> str:
    """Extract and normalize the domain from an address string."""
    if not value:
        return ""
    _, address = parseaddr(value)
    if "@" not in address:
        return ""
    return normalize_domain(address.rsplit("@", 1)[1])


def _link_hosts(parsed: Any) -> list[str]:
    hosts: list[str] = []
    for link in _get(parsed, "links", []) or []:
        host = normalize_domain(link.get("host") if isinstance(link, dict) else _get(link, "host"))
        if host:
            hosts.append(host)
    return hosts


def _link_urls(parsed: Any) -> list[str]:
    urls: list[str] = []
    for link in _get(parsed, "links", []) or []:
        url = link.get("url") if isinstance(link, dict) else _get(link, "url")
        if isinstance(url, str) and url:
            urls.append(url)
    return urls


def _levenshtein_distance(left: str, right: str) -> int:
    """Compute Levenshtein distance with a bounded dynamic-programming table."""
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i] + [0] * len(right)
        for j, right_char in enumerate(right, start=1):
            current[j] = min(
                previous[j] + 1,
                current[j - 1] + 1,
                previous[j - 1] + (left_char != right_char),
            )
        previous = current
    return previous[-1]


def _normalized_content_type(value: str | None) -> str:
    if not value:
        return ""
    return value.split(";", 1)[0].strip().lower()


def reply_to_mismatch_signal(parsed: Any, attachments: Any = None) -> Signal | None:
    from_domain = domain_from_address(_get(parsed, "from_address"))
    reply_domains = {
        domain_from_address(address) for address in (_get(parsed, "reply_to_addresses", []) or [])
    }
    reply_domains.discard("")
    if not from_domain or not reply_domains:
        return None
    if all(domain == from_domain for domain in reply_domains):
        return None
    return Signal(
        id="reply_to_mismatch",
        severity=SEVERITY_MEDIUM,
        contribution=SIGNAL_WEIGHTS["reply_to_mismatch"],
        reason=(
            "Reply-To uses a different domain from the sender-claimed From address. "
            "Both values are sender-claimed, so this shows an inconsistency in what "
            "the message claims, not proof of spoofing."
        ),
        evaluated=True,
    )


def lookalike_sender_domain_signal(parsed: Any, attachments: Any = None) -> Signal | None:
    claimed = domain_from_address(_get(parsed, "from_address"))
    if not claimed or claimed in BRAND_DOMAINS:
        return None
    if not any(_levenshtein_distance(claimed, brand) == 1 for brand in BRAND_DOMAINS):
        return None
    return Signal(
        id="lookalike_sender_domain",
        severity=SEVERITY_LOW,
        contribution=SIGNAL_WEIGHTS["lookalike_sender_domain"],
        reason=(
            "The sender-claimed From domain is one character edit away from a listed "
            "brand domain. The value is sender-claimed, so this is a lure indicator, "
            "not proof of impersonation."
        ),
        evaluated=True,
    )


def auth_results_unverifiable_signal(parsed: Any = None, attachments: Any = None) -> Signal:
    """Always emit an unevaluated authentication signal.

    The uploaded header is never parsed or interpreted. Its presence or absence
    proves nothing because the uploader controls it.
    """
    return Signal(
        id="auth_results_unverifiable",
        severity=SEVERITY_NONE,
        contribution=SIGNAL_WEIGHTS["auth_results_unverifiable"],
        reason=AUTH_UNVERIFIABLE_REASON,
        evaluated=False,
    )


def link_host_count_signal(parsed: Any, attachments: Any = None) -> Signal | None:
    if len(set(_link_hosts(parsed))) < 5:
        return None
    return Signal(
        id="link_host_count",
        severity=SEVERITY_MEDIUM,
        contribution=SIGNAL_WEIGHTS["link_host_count"],
        reason="The message body contains at least five distinct non-empty link hosts.",
        evaluated=True,
    )


def url_credential_scheme_signal(parsed: Any, attachments: Any = None) -> Signal | None:
    for url in _link_urls(parsed):
        try:
            parts = urlsplit(url)
            if parts.scheme.lower() not in {"http", "https"}:
                continue
            if parts.username and parts.password:
                return Signal(
                    id="url_credential_scheme",
                    severity=SEVERITY_HIGH,
                    contribution=SIGNAL_WEIGHTS["url_credential_scheme"],
                    reason="An HTTP(S) URL in the body contains both a username and a password.",
                    evaluated=True,
                )
        except ValueError:
            continue
    return None


def punycode_host_signal(parsed: Any, attachments: Any = None) -> Signal | None:
    for host in _link_hosts(parsed):
        if any(label.startswith("xn--") for label in host.split(".")):
            return Signal(
                id="punycode_host",
                severity=SEVERITY_MEDIUM,
                contribution=SIGNAL_WEIGHTS["punycode_host"],
                reason="A link host uses an IDNA punycode label.",
                evaluated=True,
            )
    return None


def free_mail_sender_signal(parsed: Any, attachments: Any = None) -> Signal | None:
    claimed = domain_from_address(_get(parsed, "from_address"))
    if claimed not in FREE_MAIL_DOMAINS:
        return None
    return Signal(
        id="free_mail_sender",
        severity=SEVERITY_LOW,
        contribution=SIGNAL_WEIGHTS["free_mail_sender"],
        reason=(
            "The sender-claimed From domain matches a listed free-mail provider. "
            "The value is sender-claimed, not verified."
        ),
        evaluated=True,
    )


def attachment_type_mismatch_signal(parsed: Any, attachments: Any) -> Signal | None:
    for item in attachments or []:
        declared = _normalized_content_type(_get(item, "declared_content_type"))
        detected = _normalized_content_type(_get(item, "detected_content_type"))
        if declared and detected and declared != detected:
            return Signal(
                id="attachment_type_mismatch",
                severity=SEVERITY_MEDIUM,
                contribution=SIGNAL_WEIGHTS["attachment_type_mismatch"],
                reason="An attachment's declared type differs from its detected type.",
                evaluated=True,
            )
    return None


def archive_attachment_signal(parsed: Any, attachments: Any) -> Signal | None:
    for item in attachments or []:
        filename = (_get(item, "filename") or "").strip().lower()
        suffix = "." + filename.rsplit(".", 1)[1] if "." in filename else ""
        declared = _normalized_content_type(_get(item, "declared_content_type"))
        detected = _normalized_content_type(_get(item, "detected_content_type"))
        types = {declared, detected} - {""}
        if suffix in ZIP_EXTENSIONS or types & ZIP_MIME_TYPES:
            return Signal(
                id="archive_attachment",
                severity=SEVERITY_MEDIUM,
                contribution=SIGNAL_WEIGHTS["archive_attachment"],
                reason="An attachment maps to ZIP using the fixed type/extension list.",
                evaluated=True,
            )
        if suffix in RAR_EXTENSIONS or types & RAR_MIME_TYPES:
            return Signal(
                id="archive_attachment",
                severity=SEVERITY_MEDIUM,
                contribution=SIGNAL_WEIGHTS["archive_attachment"],
                reason="An attachment maps to RAR using the fixed type/extension list.",
                evaluated=True,
            )
    return None


class _FormCounter(HTMLParser):
    """Count form start tags without rendering or executing HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.count = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "form":
            self.count += 1


def html_form_count_signal(parsed: Any, attachments: Any = None) -> Signal | None:
    html = _get(parsed, "html_body")
    if not isinstance(html, str) or not html:
        return None
    counter = _FormCounter()
    try:
        counter.feed(html)
        counter.close()
    except Exception:
        return None
    if counter.count < 1:
        return None
    return Signal(
        id="html_form_count",
        severity=SEVERITY_HIGH,
        contribution=SIGNAL_WEIGHTS["html_form_count"],
        reason="The stored HTML body contains at least one form.",
        evaluated=True,
    )


def suspicious_tld_signal(parsed: Any, attachments: Any = None) -> Signal | None:
    hosts = [domain_from_address(_get(parsed, "from_address")), *_link_hosts(parsed)]
    for host in hosts:
        if host and host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            return Signal(
                id="suspicious_tld",
                severity=SEVERITY_LOW,
                contribution=SIGNAL_WEIGHTS["suspicious_tld"],
                reason=(
                    "A sender-claimed domain or link host uses a listed suspicious TLD. "
                    "The value is sender-claimed, not verified."
                ),
                evaluated=True,
            )
    return None


def missing_date_signal(parsed: Any, attachments: Any = None) -> Signal | None:
    if _get(parsed, "date_header") and _get(parsed, "date_parsed") is not None:
        return None
    return Signal(
        id="missing_date",
        severity=SEVERITY_HIGH,
        contribution=SIGNAL_WEIGHTS["missing_date"],
        reason="The Date header is absent or could not be parsed.",
        evaluated=True,
    )


# Ordered like the architecture's signal table. Evaluation order is deterministic.
SIGNAL_FUNCTIONS = (
    reply_to_mismatch_signal,
    lookalike_sender_domain_signal,
    auth_results_unverifiable_signal,
    link_host_count_signal,
    url_credential_scheme_signal,
    punycode_host_signal,
    free_mail_sender_signal,
    attachment_type_mismatch_signal,
    archive_attachment_signal,
    html_form_count_signal,
    suspicious_tld_signal,
    missing_date_signal,
)


def evaluate_signals(parsed: Any, attachments: Any) -> list[Signal]:
    """Evaluate all signals in deterministic order."""
    signals: list[Signal] = []
    for function in SIGNAL_FUNCTIONS:
        signal = function(parsed, attachments)
        if signal is not None:
            signals.append(signal)
    return signals


def missing_evidence(signals: Any) -> list[dict[str, str]]:
    """Represent unevaluated evidence for the future report endpoint.

    Only the authentication signal has a missing-evidence target in the
    approved architecture.
    """
    result: list[dict[str, str]] = []
    for signal in signals:
        if not signal.evaluated and signal.id == "auth_results_unverifiable":
            result.append({"target": AUTH_UNVERIFIABLE_TARGET, "reason": signal.reason})
    return result
