"""URL extraction from decoded message bodies.

This module never opens a socket or imports an HTTP client. Extraction is a
best-effort text scan, not URL validation and not a security boundary.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from app.services.email.models import Link

_SCHEME_URL = re.compile(r"(?<![A-Za-z0-9+.-])([A-Za-z][A-Za-z0-9+.-]*://[^\s<>\"']+)")
_WWW_URL = re.compile(r"(?<![A-Za-z0-9.-])(www\.[^\s<>\"']+)")
_HTML_ATTR = re.compile(r"(?is)\b(?:href|src)\s*=\s*([\"'])(.*?)\1")
_TRAILING_PUNCTUATION = ".,;:!?)]}>'\""


def _host(url: str) -> str:
    """Lower-case hostname with the port removed."""
    candidate = url if "://" in url else f"https://{url}"
    try:
        host = urlsplit(candidate).hostname
    except ValueError:
        return ""
    return host.lower() if host else ""


def _clean(candidate: str) -> str:
    """Strip trailing prose punctuation that is not part of a URL."""
    return candidate.rstrip(_TRAILING_PUNCTUATION)


def extract_plain_text_links(text: str | None) -> list[Link]:
    """Extract ``scheme://`` URLs and bare ``www.`` hosts from plain text."""
    if not text:
        return []

    results: list[Link] = []
    seen: set[str] = set()
    for pattern in (_SCHEME_URL, _WWW_URL):
        for match in pattern.finditer(text):
            url = _clean(match.group(1))
            if not url or url in seen:
                continue
            seen.add(url)
            results.append(Link(url=url, host=_host(url)))
    return results


def extract_html_links(html: str | None) -> list[Link]:
    """Extract quoted ``href`` and ``src`` values with a forgiving scanner."""
    if not html:
        return []

    results: list[Link] = []
    seen: set[str] = set()
    for match in _HTML_ATTR.finditer(html):
        url = _clean(match.group(2).strip())
        if not url or url in seen:
            continue
        seen.add(url)
        results.append(Link(url=url, host=_host(url)))
    return results


def extract_links(text_body: str | None, html_body: str | None) -> list[Link]:
    """Extract links from both bodies, preserving plain-text order first."""
    links = extract_plain_text_links(text_body)
    seen = {link.url for link in links}
    for link in extract_html_links(html_body):
        if link.url not in seen:
            seen.add(link.url)
            links.append(link)
    return links
