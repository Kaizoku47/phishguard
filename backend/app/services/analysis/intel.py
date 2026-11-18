"""LevelBlue OTX threat-intelligence integration.

This module is the only outbound network boundary in PHISHGUARD. It uses the
Python standard library exclusively: DNS addresses are validated, one validated
address is pinned, TLS keeps the original hostname for SNI and certificate
verification, redirects are refused, and responses are streamed under a hard
size cap.

Provider responses are untrusted data. They never affect deterministic scoring.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import math
import re
import socket
import ssl
import threading
import time
from collections import OrderedDict
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

from pydantic import SecretStr

from app.core.config import Settings

PROVIDER_ID = "otx"
OTX_HOST = "otx.alienvault.com"
OTX_PORT = 443
OTX_API_HEADER = "X-OTX-API-KEY"

# Verified against the official OTX API documentation and OTX Python SDK:
# https://otx.alienvault.com/api/
# https://github.com/AlienVault-OTX/OTX-Python-SDK
OTX_ENDPOINTS = {
    "domain": "/api/v1/indicators/domain/{indicator}/general",
    "hash": "/api/v1/indicators/file/{indicator}/general",
}

CACHE_TTL_SECONDS = 24 * 60 * 60
CACHE_CAPACITY = 256
MIN_REQUEST_INTERVAL_SECONDS = 1.0
MAX_RETRY_AFTER_SECONDS = 60
MAX_LOOKUPS_PER_OPERATION = 5
READ_CHUNK_BYTES = 8192
MAX_HEX_FIELD_LENGTH = 16
MAX_DECIMAL_FIELD_LENGTH = 16

# HTTP token characters, used for chunk-extension and trailer field names.
_TOKEN_BYTES = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")

# Distinguishes an absent Retry-After header from a supplied but invalid one.
_RETRY_INVALID = object()

METADATA_ADDRESSES: frozenset[str] = frozenset(
    {
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "fd00:ec2::254",
    }
)

_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

_CACHE: OrderedDict[tuple[str, str, str], tuple[float, dict[str, Any]]] = OrderedDict()
_CACHE_LOCK = threading.Lock()
_PACING_LOCK = threading.Lock()
_LAST_REQUEST_MONOTONIC: float | None = None


class IntelligenceUnavailableError(Exception):
    """A safe, bounded reason why provider intelligence is unavailable."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class IntelligenceResult:
    """Supplementary intelligence data for one parsed record."""

    domains: dict[str, dict[str, Any]] = field(default_factory=dict)
    hashes: dict[str, dict[str, Any]] = field(default_factory=dict)
    missing: list[dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "domains": deepcopy(self.domains),
            "hashes": deepcopy(self.hashes),
            "missing": list(self.missing),
        }


def _normalize_domain(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IntelligenceUnavailableError("invalid_indicator")
    host = value.strip().lower()
    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > 253 or any(char.isspace() for char in host):
        raise IntelligenceUnavailableError("invalid_indicator")
    if "/" in host or "\\" in host or "@" in host or ":" in host:
        raise IntelligenceUnavailableError("invalid_indicator")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        raise IntelligenceUnavailableError("invalid_indicator")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise IntelligenceUnavailableError("invalid_indicator") from None
    labels = host.split(".")
    if any(not _DOMAIN_LABEL_RE.match(label) for label in labels):
        raise IntelligenceUnavailableError("invalid_indicator")
    return host


def _normalize_hash(value: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.match(value.strip()):
        raise IntelligenceUnavailableError("invalid_indicator")
    return value.strip().lower()


def _is_unsafe_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    candidate = address
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        candidate = address.ipv4_mapped
    return (
        candidate.is_private
        or candidate.is_loopback
        or candidate.is_link_local
        or candidate.is_multicast
        or candidate.is_reserved
        or candidate.is_unspecified
        or str(candidate) in METADATA_ADDRESSES
        or str(address) in METADATA_ADDRESSES
    )


def _validate_dns(host: str) -> tuple[int, ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve and validate every answer, then pin one deterministic address."""
    try:
        answers = socket.getaddrinfo(host, OTX_PORT, type=socket.SOCK_STREAM)
    except OSError:
        raise IntelligenceUnavailableError("dns_resolution_failed") from None

    validated: list[tuple[int, ipaddress.IPv4Address | ipaddress.IPv6Address]] = []
    for answer in answers:
        raw_address = answer[4][0]
        if isinstance(raw_address, bytes):
            raw_address = raw_address.decode("ascii", "replace")
        raw_address = raw_address.split("%", 1)[0]
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError:
            raise IntelligenceUnavailableError("unsafe_dns_answer") from None
        if _is_unsafe_address(address):
            raise IntelligenceUnavailableError("unsafe_dns_answer")
        validated.append((int(answer[0]), address))

    if not validated:
        raise IntelligenceUnavailableError("dns_resolution_failed")
    validated.sort(key=lambda item: (item[0], item[1].packed))
    return validated[0]


def _wait_for_pace() -> None:
    """Conservative process-local pacing; no quota claim is made."""
    global _LAST_REQUEST_MONOTONIC
    with _PACING_LOCK:
        now = time.monotonic()
        if _LAST_REQUEST_MONOTONIC is not None:
            remaining = MIN_REQUEST_INTERVAL_SECONDS - (now - _LAST_REQUEST_MONOTONIC)
            if remaining > 0:
                time.sleep(remaining)
        _LAST_REQUEST_MONOTONIC = time.monotonic()


def _retry_after_seconds(value: str | None, now: datetime | None = None) -> object:
    """Return a bounded delay, ``None`` for absent, or ``_RETRY_INVALID``."""
    if not value or not value.strip():
        return None
    text = value.strip()

    try:
        seconds = int(text)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError):
            return _RETRY_INVALID
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=UTC)
        reference = now or datetime.now(UTC)
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=UTC)
        seconds = math.ceil((retry_at.astimezone(UTC) - reference.astimezone(UTC)).total_seconds())

    if seconds < 0:
        return 0
    if seconds > MAX_RETRY_AFTER_SECONDS:
        return _RETRY_INVALID
    return seconds


def _validate_api_key(key: str) -> None:
    """Reject anything that is not a printable ASCII HTTP header value."""
    if not key or any(not 0x21 <= ord(char) <= 0x7E for char in key):
        raise IntelligenceUnavailableError("invalid_api_key")


def _build_request(path: str, api_key: SecretStr | None) -> bytes:
    key = api_key.get_secret_value() if api_key is not None else ""
    _validate_api_key(key)
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {OTX_HOST}",
        f"{OTX_API_HEADER}: {key}" if key else "",
        "Accept: application/json",
        "User-Agent: phishguard-backend/2.3.6",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(lines).encode("ascii")


def _read_capped(connection: ssl.SSLSocket, maximum: int, deadline: float) -> bytes:
    """Read up to ``maximum`` bytes without extending the total deadline."""
    chunks: list[bytes] = []
    total = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise IntelligenceUnavailableError("provider_timeout")
        connection.settimeout(remaining)
        chunk = connection.recv(READ_CHUNK_BYTES)
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise IntelligenceUnavailableError("response_too_large")
        chunks.append(chunk)
    return b"".join(chunks)


def _valid_field_name(name: bytes) -> bool:
    return bool(_TOKEN_BYTES.match(name))


def _valid_field_value(value: bytes) -> bool:
    return all(char >= 0x20 and char != 0x7F for char in value)


def _valid_chunk_extension(extension: bytes) -> bool:
    """Validate RFC-style ``;name`` or ``;name=value`` chunk extensions."""
    if not extension:
        return False
    for segment in extension.split(b";"):
        segment = segment.strip()
        if not segment:
            return False
        name, separator, value = segment.partition(b"=")
        if not _valid_field_name(name.strip()):
            return False
        if not separator:
            continue
        value = value.strip()
        if value.startswith(b'"'):
            if len(value) < 2 or not value.endswith(b'"'):
                return False
            inner = value[1:-1]
            if not _valid_field_value(inner) or b'"' in inner:
                return False
        elif not _valid_field_name(value):
            return False
    return True


def _decode_chunked(body: bytes, maximum: int) -> bytes:
    """Decode valid HTTP chunked framing without an HTTP client dependency."""
    decoded = bytearray()
    position = 0
    hex_digits = b"0123456789abcdefABCDEF"

    while True:
        line_end = body.find(b"\r\n", position)
        if line_end < 0:
            raise IntelligenceUnavailableError("malformed_response")
        size_part, separator, extension = body[position:line_end].partition(b";")
        if separator and not _valid_chunk_extension(extension):
            raise IntelligenceUnavailableError("malformed_response")
        size_field = size_part.strip()
        if (
            not size_field
            or len(size_field) > MAX_HEX_FIELD_LENGTH
            or any(char not in hex_digits for char in size_field)
        ):
            raise IntelligenceUnavailableError("malformed_response")
        try:
            size = int(size_field, 16)
        except (ValueError, OverflowError):
            raise IntelligenceUnavailableError("malformed_response") from None
        position = line_end + 2

        if size == 0:
            while True:
                trailer_end = body.find(b"\r\n", position)
                if trailer_end < 0:
                    raise IntelligenceUnavailableError("malformed_response")
                trailer = body[position:trailer_end]
                position = trailer_end + 2
                if not trailer:
                    break
                name, delimiter, value = trailer.partition(b":")
                if (
                    not delimiter
                    or not _valid_field_name(name.strip())
                    or name != name.strip()
                    or not _valid_field_value(value)
                ):
                    raise IntelligenceUnavailableError("malformed_response")
            if position != len(body):
                raise IntelligenceUnavailableError("malformed_response")
            break

        chunk_end = position + size
        if chunk_end + 2 > len(body) or body[chunk_end : chunk_end + 2] != b"\r\n":
            raise IntelligenceUnavailableError("malformed_response")
        decoded.extend(body[position:chunk_end])
        if len(decoded) > maximum:
            raise IntelligenceUnavailableError("response_too_large")
        position = chunk_end + 2

    return bytes(decoded)


def _parse_http_response(raw: bytes, maximum: int) -> tuple[int, dict[str, str], bytes]:
    if len(raw) > maximum:
        raise IntelligenceUnavailableError("response_too_large")
    head, separator, raw_body = raw.partition(b"\r\n\r\n")
    if not separator:
        raise IntelligenceUnavailableError("malformed_response")
    stripped_head = head.replace(b"\r\n", b"")
    if b"\r" in stripped_head or b"\n" in stripped_head:
        raise IntelligenceUnavailableError("malformed_response")

    lines = head.split(b"\r\n")
    if not lines:
        raise IntelligenceUnavailableError("malformed_response")
    try:
        status_line = lines[0].decode("ascii")
    except UnicodeDecodeError:
        raise IntelligenceUnavailableError("malformed_response") from None
    status_parts = status_line.split(" ", 2)
    if (
        len(status_parts) < 2
        or status_parts[0] not in {"HTTP/1.0", "HTTP/1.1"}
        or len(status_parts[1]) != 3
        or not status_parts[1].isdigit()
    ):
        raise IntelligenceUnavailableError("malformed_response")
    status = int(status_parts[1])

    headers: dict[str, str] = {}
    for line in lines[1:]:
        try:
            text = line.decode("ascii")
        except UnicodeDecodeError:
            raise IntelligenceUnavailableError("malformed_response") from None
        name, delimiter, value = text.partition(":")
        if not delimiter or not name.strip() or name != name.strip():
            raise IntelligenceUnavailableError("malformed_response")
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in name + value):
            raise IntelligenceUnavailableError("malformed_response")
        key = name.strip().lower()
        if key in headers:
            raise IntelligenceUnavailableError("malformed_response")
        headers[key] = value.strip()

    transfer_encoding = headers.get("transfer-encoding")
    content_length = headers.get("content-length")
    if transfer_encoding:
        if transfer_encoding.lower() != "chunked" or content_length is not None:
            raise IntelligenceUnavailableError("malformed_response")
        body = _decode_chunked(raw_body, maximum)
    elif content_length is not None:
        if (
            not content_length
            or len(content_length) > MAX_DECIMAL_FIELD_LENGTH
            or not content_length.isdigit()
        ):
            raise IntelligenceUnavailableError("malformed_response")
        try:
            expected_length = int(content_length)
        except (ValueError, OverflowError):
            raise IntelligenceUnavailableError("malformed_response") from None
        if len(raw_body) != expected_length:
            raise IntelligenceUnavailableError("malformed_response")
        body = raw_body
    else:
        body = raw_body

    if len(body) > maximum:
        raise IntelligenceUnavailableError("response_too_large")
    return status, headers, body


def _pinned_https_get(
    path: str,
    api_key: SecretStr | None,
    settings: Settings,
    pinned: tuple[int, ipaddress.IPv4Address | ipaddress.IPv6Address],
) -> bytes:
    """Make one request over a socket pinned to a previously validated IP."""
    family, address = pinned
    deadline = time.monotonic() + settings.intel_timeout_seconds
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        sock.settimeout(remaining)
        sock.connect((str(address), OTX_PORT))
        context = ssl.create_default_context()
        connection = context.wrap_socket(sock, server_hostname=OTX_HOST)
    except TimeoutError:
        with contextlib.suppress(OSError):
            sock.close()
        raise IntelligenceUnavailableError("provider_timeout") from None
    except (ssl.SSLError, OSError):
        with contextlib.suppress(OSError):
            sock.close()
        raise IntelligenceUnavailableError("tls_failure") from None

    try:
        connection.sendall(_build_request(path, api_key))
        raw = _read_capped(connection, settings.intel_max_response_bytes, deadline)
    except TimeoutError:
        raise IntelligenceUnavailableError("provider_timeout") from None
    except IntelligenceUnavailableError:
        raise
    except OSError:
        raise IntelligenceUnavailableError("provider_connection_failed") from None
    finally:
        with contextlib.suppress(OSError):
            connection.close()
    return raw


def _request_json(path: str, api_key: SecretStr | None, settings: Settings) -> dict[str, Any]:
    pinned = _validate_dns(OTX_HOST)
    for attempt in range(2):
        _wait_for_pace()
        raw = _pinned_https_get(path, api_key, settings, pinned)
        status, headers, body = _parse_http_response(raw, settings.intel_max_response_bytes)

        if 300 <= status < 400:
            raise IntelligenceUnavailableError("redirect_refused")
        if status == 429:
            if attempt == 0:
                retry_after = _retry_after_seconds(headers.get("retry-after"))
                if retry_after is _RETRY_INVALID:
                    raise IntelligenceUnavailableError("provider_rate_limited")
                if retry_after is not None:
                    time.sleep(retry_after)
                continue
            raise IntelligenceUnavailableError("provider_rate_limited")
        if status in (401, 403):
            raise IntelligenceUnavailableError("unauthorized")
        if status >= 500:
            raise IntelligenceUnavailableError("provider_server_error")
        if status != 200:
            raise IntelligenceUnavailableError("provider_http_error")

        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise IntelligenceUnavailableError("malformed_response") from None
        if not isinstance(payload, dict):
            raise IntelligenceUnavailableError("malformed_response")
        return _extract_minimal_fields(payload)
    raise IntelligenceUnavailableError("provider_rate_limited")  # pragma: no cover


def _extract_minimal_fields(payload: dict[str, Any]) -> dict[str, Any]:
    """Extract only finite, typed fields from a recognized OTX response."""
    recognized = False
    result: dict[str, Any] = {
        "provider": PROVIDER_ID,
        "reputation": None,
        "pulse_count": None,
    }

    if "reputation" in payload:
        recognized = True
        reputation = payload["reputation"]
        if (
            isinstance(reputation, bool)
            or not isinstance(reputation, (int, float))
            or not math.isfinite(reputation)
        ):
            raise IntelligenceUnavailableError("malformed_response")
        result["reputation"] = reputation

    if "pulse_info" in payload:
        recognized = True
        pulse_info = payload["pulse_info"]
        if not isinstance(pulse_info, dict):
            raise IntelligenceUnavailableError("malformed_response")
        if "count" in pulse_info:
            count = pulse_info["count"]
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise IntelligenceUnavailableError("malformed_response")
            result["pulse_count"] = count

    if not recognized:
        raise IntelligenceUnavailableError("malformed_response")
    return result


def _cache_key(operation: str, indicator: str) -> tuple[str, str, str]:
    return (PROVIDER_ID, operation, indicator)


def _purge_expired(now: float) -> None:
    """Drop every expired entry; caller holds ``_CACHE_LOCK``."""
    expired = [
        key for key, (stored_at, _) in _CACHE.items() if now - stored_at >= CACHE_TTL_SECONDS
    ]
    for key in expired:
        _CACHE.pop(key, None)


def _cache_get(key: tuple[str, str, str]) -> dict[str, Any] | None:
    now = time.monotonic()
    with _CACHE_LOCK:
        entry = _CACHE.get(key)
        if entry is None:
            return None
        stored_at, value = entry
        if now - stored_at >= CACHE_TTL_SECONDS:
            _CACHE.pop(key, None)
            return None
        _CACHE.move_to_end(key)
        return deepcopy(value)


def _cache_put(key: tuple[str, str, str], value: dict[str, Any]) -> None:
    with _CACHE_LOCK:
        now = time.monotonic()
        _purge_expired(now)
        _CACHE[key] = (now, deepcopy(value))
        _CACHE.move_to_end(key)
        while len(_CACHE) > CACHE_CAPACITY:
            _CACHE.popitem(last=False)


def _lookup(operation: str, indicator: str, settings: Settings) -> dict[str, Any]:
    key = _cache_key(operation, indicator)
    cached = _cache_get(key)
    if cached is not None:
        return cached

    api_key = settings.otx_api_key
    if api_key is None:
        raise IntelligenceUnavailableError("api_key_not_configured")

    path = OTX_ENDPOINTS[operation].format(indicator=indicator)
    value = _request_json(path, api_key, settings)
    _cache_put(key, value)
    return value


def lookup_domain(domain: str, settings: Settings) -> dict[str, Any]:
    """Look up one normalized domain indicator through the shared guard."""
    return _lookup("domain", _normalize_domain(domain), settings)


def lookup_hash(sha256: str, settings: Settings) -> dict[str, Any]:
    """Look up one normalized SHA-256 indicator through the shared guard."""
    return _lookup("hash", _normalize_hash(sha256), settings)


def _missing(target: str, reason: str) -> dict[str, str]:
    return {"target": target, "reason": reason[:64]}


def collect_intelligence(parsed: Any, attachments: Any, settings: Settings) -> IntelligenceResult:
    """Collect supplementary OTX data without changing deterministic scoring.

    Provider failures are recorded as missing intelligence and never raised to
    the caller. No URL from the message is fetched: only normalized domains and
    attachment digests are used as indicators against the fixed OTX endpoint.
    """
    result = IntelligenceResult()

    domains: list[str] = []
    from_address = getattr(parsed, "from_address", None)
    if isinstance(from_address, str) and "@" in from_address:
        with contextlib.suppress(IntelligenceUnavailableError):
            domains.append(_normalize_domain(from_address.rsplit("@", 1)[1]))
    for link in getattr(parsed, "links", []) or []:
        host = link.get("host") if isinstance(link, dict) else getattr(link, "host", None)
        if not isinstance(host, str):
            continue
        with contextlib.suppress(IntelligenceUnavailableError):
            domains.append(_normalize_domain(host))

    hashes: list[str] = []
    for item in attachments or []:
        digest = getattr(item, "sha256", None)
        if not isinstance(digest, str):
            continue
        with contextlib.suppress(IntelligenceUnavailableError):
            hashes.append(_normalize_hash(digest))

    for operation, indicators, target_bucket, result_bucket in (
        ("domain", dict.fromkeys(domains), "domains", result.domains),
        ("hash", dict.fromkeys(hashes), "hashes", result.hashes),
    ):
        ordered = list(indicators)
        for indicator in ordered[:MAX_LOOKUPS_PER_OPERATION]:
            target = f"{PROVIDER_ID}:{target_bucket}:{indicator}"
            try:
                value = _lookup(operation, indicator, settings)
            except IntelligenceUnavailableError as exc:
                result.missing.append(_missing(target, exc.reason))
                continue
            result_bucket[indicator] = value
        for indicator in ordered[MAX_LOOKUPS_PER_OPERATION:]:
            target = f"{PROVIDER_ID}:{target_bucket}:{indicator}"
            result.missing.append(_missing(target, "lookup_limit_reached"))
    return result
