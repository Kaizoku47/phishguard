"""Application-level exceptions.

Domain code raises these; the API layer translates them into responses. Keeping
the translation here means the analysis packages never import FastAPI, so the
same business logic can run inside a worker process.
"""

from __future__ import annotations


class PhishGuardError(Exception):
    """Base class for all application errors."""


class ConfigurationError(PhishGuardError):
    """The process environment is missing or unsafe."""


class NotFoundError(PhishGuardError):
    """A requested resource does not exist."""


class AuthenticationRequiredError(PhishGuardError):
    """No valid bearer token was supplied."""


class PayloadTooLargeError(PhishGuardError):
    """The uploaded message exceeds the configured byte cap."""


class UnsupportedMediaTypeError(PhishGuardError):
    """The request content type is not message/rfc822."""


class EmptyPayloadError(PhishGuardError):
    """The upload contained no bytes."""


class EvidenceStorageError(PhishGuardError):
    """Evidence could not be published, read or removed safely."""


class ParsingNotCompleteError(PhishGuardError):
    """Parsed data was requested before parsing completed."""


class AnalysisNotPerformedError(PhishGuardError):
    """The report was requested before deterministic analysis ran."""
