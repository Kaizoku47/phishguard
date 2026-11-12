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
