"""PHISHGUARD domain services.

The services hold the application's business logic. They raise
``PhishGuardError`` subclasses; the API layer translates them into responses.
Keeping the translation out of this package means the same logic can run
inside a worker process.
"""

from __future__ import annotations
