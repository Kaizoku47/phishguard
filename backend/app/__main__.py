"""Module entry point.

Run with either of:

    python -m app
    uvicorn --factory app.main:create_app

The module-level ``app`` exists only for ASGI servers that import an attribute
directly (``uvicorn app.__main__:app``); the factory remains the primary path.
"""

from __future__ import annotations

from app.main import create_app

app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
