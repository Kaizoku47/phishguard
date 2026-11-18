#!/usr/bin/env python
"""Create or rotate the local PHISHGUARD API token in ``backend/.env``.

Run from ``backend/``:

    .venv/bin/python scripts/bootstrap_token.py
    .venv/bin/python scripts/bootstrap_token.py --rotate --confirm

Safety rules:

- the generated token is never printed;
- a valid existing token is never rotated without ``--rotate --confirm``;
- a malformed non-placeholder value is reported for manual repair and never
  overwritten automatically;
- the ``.env`` file is written atomically with mode ``0600``.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import secrets
import sys
import tempfile
from pathlib import Path

ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
TOKEN_KEY = "PHISHGUARD_API_TOKEN"  # noqa: S105
MIN_LENGTH = 32
PLACEHOLDERS = frozenset({"replace-me-with-a-generated-value", "changeme", "change-me", "secret"})


def _read_lines() -> list[str]:
    if not ENV_PATH.exists():
        return []
    return ENV_PATH.read_text().splitlines()


def _find_token(lines: list[str]) -> tuple[int | None, str | None]:
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key.strip() == TOKEN_KEY:
            return index, value.strip()
    return None, None


def _is_valid(token: str | None) -> bool:
    return bool(token) and len(token or "") >= MIN_LENGTH and token not in PLACEHOLDERS


def _write_env(lines: list[str], index: int | None, token: str) -> None:
    line = f"{TOKEN_KEY}={token}"
    if index is None:
        lines.append(line)
    else:
        lines[index] = line
    content = "\n".join(lines).rstrip("\n") + "\n"

    descriptor, temp_name = tempfile.mkstemp(prefix=".env.", dir=str(ENV_PATH.parent))
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w") as handle:
            handle.write(content)
        os.replace(temp_name, ENV_PATH)
        os.chmod(ENV_PATH, 0o600)
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rotate", action="store_true", help="replace an existing token")
    parser.add_argument("--confirm", action="store_true", help="confirm an explicit rotation")
    args = parser.parse_args(argv)

    lines = _read_lines()
    index, existing = _find_token(lines)

    if args.rotate and not args.confirm:
        print("--rotate requires --confirm")
        return 2

    if _is_valid(existing) and not args.rotate:
        print("PHISHGUARD_API_TOKEN is present; no change made")
        return 0

    if existing and existing in PLACEHOLDERS:
        print("placeholder token found; generating a local value")
    elif existing and not _is_valid(existing) and not args.rotate:
        print("malformed PHISHGUARD_API_TOKEN found; repair manually or use --rotate --confirm")
        return 1

    token = secrets.token_urlsafe(48)
    _write_env(lines, index, token)
    print("PHISHGUARD_API_TOKEN written to backend/.env (mode 0600)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
