# PHISHGUARD Backend

FastAPI service for the PHISHGUARD phishing investigation platform.

> **Status: scaffolding.** This milestone delivers the application skeleton,
> configuration and health endpoints. There is no email parsing, no phishing
> analysis, no database schema, no AI agent and no authentication. Do not treat
> this service as able to investigate anything yet.

## Requirements

| Tool | Version |
|---|---|
| Python | 3.12 or newer |
| PostgreSQL | 16 (planned; **not used by this milestone**) |

## Local setup

All commands run from `backend/`. Dependencies go into a project-local virtual
environment; the system interpreter is never modified.

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e ".[dev]"
```

`backend/.venv/` is already ignored by the root `.gitignore`.

## Configuration

Settings come from the environment, optionally supplemented by a `.env` file in
`backend/`. Copy the root template and trim it if you prefer:

```bash
cp ../.env.example .env
```

One value has no default and must be supplied:

```bash
openssl rand -hex 32      # use the output as PHISHGUARD_SECRET_KEY
```

The service refuses to start when:

- `PHISHGUARD_SECRET_KEY` is missing or shorter than 16 characters;
- the secret is still one of the documented placeholder strings;
- `PHISHGUARD_CORS_ORIGINS` contains `*` or a non-http(s) URL;
- `debug` is enabled while `environment=production`.

Secrets are held as `SecretStr`, so they do not appear in `repr()`, logs or
exception output.

## Running

```bash
cd backend
.venv/bin/uvicorn --factory app.main:create_app --reload --host 127.0.0.1 --port 8000
```

`--factory` is required: `create_app` builds a configured instance and opens no
connection at import time, which is what keeps tests isolated.

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness and dependency health |
| `GET /api/v1/health` | The same check inside the versioned API |
| `GET /docs` | OpenAPI UI (interactive) |
| `GET /openapi.json` | Machine-readable schema |

Example response:

```json
{
  "status": "ok",
  "service": "phishguard-api",
  "version": "0.1.0",
  "checks": []
}
```

`checks` is empty because no dependency is wired up yet. It is reported
explicitly rather than omitted, so "no dependencies configured" is never
mistaken for "all dependencies healthy".

## Tests

Tests run without PostgreSQL, Redis or network access.

```bash
cd backend
.venv/bin/python -m pytest                    # suite
.venv/bin/python -m pytest --cov=app          # with coverage
.venv/bin/python -m pytest -m "not integration"
```

The suite sets its own throwaway `PHISHGUARD_SECRET_KEY` through
`[tool.pytest.ini_options] env`, so it does not depend on your shell.

## Linting and formatting

```bash
cd backend
.venv/bin/ruff check .          # lint (includes security rules)
.venv/bin/ruff format --check .  # formatting
.venv/bin/ruff format .          # apply formatting
```

## Layout

```
backend/
├── app/
│   ├── main.py            # application factory, lifespan, error handlers
│   ├── __main__.py        # ASGI entry point
│   ├── api/
│   │   ├── dependencies.py  # shared FastAPI dependencies
│   │   ├── health.py        # GET /health
│   │   └── v1/router.py     # versioned API mount point
│   ├── core/
│   │   ├── config.py      # pydantic-settings configuration
│   │   ├── exceptions.py  # domain error types
│   │   └── logging.py     # log setup with credential redaction
│   ├── db/session.py      # async engine and session factory
│   ├── models/base.py     # ORM models (empty for now)
│   ├── schemas/health.py  # response models
│   └── services/health.py # health logic, framework-independent
├── tests/
└── pyproject.toml
```

### The framework boundary

`app/services/` holds business logic and imports no web framework. `app/api/`
translates HTTP into calls on those services. This is deliberate: the analysis
engine will later run inside a worker process, reusing the same service code
without a rewrite.

## Dependency versions

Installed and verified against Python 3.12.3 on 2026-11-06:

| Package | Version |
|---|---|
| fastapi | 0.162.0 |
| starlette | 1.10.0 |
| pydantic | 2.14.3 |
| pydantic-settings | 2.16.2 |
| SQLAlchemy | 2.0.57 |
| uvicorn | 0.54.0 |
| pytest | 8.4.2 |
| pytest-cov | 7.1.0 |
| pytest-asyncio | 1.4.1.post1 |
| pytest-env | 1.8.5 |
| httpx | 0.28.1 |
| ruff | 0.17.4 |

`pyproject.toml` declares ranges rather than exact pins so security patches
flow in; this table records what was actually resolved.

## Known limitations

- No database is connected. `app/db/session.py` defines an engine factory but
  nothing calls it, and there are no models or migrations.
- No authentication or authorization. Do not expose this service beyond
  localhost.
- `uvicorn --reload` is for development only.
- A Starlette deprecation warning about `httpx` appears in test output; it comes
  from the test client and does not affect runtime behaviour.
