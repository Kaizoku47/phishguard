# PHISHGUARD Database

PostgreSQL 16 running in Docker, with SQLAlchemy 2.0 async access and Alembic
migrations. This document covers setup, operation and troubleshooting.

> **Status: infrastructure only.** The schema is intentionally empty. Email
> analysis, phishing evidence, threat intelligence, risk scoring, investigation
> and AI agent tables belong to later milestones.

## Why a dedicated Docker service

The host already runs other software on PostgreSQL's default port. PHISHGUARD
therefore runs its own isolated PostgreSQL container on a port of its own:

| Thing | Value | Why |
|---|---|---|
| Host port | **5434** | 5432 is a native PostgreSQL install; 5433 is another project's container |
| Binding | `127.0.0.1` | Not reachable from the network |
| Compose project | `phishguard-dev` | Namespaced so it never collides with other projects |
| Volume | `phishguard-dev-postgres-data` | Dedicated, never shared |
| Network | `phishguard-dev-network` | Dedicated bridge |

Nothing in this project stops, restarts, prunes or reuses any other container,
volume or network.

## Resource configuration

The VM has 13.2 GB of RAM shared with the IDE, the editor and other projects.
PostgreSQL is therefore tuned conservatively and capped:

| Setting | Value | Reason |
|---|---|---|
| `shared_buffers` | 256 MB | Small working set for a development database |
| `work_mem` | 4 MB | Sorting and hashing per operation |
| `max_connections` | 20 | The app pool opens at most 7 (`pool_size` 5 + `max_overflow` 2) |
| `maintenance_work_mem` | 64 MB | Vacuum and index builds |
| `effective_cache_size` | 512 MB | Planner hint only, allocates nothing |
| Container memory limit | 1 GB | Measured usage is ~105 MB |

These are development values. A production deployment needs its own sizing.

## Prerequisites

- Docker Engine with the Compose v2 plugin (`docker compose`, not `docker-compose`)
- Python 3.12

## Setup

```bash
cd ~/Desktop/Projects/phishguard

# 1. Environment file. Never committed; .gitignore covers it.
cp .env.example .env
chmod 600 .env

# 2. Replace the placeholders with generated values.
#    The password is never echoed to the terminal.
openssl rand -hex 24      # -> POSTGRES_PASSWORD
openssl rand -hex 32      # -> PHISHGUARD_SECRET_KEY
```

`.env` must contain matching passwords in every URL:

```
POSTGRES_PASSWORD=<generated>
DATABASE_URL=postgresql+asyncpg://phishguard:<generated>@127.0.0.1:5434/phishguard
DATABASE_URL_SYNC=postgresql+psycopg://phishguard:<generated>@127.0.0.1:5434/phishguard
ALEMBIC_DATABASE_URL=postgresql+psycopg://phishguard:<generated>@127.0.0.1:5434/phishguard
DATABASE_URL_TEST=postgresql+asyncpg://phishguard:<generated>@127.0.0.1:5434/phishguard_test
```

A mismatch between `POSTGRES_PASSWORD` and the password inside a URL is the most
common cause of `password authentication failed`. See Troubleshooting.

Python dependencies:

```bash
cd backend
python3 -m venv .venv
.venv/bin/pip install -e ".[dev,postgres]"
```

## Starting PostgreSQL

Always pass the project name and file explicitly:

```bash
docker compose -p phishguard-dev -f docker-compose.yml up -d postgres
```

Check status and health:

```bash
docker compose -p phishguard-dev -f docker-compose.yml ps
```

A healthy container reports `Up ... (healthy)`.

Follow the logs:

```bash
docker compose -p phishguard-dev -f docker-compose.yml logs postgres
```

## Stopping

Stop only PHISHGUARD services:

```bash
docker compose -p phishguard-dev -f docker-compose.yml stop postgres
```

Remove the container but **keep the data volume**:

```bash
docker compose -p phishguard-dev -f docker-compose.yml down
```

`docker compose down -v` deletes the volume and is therefore **not** routine
cleanup. Use it only when you intend to destroy all local database data.

## Creating the test database

The integration suite uses a separate database on the same server. One command
creates it:

```bash
cd backend
.venv/bin/python scripts/bootstrap_test_db.py
```

It prints either `test database 'phishguard_test' already exists; nothing to
do` or `test database 'phishguard_test' created`. It is idempotent: running it
again leaves the database and its contents alone.

Before connecting, the script checks that the target is the PHISHGUARD service
on `127.0.0.1:5434` and that the database is `phishguard_test`. It refuses to
run against the native PostgreSQL on 5432, against another project's container
on 5433, or against the development database. It never drops or recreates a
database.

The equivalent manual command, if you prefer:

```bash
docker compose -p phishguard-dev -f docker-compose.yml exec postgres \
  psql -U phishguard -d phishguard -c "CREATE DATABASE phishguard_test"
```

Creating it twice raises an error; that is harmless.

## Connecting

From the host, using the client shipped with Ubuntu:

```bash
psql "postgresql://phishguard@127.0.0.1:5434/phishguard"
```

Or inside the container:

```bash
docker compose -p phishguard-dev -f docker-compose.yml exec postgres \
  psql -U phishguard -d phishguard
```

## Migrations

Alembic reads its URL from `ALEMBIC_DATABASE_URL`, falling back to
`DATABASE_URL_SYNC`. No credential is stored in `alembic.ini`.

Apply all migrations:

```bash
cd backend
.venv/bin/alembic upgrade head
```

Inspect the current revision:

```bash
.venv/bin/alembic current
.venv/bin/alembic history --verbose
```

Create a new revision after changing a model:

```bash
cd backend
.venv/bin/alembic revision --autogenerate -m "describe the change"
```

Review the generated file before applying it. `--autogenerate` is a draft, not
an authority: check the operations, then run `upgrade head`.

Roll back one revision:

```bash
.venv/bin/alembic downgrade -1
```

Migrations never run automatically at application startup. Applying schema
changes is always an explicit operator action.

### The baseline revision

`0001_baseline` is deliberately empty. It establishes the revision ledger with
no domain tables, so the first real table arrives as a reviewable diff rather
than folded into a baseline.

## Testing

Unit tests need no database:

```bash
cd backend
.venv/bin/python -m pytest -m "not integration"
```

Integration tests need the running container and the test database:

```bash
# Once, on a fresh clone:
.venv/bin/python scripts/bootstrap_test_db.py

.venv/bin/python -m pytest -m integration
```

Both together, which is what CI does:

```bash
.venv/bin/python -m pytest
```

Integration tests run sequentially. They target `phishguard_test` only, and
refuse to run if the target is not `127.0.0.1:5434` or if it resolves to the
development database. This guard exists so a misconfiguration cannot destroy
real data.

## Auditing dependencies

`pip-audit` checks the installed and declared dependencies against the
published vulnerability database:

```bash
cd backend
.venv/bin/pip-audit . --progress-spinner off
```

It exits non-zero when a vulnerability is found, so it works as a CI gate. Run
it before a release, and after any dependency upgrade.

The full list of dependencies with the versions resolved on 2026-11-12 is in
`backend/README.md`.

## Health and readiness

| Endpoint | Meaning |
|---|---|
| `GET /health` | Liveness. The process is running. Does not touch the database. |
| `GET /ready` | Readiness. Returns `200 {"status":"ready"}` when `SELECT 1` succeeds, `503 {"status":"not_ready"}` otherwise. |

`/ready` never returns a database URL, password or stack trace. The two are
separate on purpose: a healthy process with an unreachable database is
"live but not ready", which is exactly what an orchestrator needs to know.

## Persistence

Data lives in the named volume `phishguard-dev-postgres-data`. Stopping or
restarting the container preserves it:

```bash
docker compose -p phishguard-dev -f docker-compose.yml stop postgres
docker compose -p phishguard-dev -f docker-compose.yml start postgres
```

This was verified during Milestone 2.2: a row written before a restart was
present afterwards.

## Backup and restore

Backup the development database:

```bash
docker compose -p phishguard-dev -f docker-compose.yml exec -T postgres \
  pg_dump -U phishguard -d phishguard > phishguard-backup.sql
```

Restore:

```bash
cat phishguard-backup.sql | docker compose -p phishguard-dev -f docker-compose.yml \
  exec -T postgres psql -U phishguard -d phishguard
```

Backups contain real data. They are covered by the root `.gitignore`
(`*.sql.gz`, `*.dump`, `*.bak`) but a plain `.sql` is not ignored by pattern, so
store backups outside the repository or delete them after use.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `password authentication failed for user "phishguard"` | `POSTGRES_PASSWORD` and the password inside a `DATABASE_URL*` differ, or `.env` was created before a new field was added | Regenerate every URL from the same password. `psql -h 127.0.0.1 -p 5434 -U phishguard -d phishguard` tests the real TCP credential |
| `does not match POSTGRES_HOST and POSTGRES_PORT` | The parts and the URLs describe different servers | Pick one target and make both agree. The application refuses to guess |
| `connection refused` on 5434 | Container not running | `docker compose -p phishguard-dev -f docker-compose.yml up -d postgres` |
| `database "phishguard_test" does not exist` | Test database never created | `.venv/bin/python scripts/bootstrap_test_db.py` |
| `refusing to use database 'phishguard'` | The test target points at the development database | Set `DATABASE_URL_TEST` to the `phishguard_test` database |
| `refusing to use port 5432` | The URL points at the native PostgreSQL | Use port 5434 |
| `error parsing value for field "cors_origins"` | List field written in shell style | pydantic-settings expects JSON: `PHISHGUARD_CORS_ORIGINS=["http://localhost:5173"]` |
| `relation "alembic_version" does not exist` | Migrations never applied to that database | `alembic upgrade head` |
| Integration tests refuse to run | Target validation rejected the URL | Confirm host `127.0.0.1`, port `5434`, database `phishguard_test` |
| `pip-audit` reports a vulnerability | A dependency has a known issue | Check the reported fixed version, upgrade within the declared range, then re-run the tests |
| Port 5434 already allocated | Another service took the port | Stop that service, or change the port in `docker-compose.yml` **and** every URL |

## Safety rules

- Never run `docker system prune` or `docker volume prune`.
- Never run `docker compose down -v` as routine cleanup.
- Never stop or recreate containers belonging to other projects.
- Never point PHISHGUARD at the native PostgreSQL on 5432 or another project's
  container on 5433.
- Never commit `.env`.
- Never log a connection URL; use the redacted form.