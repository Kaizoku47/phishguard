# PHISHGUARD Phase 2 — Inspection Report and Proposed Architecture

**No files created, modified, deleted, installed or moved. No secrets read. Read-only inspection.**

---

## A. Current Project Inspection Report

**Repository:** `phishguard` (local working copy)

- Git repo initialized, branch `master`, **no commits yet**.
- Only untracked content: `.opencode/`.
- No git remote configured.
- No application code exists. This is a greenfield start.

**`.opencode/` contents (project-local, not PHISHGUARD config):**

- `skills/` — 8 UI/design skills (`banner-design`, `brand`, `design`, `design-system`, `impeccable`, `slides`, `ui-styling`, `ui-ux-pro-max`).
- `commands/impeccable.md` — one command.
- `node_modules/`, `package.json`, `package-lock.json` — opencode plugin install (`@opencode-ai/plugin`).
- `.gitignore` — ignores its own `node_modules`, `package.json`, `package-lock.json`.

This `.opencode/` tree is design/frontend tooling only. It contains no backend, no Python, no PHISHGUARD logic. Nothing here relates to Phase 1 artifacts — Phase 1 output is not present in this directory.

**Local toolchain available:**

| Tool | Version | Status |
|------|---------|--------|
| Python | 3.12.3 | present |
| pip | 24.0 | present |
| Node | v24.22.0 | present |
| npm | 12.2.1 | present |
| Docker | 29.1.3 | present |
| docker-compose | 1.29.2 | present (old v1) |
| PostgreSQL client | psql 16.15 | present |
| git | 2.43.0 | present |
| gh (GitHub CLI) | — | **missing** |
| prettier | — | **missing** |
| ruff | — | **missing** |

No Python virtual environment active. `ruff`, `prettier`, `gh` will need install when implementation begins.

---

## B. Existing Hermes and ECC Capabilities

**ECC is installed and integrated with Hermes.**

Two ECC install targets exist:

| Target | Root | Installed | Last validated |
|--------|------|-----------|----------------|
| Hermes | `~/.hermes` | 2026-10-30 | 2026-11-03 |
| opencode | `~/.config/opencode` | 2026-11-03 | — |

- **Hermes ECC install:** profile `full`, hooks enabled, 540 recorded operations. Hermes provides **71 agents, 314 skills, 98 commands** (per `~/.hermes/AGENTS.md`, ECC v2.2.3).
- **opencode ECC install:** profile `full`, all modules selected, hook consent enabled. 52 global skills under `~/.config/opencode/skills/`, 124 commands under `~/.config/opencode/commands/`.
- Hermes also has its own 68 skills and 71 agents in `~/.hermes/skills/` and `~/.hermes/agents/`.

**All 10 requested ECC skills are present in opencode:**

| Skill | Status |
|-------|--------|
| fastapi-patterns | YES |
| python-patterns | YES |
| python-testing | YES |
| tdd-workflow | YES |
| security-review | YES |
| agent-security-hardening | YES |
| agent-architecture-audit | YES |
| docker-patterns | YES |
| git-workflow | YES |
| verification-loop | YES |

Relevant commands also available: `fastapi-review`, `code-review`, `verification-loop`, `harness-audit`, `feature-dev`, `eval`.

**Conclusion:** ECC is fully available. The ten skills needed for Phase 2 are all loadable from opencode. Hermes is the agent runtime layer and shares the ECC install.

---

## C. Recommended Technology Stack

| Layer | Choice | Why |
|-------|--------|-----|
| Backend | **Python 3.12 + FastAPI** | Async, typed, fast, ECC `fastapi-patterns`/`python-patterns` cover it |
| Validation | **Pydantic v2** | Ships with FastAPI, schema for untrusted input |
| ORM | **SQLAlchemy 2.0 (async)** | Standard, works with Alembic |
| Migrations | **Alembic** | Pairs with SQLAlchemy, ECC `database-migrations` |
| Database | **PostgreSQL 16** | Already installed locally; JSONB for analysis artifacts |
| Task queue | **Celery + Redis** (or FastAPI BackgroundTasks early) | Ingestion and intel calls must not block HTTP |
| Frontend | **React 18 + TypeScript + Vite** | ECC `react-patterns`, `typescript-patterns` |
| Data fetching | **TanStack Query** | Standard React server-state |
| Styling | **Tailwind CSS** | Project already has `ui-styling`/`ui-ux-pro-max` skills |
| Email parsing | **Python stdlib `email`** (safe, no execution) | Parse `.eml` without running anything |
| AI agent | **Provider-agnostic LLM client + constrained tool layer** | ECC `agent-security-hardening`, `agent-architecture-audit` |
| Containers | **Docker + docker-compose** | ECC `docker-patterns`; local compose v1 is old — use `docker compose` v2 plugin if available |
| CI/CD | **GitHub Actions (free tier)** | Requirements match exactly |
| Secrets | **GitHub Encrypted Secrets + `.env` (gitignored)** | Never in source |
| Security scans | **pip-audit, bandit, npm audit, Trivy, gitleaks** | All free/OSS |

---

## D. Proposed Architecture and Component Responsibilities

Plain-language overview: PHISHGUARD takes a suspicious email, parses it safely in a sealed box, gathers evidence from threat feeds, scores the risk with an explanation, and hands a human analyst a clear report. Nothing untrusted is ever opened or run.

**Components:**

1. **API layer (FastAPI)** — receives `.eml` uploads and analysis requests, returns JSON. All input treated as hostile.
2. **Storage (PostgreSQL)** — stores emails, parsed artifacts, analyses, scores, audit trail.
3. **Ingestion service** — reads `.eml` using Python's `email` module in a worker. Extracts headers, body, links, attachment metadata. **Never opens or executes attachments.**
4. **Static analysis modules** — header forensics (SPF/DKIM/DMARC results), URL inspection, attachment type/hash analysis, lookalike-domain detection.
5. **Threat intelligence adapters** — pluggable connectors (VirusTotal, URLScan, AbuseIPDB, etc.) that only make allow-listed outbound calls, behind an SSRF guard. Keys from env, never logged.
6. **Risk scoring engine** — weighted, explainable scoring. Each signal contributes a documented weight and human-readable reason.
7. **AI investigation agent** — LLM that plans steps but may only call a fixed, safe tool set (e.g. `lookup_domain`, `check_hash`, `get_headers`). No shell, no file write, no arbitrary HTTP. Every action and decision is written to an audit log.
8. **Frontend (React/TS)** — analyst dashboard: upload, view findings, see the score breakdown and agent reasoning.
9. **Cross-cutting:** logging (structured, secrets redacted), error handling (typed, no stack traces to client), auth (least privilege).

**Data flow:** Upload → store raw → worker parse (sandboxed, no execution) → analysis modules → intel lookups (guarded) → score with reasons → agent reviews with read-only tools → persist report → frontend displays.

---

## E. Proposed Project Directory Structure

```
phishguard/
├── .github/
│   └── workflows/          # CI/CD pipelines
├── backend/
│   ├── app/
│   │   ├── api/            # FastAPI routers
│   │   ├── core/           # config, logging, security
│   │   ├── models/         # SQLAlchemy models
│   │   ├── schemas/        # Pydantic schemas
│   │   ├── services/       # ingestion, analysis, scoring
│   │   ├── intel/          # threat-intel adapters + SSRF guard
│   │   └── agent/          # AI agent + tool definitions
│   ├── alembic/            # migrations
│   ├── tests/
│   ├── pyproject.toml
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── api/
│   │   └── types/
│   ├── tests/
│   ├── package.json
│   └── Dockerfile
├── docker-compose.yml
├── docs/
├── .env.example            # placeholders only, no real secrets
├── .gitignore
└── README.md
```

---

## F. CI/CD Architecture and Workflow Design

All on **GitHub Actions free tier**. Plain description: every push runs a set of independent checks; a PR cannot merge if any fails.

**Pipeline (`.github/workflows/ci.yml`), jobs run in parallel where possible:**

| Job | Tool | Free? |
|-----|------|-------|
| Backend tests | pytest + coverage | yes |
| Frontend tests | vitest / jest | yes |
| Python lint/format | ruff + black | yes |
| Python type check | mypy | yes |
| TS lint/format | eslint + prettier | yes |
| TS type check | tsc --noEmit | yes |
| Python security scan | bandit | yes |
| Dependency audit (Python) | pip-audit | yes |
| Dependency audit (JS) | npm audit | yes |
| Secret scanning | gitleaks | yes |
| Container scan (when Dockerfiles exist) | Trivy | yes |

**Branch protection:** require all checks to pass before merge to `main`.

**Least-privilege CI:** workflow uses `permissions: contents: read` by default; no write scopes unless a specific job needs it. No secrets echoed. Intel API keys injected as GitHub Encrypted Secrets only.

**Free-tier notes and limitations:**

- GitHub Actions minutes: **2,000/month free for private repos**, unlimited for public repos.
- gitleaks, Trivy, pip-audit, bandit, ruff, mypy, pytest, vitest — all free/OSS.
- **Paid features to be aware of:** GitHub Advanced Security (CodeQL private-repo, secret scanning push protection on private repos) may need a paid plan; Trivy + gitleaks cover the same ground for free.
- Codecov/code-climate coverage reporting has free tiers with limits.
- `gh` CLI is **not installed locally** — needed for local PR work; install later.

---

## G. Security Architecture

Treat every uploaded email, URL, attachment and intel response as hostile.

1. **No execution:** attachments are never opened, rendered or run. Only metadata and hashes are read.
2. **No auto-visiting:** URLs are analyzed statically (string, structure, domain age, lookalike checks via intel APIs) — the app does **not** fetch suspicious URLs itself.
3. **SSRF prevention:** outbound calls only to an allow-list of intel endpoints; block private IP ranges, metadata IPs, redirects to internal hosts; validate and pin destinations.
4. **Secret handling:** all API keys via env vars (GitHub Secrets in CI, `.env` locally, gitignored). A redaction filter strips secrets from all logs. `.env.example` has placeholders only.
5. **Least privilege:** CI jobs default to read-only token. Docker containers run as non-root. DB user has only needed rights.
6. **AI agent constraints:** the agent may only call a fixed, declared tool set — no shell, no filesystem write, no arbitrary outbound HTTP. Every tool call and decision is append-only audited. Prompt-injection from email content is assumed and neutralized by treating email text as data, not instructions.
7. **Input validation:** all input through Pydantic schemas; size limits on uploads; reject malformed `.eml`.
8. **Secret scanning:** gitleaks in CI plus a pre-commit hook.

---

## H. Development Roadmap with Implementation Order

Each step is one focused PR, checks green before moving on.

1. **Scaffold repo** — `.gitignore`, `.env.example`, README, directory skeleton.
2. **Backend skeleton** — FastAPI app, config, structured logging, health endpoint. (skills: fastapi-patterns, python-patterns)
3. **Database layer** — SQLAlchemy models + Alembic initial migration. (database-migrations)
4. **Safe `.eml` ingestion** — parse headers/body/links/attachment metadata, no execution. Tests. (security-review, python-testing)
5. **Static analysis modules** — header forensics, URL inspection, attachment hashing. (tdd-workflow)
6. **Threat intel adapters + SSRF guard** — allow-listed connectors, secrets from env. (security-review)
7. **Explainable risk scoring engine** — weighted signals + reasons. Tests.
8. **AI agent + constrained tools + audit log.** (agent-security-hardening, agent-architecture-audit)
9. **Frontend scaffold** — Vite + React + TS + Tailwind, upload + report views.
10. **Docker** — Dockerfiles + docker-compose (api, worker, db, redis). (docker-patterns)
11. **CI/CD** — the full GitHub Actions pipeline. (git-workflow, verification-loop)
12. **Docs** — architecture, security model, runbook, contributing.

---

## I. Risks, Trade-offs and Free-Tier Limitations

**Risks:**

- **AI agent is the highest-risk component.** Prompt injection via email is expected. Mitigation: constrained tools, treat email as data, full audit. Validate with ECC `agent-security-hardening` before enabling.
- **Threat intel APIs have rate limits and cost.** Free tiers are small; design caching to reduce calls.
- **Phishing detection is never 100%.** Scoring must be explained and human-reviewed, not auto-actioned.
- **Old local docker-compose (v1.29.2).** Prefer the `docker compose` v2 plugin; v1 may misbehave with modern compose files.

**Trade-offs:**

- Celery + Redis adds infra now vs. FastAPI BackgroundTasks as a simpler start. Recommend BackgroundTasks for step 5, upgrade to Celery when intel calls get heavy.
- Scanning only (no URL fetching) is safer but less thorough than a sandboxed headless visit. Correct default: safety first.

**Free-tier limitations:**

- GitHub Actions: 2,000 min/month private, unlimited public.
- GitHub Advanced Security (private-repo CodeQL/secret push protection) is **paid** — replaced by free Trivy + gitleaks.
- Some intel providers charge past free quotas.
- Coverage dashboards have free caps.

---

**Blockers before implementation:** install `ruff`, `prettier`, `gh`; confirm `docker compose` v2 availability; create the git remote / initial commit decision.

**Awaiting approval before any implementation.**
